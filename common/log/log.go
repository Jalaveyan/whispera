package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

func toZapLevel(l Level) zapcore.Level {
	switch l {
	case LevelDebug:
		return zapcore.DebugLevel
	case LevelInfo:
		return zapcore.InfoLevel
	case LevelWarn:
		return zapcore.WarnLevel
	case LevelFatal:
		return zapcore.FatalLevel
	default:
		return zapcore.ErrorLevel
	}
}

func levelFromString(s string) Level {
	switch s {
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARN":
		return LevelWarn
	case "ERROR":
		return LevelError
	case "FATAL":
		return LevelFatal
	}
	return LevelInfo
}

func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "fatal":
		return LevelFatal
	default:
		return LevelInfo
	}
}

const colorReset = "\x1b[0m"

var levelColors = map[zapcore.Level]string{
	zapcore.DebugLevel: "\x1b[90m",
	zapcore.InfoLevel:  "\x1b[36m",
	zapcore.WarnLevel:  "\x1b[33m",
	zapcore.ErrorLevel: "\x1b[31m",
	zapcore.FatalLevel: "\x1b[35m",
}

func encodeTimeShort(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("15:04:05.000"))
}

func encodeLevelPlain(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(fmt.Sprintf("[%-5s]", l.CapitalString()))
}

func encodeLevelColored(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	color := levelColors[l]
	enc.AppendString(fmt.Sprintf("%s[%-5s]%s", color, l.CapitalString(), colorReset))
}

func encodeNamePadded(s string, enc zapcore.PrimitiveArrayEncoder) {
	const width = 9
	if len(s) > width {
		s = s[:width]
	}
	enc.AppendString(fmt.Sprintf("%-*s", width, s))
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func buildEncoderConfig(color bool) zapcore.EncoderConfig {
	cfg := zapcore.EncoderConfig{
		TimeKey:          "ts",
		LevelKey:         "level",
		NameKey:          "module",
		MessageKey:       "msg",
		LineEnding:       zapcore.DefaultLineEnding,
		EncodeTime:       encodeTimeShort,
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeName:       encodeNamePadded,
		ConsoleSeparator: " ",
	}
	if color {
		cfg.EncodeLevel = encodeLevelColored
	} else {
		cfg.EncodeLevel = encodeLevelPlain
	}
	return cfg
}

type atomicWriter struct {
	w atomic.Pointer[io.Writer]
}

func newAtomicWriter(w io.Writer) *atomicWriter {
	a := &atomicWriter{}
	a.w.Store(&w)
	return a
}

func (a *atomicWriter) Write(p []byte) (int, error) { return (*a.w.Load()).Write(p) }
func (a *atomicWriter) Sync() error                 { return nil }
func (a *atomicWriter) set(w io.Writer)             { a.w.Store(&w) }

type Entry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Module  string    `json:"module,omitempty"`
	Message string    `json:"msg"`
}

const ringSize = 5000

type ringBuffer struct {
	mu    sync.RWMutex
	buf   []Entry
	size  int
	head  int
	count int
}

func newRingBuffer() *ringBuffer {
	return &ringBuffer{buf: make([]Entry, ringSize), size: ringSize}
}

func (r *ringBuffer) push(e Entry) {
	r.mu.Lock()
	r.buf[r.head] = e
	r.head = (r.head + 1) % r.size
	if r.count < r.size {
		r.count++
	}
	r.mu.Unlock()
}

func (r *ringBuffer) snapshot(limit int, minLevel Level) []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 || limit > r.count {
		limit = r.count
	}
	out := make([]Entry, 0, limit)
	start := (r.head - r.count + r.size) % r.size
	for i := 0; i < r.count; i++ {
		idx := (start + i) % r.size
		e := r.buf[idx]
		if minLevel > LevelDebug && levelFromString(e.Level) < minLevel {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out
}

type ringCore struct{ rb *ringBuffer }

func (rc ringCore) Enabled(zapcore.Level) bool               { return true }
func (rc ringCore) With(fields []zapcore.Field) zapcore.Core { return rc }
func (rc ringCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return ce.AddCore(e, rc)
}
func (rc ringCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	rc.rb.push(Entry{Time: e.Time, Level: e.Level.CapitalString(), Module: e.LoggerName, Message: e.Message})
	return nil
}
func (rc ringCore) Sync() error { return nil }

var (
	globalZap     *zap.Logger
	globalOnce    sync.Once
	globalLevel   zap.AtomicLevel
	globalErrSink *atomicWriter
	globalRing    *ringBuffer
)

func buildGlobal() {
	globalLevel = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	globalErrSink = newAtomicWriter(os.Stderr)
	globalRing = newRingBuffer()

	encCfg := buildEncoderConfig(isTerminal(os.Stderr))

	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encCfg),
		globalErrSink,
		globalLevel,
	)
	globalZap = zap.New(zapcore.NewTee(consoleCore, ringCore{rb: globalRing}))
}

func global() *zap.Logger {
	globalOnce.Do(buildGlobal)
	return globalZap
}

func Module(name string) *Logger {
	return &Logger{s: global().Named(name).Sugar()}
}

func SetLevel(level Level) {
	globalOnce.Do(buildGlobal)
	globalLevel.SetLevel(toZapLevel(level))
}

func SetOutput(w io.Writer) {
	globalOnce.Do(buildGlobal)
	globalErrSink.set(w)
}

func Warn(msg string, args ...interface{}) {
	Module("").Warn(msg, args...)
}

func Snapshot(limit int, minLevel Level) []Entry {
	globalOnce.Do(buildGlobal)
	return globalRing.snapshot(limit, minLevel)
}

var (
	traceLog  *zap.SugaredLogger
	traceOnce sync.Once
)

func Trace() *zap.SugaredLogger {
	traceOnce.Do(func() {
		traceLog = global().
			WithOptions(zap.AddCaller(), zap.IncreaseLevel(zapcore.InfoLevel)).
			Named("tuntrace").
			Sugar()
	})
	return traceLog
}
