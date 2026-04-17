package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
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

func (l Level) Color() string {
	switch l {
	case LevelDebug:
		return "\033[36m"
	case LevelInfo:
		return "\033[32m"
	case LevelWarn:
		return "\033[33m"
	case LevelError:
		return "\033[31m"
	case LevelFatal:
		return "\033[35m"
	default:
		return "\033[0m"
	}
}

type Config struct {
	Level       Level
	EnableColor bool
	Prefix      string
	ShowCaller  bool
	TimeFormat  string
	Stdout      io.Writer
	Stderr      io.Writer
	MaskLogs    bool
	JSONMode    bool
}

func DefaultConfig() *Config {
	mask := os.Getenv("WHISPERA_MASK_LOGS") == "false"
	jsonMode := os.Getenv("WHISPERA_LOG_JSON") == "true"
	return &Config{
		Level:       LevelInfo,
		EnableColor: !jsonMode,
		Prefix:      "[WHISPERA]",
		ShowCaller:  false,
		TimeFormat:  "2006-01-02 15:04:05",
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		MaskLogs:    mask,
		JSONMode:    jsonMode,
	}
}

type Logger struct {
	mu     sync.Mutex
	config *Config
	fields map[string]interface{}
}

func New(cfg *Config) *Logger {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	if cfg.TimeFormat == "" {
		cfg.TimeFormat = "2006-01-02 15:04:05"
	}

	return &Logger{
		config: cfg,
		fields: make(map[string]interface{}),
	}
}

func (l *Logger) WithField(key string, value interface{}) *Logger {
	newLogger := &Logger{
		config: l.config,
		fields: make(map[string]interface{}),
	}
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	newLogger.fields[key] = value
	return newLogger
}

func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	newLogger := &Logger{
		config: l.config,
		fields: make(map[string]interface{}),
	}
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	for k, v := range fields {
		newLogger.fields[k] = v
	}
	return newLogger
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config.Level = level
}

func (l *Logger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config.Level
}


// -----------------------------------------------------------------------------

func (l *Logger) log(level Level, msg string, args ...interface{}) {
	if level < l.config.Level {
		return
	}

	var out io.Writer
	if level >= LevelError {
		out = l.config.Stderr
	} else {
		out = l.config.Stdout
	}

	now := time.Now()

	var formatted string
	if len(args) > 0 {
		formatted = fmt.Sprintf(msg, args...)
	} else {
		formatted = msg
	}

	modName := ""
	if mod, ok := l.fields["module"]; ok {
		modName = fmt.Sprintf("%v", mod)
	}
	ring().push(RingEntry{
		Time:    now,
		Level:   level.String(),
		Module:  modName,
		Message: formatted,
	})

	if l.config.JSONMode {
		entry := map[string]interface{}{
			"ts":    now.Format(time.RFC3339Nano),
			"level": level.String(),
			"msg":   formatted,
		}
		for k, v := range l.fields {
			entry[k] = v
		}
		if l.config.ShowCaller {
			if _, file, line, ok := runtime.Caller(2); ok {
				parts := strings.Split(file, "/")
				if len(parts) > 0 {
					file = parts[len(parts)-1]
				}
				entry["caller"] = fmt.Sprintf("%s:%d", file, line)
			}
		}
		data, _ := json.Marshal(entry)
		data = append(data, '\n')
		l.mu.Lock()
		out.Write(data)
		l.mu.Unlock()
		return
	}

	var sb strings.Builder

	timestamp := now.Format(l.config.TimeFormat)

	colorReset := "\033[0m"
	if l.config.EnableColor {
		sb.WriteString(level.Color())
	}

	if l.config.Prefix != "" {
		sb.WriteString(l.config.Prefix)
		sb.WriteString(" ")
	}

	sb.WriteString(fmt.Sprintf("[%s] [%-5s] ", timestamp, level.String()))

	if len(l.fields) > 0 {
		if mod, ok := l.fields["module"]; ok {
			sb.WriteString(fmt.Sprintf("[%s] ", mod))
		}
	}

	if l.config.ShowCaller {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			parts := strings.Split(file, "/")
			if len(parts) > 0 {
				file = parts[len(parts)-1]
			}
			sb.WriteString(fmt.Sprintf("(%s:%d) ", file, line))
		}
	}

	sb.WriteString(formatted)

	if len(l.fields) > 0 {
		first := true
		for k, v := range l.fields {
			if k == "module" {
				continue
			}
			if first {
				sb.WriteString(" |")
				first = false
			}
			sb.WriteString(fmt.Sprintf(" %s=%v", k, v))
		}
	}

	if l.config.EnableColor {
		sb.WriteString(colorReset)
	}

	sb.WriteString("\n")

	l.mu.Lock()
	fmt.Fprint(out, sb.String())
	l.mu.Unlock()
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	l.log(LevelDebug, msg, args...)
}

func (l *Logger) Info(msg string, args ...interface{}) {
	l.log(LevelInfo, msg, args...)
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	l.log(LevelWarn, msg, args...)
}

func (l *Logger) Error(msg string, args ...interface{}) {
	l.log(LevelError, msg, args...)
}

func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.log(LevelFatal, msg, args...)
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(LevelFatal, format, args...)
	os.Exit(1)
}

func (l *Logger) Printf(format string, args ...interface{}) {
	l.Info(format, args...)
}

func (l *Logger) Println(args ...interface{}) {
	l.Info("%s", fmt.Sprint(args...))
}

var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

func Global() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = New(nil)
	})
	return globalLogger
}

func SetGlobal(l *Logger) {
	globalLogger = l
}

func Debug(msg string, args ...interface{}) {
	Global().Debug(msg, args...)
}

func Info(msg string, args ...interface{}) {
	Global().Info(msg, args...)
}

func Warn(msg string, args ...interface{}) {
	Global().Warn(msg, args...)
}

func Error(msg string, args ...interface{}) {
	Global().Error(msg, args...)
}

func Fatal(msg string, args ...interface{}) {
	Global().Fatal(msg, args...)
}

func WithField(key string, value interface{}) *Logger {
	return Global().WithField(key, value)
}

func WithFields(fields map[string]interface{}) *Logger {
	return Global().WithFields(fields)
}

func SetLevel(level Level) {
	Global().SetLevel(level)
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

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config.Stdout = w
	l.config.Stderr = w
}

func SetOutput(w io.Writer) {
	Global().SetOutput(w)
}

func Module(name string) *Logger {
	return Global().WithField("module", name)
}
