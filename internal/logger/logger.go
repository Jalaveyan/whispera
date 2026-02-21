package logger

import (
	"fmt"
	"io"
	"math/rand"
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
	MaskLogs    bool // Enable fake (masked) logs
}

func DefaultConfig() *Config {
	mask := os.Getenv("WHISPERA_MASK_LOGS") == "true"
	return &Config{
		Level:       LevelInfo,
		EnableColor: true,
		Prefix:      "[WHISPERA]",
		ShowCaller:  false,
		TimeFormat:  "2006-01-02 15:04:05",
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		MaskLogs:    mask,
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
// FAKE DATA GENERATORS (MASKING)
// -----------------------------------------------------------------------------
var (
	fakePaths = []string{
		"/", "/index.html", "/about.html", "/contact", "/style.css", "/main.js", "/logo.png",
		"/api/v1/status", "/login", "/dashboard", "/favicon.ico", "/robots.txt",
		"/assets/font.woff2", "/images/banner.jpg", "/sitemap.xml",
	}
	fakeUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
	}
	fakeMethods = []string{"GET", "POST", "HEAD"}
	fakeCodes   = []int{200, 200, 200, 301, 302, 404, 500}
)

func fakeNginxLog() string {
	ip := fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
	ts := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	method := fakeMethods[rand.Intn(len(fakeMethods))]
	// Append random query param sometimes
	path := fakePaths[rand.Intn(len(fakePaths))]
	if rand.Intn(3) == 0 {
		path += fmt.Sprintf("?id=%d", rand.Intn(1000))
	}
	code := fakeCodes[rand.Intn(len(fakeCodes))]
	size := rand.Intn(5000) + 200
	ua := fakeUserAgents[rand.Intn(len(fakeUserAgents))]

	// Apache/Nginx Common Log Format
	return fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" %d %d \"-\" \"%s\"\n", ip, ts, method, path, code, size, ua)
}

func fakeErrorLog() string {
	ts := time.Now().Format("2006/01/02 15:04:05")
	levels := []string{"error", "warn"}
	msgs := []string{
		"client closed connection while waiting for request",
		"upstream timed out (110: Connection timed out) while reading response header from upstream",
		"file not found",
		"access forbidden by rule",
		"open() \"/usr/share/nginx/html/favicon.ico\" failed (2: No such file or directory)",
	}
	// Nginx error log format
	return fmt.Sprintf("%s [%s] %d#0: *%d %s, client: %d.%d.%d.%d, server: localhost\n",
		ts, levels[rand.Intn(len(levels))], rand.Intn(1000)+500, rand.Intn(99999), msgs[rand.Intn(len(msgs))],
		rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
}

// -----------------------------------------------------------------------------

func (l *Logger) log(level Level, msg string, args ...interface{}) {
	if level < l.config.Level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.config.MaskLogs {
		if level >= LevelError {
			fmt.Fprint(l.config.Stdout, fakeErrorLog())
		} else {
			fmt.Fprint(l.config.Stdout, fakeNginxLog())
		}
		return
	}

	var out io.Writer
	if level >= LevelError {
		out = l.config.Stderr
	} else {
		out = l.config.Stdout
	}

	var sb strings.Builder

	timestamp := time.Now().Format(l.config.TimeFormat)

	colorReset := "\033[0m"
	if l.config.EnableColor {
		sb.WriteString(level.Color())
	}

	if l.config.Prefix != "" {
		sb.WriteString(l.config.Prefix)
		sb.WriteString(" ")
	}

	sb.WriteString(fmt.Sprintf("[%s] [%s] ", timestamp, level.String()))

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

	if len(args) > 0 {
		sb.WriteString(fmt.Sprintf(msg, args...))
	} else {
		sb.WriteString(msg)
	}

	if len(l.fields) > 0 {
		sb.WriteString(" |")
		for k, v := range l.fields {
			sb.WriteString(fmt.Sprintf(" %s=%v", k, v))
		}
	}

	if l.config.EnableColor {
		sb.WriteString(colorReset)
	}

	sb.WriteString("\n")

	fmt.Fprint(out, sb.String())
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
