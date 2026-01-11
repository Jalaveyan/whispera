// Package logger provides structured logging for Whispera
package logger

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Level represents log level
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// String returns the level name
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

// Color returns ANSI color code for level
func (l Level) Color() string {
	switch l {
	case LevelDebug:
		return "\033[36m" // Cyan
	case LevelInfo:
		return "\033[32m" // Green
	case LevelWarn:
		return "\033[33m" // Yellow
	case LevelError:
		return "\033[31m" // Red
	case LevelFatal:
		return "\033[35m" // Magenta
	default:
		return "\033[0m"
	}
}

// Config holds logger configuration
type Config struct {
	Level       Level  // Minimum log level
	EnableColor bool   // Enable ANSI colors
	Prefix      string // Log prefix (e.g., "[WHISPERA]")
	ShowCaller  bool   // Show caller file:line
	TimeFormat  string // Time format string
	Stdout      io.Writer
	Stderr      io.Writer
}

// DefaultConfig returns default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:       LevelInfo,
		EnableColor: true,
		Prefix:      "[WHISPERA]",
		ShowCaller:  false,
		TimeFormat:  "2006-01-02 15:04:05",
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
	}
}

// Logger provides structured logging
type Logger struct {
	mu     sync.Mutex
	config *Config
	fields map[string]interface{}
}

// New creates a new logger
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

// WithField returns a new logger with the field added
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

// WithFields returns a new logger with multiple fields added
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

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config.Level = level
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config.Level
}

// log is the internal logging method
func (l *Logger) log(level Level, msg string, args ...interface{}) {
	if level < l.config.Level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Choose output: errors go to stderr, rest to stdout
	var out io.Writer
	if level >= LevelError {
		out = l.config.Stderr
	} else {
		out = l.config.Stdout
	}

	// Build the log line
	var sb strings.Builder

	// Timestamp
	timestamp := time.Now().Format(l.config.TimeFormat)

	// Color prefix
	colorReset := "\033[0m"
	if l.config.EnableColor {
		sb.WriteString(level.Color())
	}

	// Prefix
	if l.config.Prefix != "" {
		sb.WriteString(l.config.Prefix)
		sb.WriteString(" ")
	}

	// Timestamp and level
	sb.WriteString(fmt.Sprintf("[%s] [%s] ", timestamp, level.String()))

	// Caller info
	if l.config.ShowCaller {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			// Extract just the filename
			parts := strings.Split(file, "/")
			if len(parts) > 0 {
				file = parts[len(parts)-1]
			}
			sb.WriteString(fmt.Sprintf("(%s:%d) ", file, line))
		}
	}

	// Message
	if len(args) > 0 {
		sb.WriteString(fmt.Sprintf(msg, args...))
	} else {
		sb.WriteString(msg)
	}

	// Fields
	if len(l.fields) > 0 {
		sb.WriteString(" |")
		for k, v := range l.fields {
			sb.WriteString(fmt.Sprintf(" %s=%v", k, v))
		}
	}

	// Color reset
	if l.config.EnableColor {
		sb.WriteString(colorReset)
	}

	sb.WriteString("\n")

	// Write to output
	fmt.Fprint(out, sb.String())
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...interface{}) {
	l.log(LevelDebug, msg, args...)
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...interface{}) {
	l.log(LevelInfo, msg, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.log(LevelWarn, msg, args...)
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...interface{}) {
	l.log(LevelError, msg, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.log(LevelFatal, msg, args...)
	os.Exit(1)
}

// Fatalf logs a fatal message with format and exits (compatibility with standard log)
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(LevelFatal, format, args...)
	os.Exit(1)
}

// Printf logs at info level (compatibility with standard log)
func (l *Logger) Printf(format string, args ...interface{}) {
	l.Info(format, args...)
}

// Println logs at info level (compatibility with standard log)
func (l *Logger) Println(args ...interface{}) {
	l.Info("%s", fmt.Sprint(args...))
}

// Global logger instance
var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

// Global returns the global logger instance
func Global() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = New(nil)
	})
	return globalLogger
}

// SetGlobal sets the global logger instance
func SetGlobal(l *Logger) {
	globalLogger = l
}

// Package-level convenience functions

// Debug logs a debug message
func Debug(msg string, args ...interface{}) {
	Global().Debug(msg, args...)
}

// Info logs an info message
func Info(msg string, args ...interface{}) {
	Global().Info(msg, args...)
}

// Warn logs a warning message
func Warn(msg string, args ...interface{}) {
	Global().Warn(msg, args...)
}

// Error logs an error message
func Error(msg string, args ...interface{}) {
	Global().Error(msg, args...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, args ...interface{}) {
	Global().Fatal(msg, args...)
}

// WithField returns a new logger with the field added
func WithField(key string, value interface{}) *Logger {
	return Global().WithField(key, value)
}

// WithFields returns a new logger with multiple fields added
func WithFields(fields map[string]interface{}) *Logger {
	return Global().WithFields(fields)
}

// SetLevel sets the global log level
func SetLevel(level Level) {
	Global().SetLevel(level)
}

// ParseLevel parses a level string
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

// Module logger creates a logger for a specific module
func Module(name string) *Logger {
	return Global().WithField("module", name)
}
