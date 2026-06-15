package logger

import (
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	s *zap.SugaredLogger
}

func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{s: l.s.With(key, value)}
}

func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	kv := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		kv = append(kv, k, v)
	}
	return &Logger{s: l.s.With(kv...)}
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.s.Debugf(msg, args...)
	} else {
		l.s.Debug(msg)
	}
}

func (l *Logger) Info(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.s.Infof(msg, args...)
	} else {
		l.s.Info(msg)
	}
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.s.Warnf(msg, args...)
	} else {
		l.s.Warn(msg)
	}
}

func (l *Logger) Error(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.s.Errorf(msg, args...)
	} else {
		l.s.Error(msg)
	}
}

func (l *Logger) Fatal(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.s.Fatalf(msg, args...)
	} else {
		l.s.Fatal(msg)
	}
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.s.Fatalf(format, args...)
}

func (l *Logger) Printf(format string, args ...interface{}) {
	l.Info(format, args...)
}

func (l *Logger) Println(args ...interface{}) {
	l.s.Info(args...)
}

func (l *Logger) SetLevel(level Level) {
	globalOnce.Do(buildGlobal)
	globalLevel.SetLevel(toZapLevel(level))
}

func (l *Logger) GetLevel() Level {
	globalOnce.Do(buildGlobal)
	switch globalLevel.Level() {
	case zapcore.DebugLevel:
		return LevelDebug
	case zapcore.InfoLevel:
		return LevelInfo
	case zapcore.WarnLevel:
		return LevelWarn
	case zapcore.FatalLevel:
		return LevelFatal
	default:
		return LevelError
	}
}

func (l *Logger) SetOutput(w io.Writer) {
	globalOnce.Do(buildGlobal)
	globalErrSink.set(w)
}
