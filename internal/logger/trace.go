package logger

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	traceLogger *zap.SugaredLogger
	traceOnce   sync.Once
)

func Trace() *zap.SugaredLogger {
	traceOnce.Do(func() {
		syncers := []zapcore.WriteSyncer{zapcore.AddSync(os.Stdout)}
		path := os.Getenv("WHISPERA_TRACE_FILE")
		if path == "" {
			path = "/var/log/whispera/tunnel-trace.log"
		}
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			syncers = append(syncers, zapcore.AddSync(f))
		}
		encCfg := zap.NewProductionEncoderConfig()
		encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
		encCfg.TimeKey = "ts"
		encCfg.MessageKey = "event"
		core := zapcore.NewCore(
			zapcore.NewJSONEncoder(encCfg),
			zapcore.NewMultiWriteSyncer(syncers...),
			zapcore.InfoLevel,
		)
		traceLogger = zap.New(core, zap.AddCaller()).Named("tuntrace").Sugar()
	})
	return traceLogger
}
