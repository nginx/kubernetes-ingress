package log

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
)

type ctxLogger struct{}

// ContextWithLogger adds logger to context
func ContextWithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxLogger{}, l)
}

// LoggerFromContext returns logger from context
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxLogger{}).(*slog.Logger); ok {
		return l
	}
	return slog.New(glog.New(os.Stdout, nil))
}

// Tracef returns formatted trace log
func Tracef(logger *slog.Logger, format string, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelTrace) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Tracef]
	r := slog.NewRecord(time.Now(), levels.LevelTrace, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Trace returns raw trace log
func Trace(logger *slog.Logger, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelTrace) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Trace]
	r := slog.NewRecord(time.Now(), levels.LevelTrace, fmt.Sprint(args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Debugf returns formatted trace log
func Debugf(logger *slog.Logger, format string, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelDebug) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Debugf]
	r := slog.NewRecord(time.Now(), levels.LevelDebug, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Debug returns raw trace log
func Debug(logger *slog.Logger, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelDebug) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Debug]
	r := slog.NewRecord(time.Now(), levels.LevelDebug, fmt.Sprint(args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Infof returns formatted trace log
func Infof(logger *slog.Logger, format string, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelInfo) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Infof]
	r := slog.NewRecord(time.Now(), levels.LevelInfo, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Info returns raw trace log
func Info(logger *slog.Logger, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelInfo) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Info]
	r := slog.NewRecord(time.Now(), levels.LevelInfo, fmt.Sprint(args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Warnf returns formatted trace log
func Warnf(logger *slog.Logger, format string, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelWarning) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Warn]
	r := slog.NewRecord(time.Now(), levels.LevelWarning, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Warn returns raw trace log
func Warn(logger *slog.Logger, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelWarning) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Warn]
	r := slog.NewRecord(time.Now(), levels.LevelWarning, fmt.Sprint(args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Errorf returns formatted trace log
func Errorf(logger *slog.Logger, format string, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelError) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Errorf]
	r := slog.NewRecord(time.Now(), levels.LevelError, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Error returns raw trace log
func Error(logger *slog.Logger, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelError) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Error]
	r := slog.NewRecord(time.Now(), levels.LevelError, fmt.Sprint(args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
}

// Fatalf returns formatted trace log
func Fatalf(logger *slog.Logger, format string, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelFatal) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Errorf]
	r := slog.NewRecord(time.Now(), levels.LevelFatal, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
	os.Exit(1)
}

// Fatal returns raw trace log
func Fatal(logger *slog.Logger, args ...any) {
	if !logger.Enabled(context.Background(), levels.LevelFatal) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Error]
	r := slog.NewRecord(time.Now(), levels.LevelFatal, fmt.Sprint(args...), pcs[0])
	_ = logger.Handler().Handle(context.Background(), r)
	os.Exit(1)
}
