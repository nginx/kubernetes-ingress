package levels

import "log/slog"

const (
	// LevelTrace - Trace Level Logging same as glog.V(3)
	LevelTrace = slog.Level(-8)
	// LevelDebug - Debug Level Logging same as glog.V(2)
	LevelDebug = slog.LevelDebug
	// LevelInfo - Info Level Logging same as glog.Info()
	LevelInfo = slog.LevelInfo
	// LevelWarning - Warn Level Logging same as glog.Warning()
	LevelWarning = slog.LevelWarn
	// LevelError - Error Level Logging same as glog.Error()
	LevelError = slog.LevelError
	// LevelFatal - Fatal Level Logging same as glog.Fatal()
	LevelFatal = slog.Level(12)
)
