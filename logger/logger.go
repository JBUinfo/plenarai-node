package logger

import (
	"log/slog"
	"os"
)

var Log *slog.Logger

func Init(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	Log = slog.New(handler)
}
