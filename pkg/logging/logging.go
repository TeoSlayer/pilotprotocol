package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Setup configures the default slog logger with the given level and format.
// format can be "text" (human-readable) or "json" (machine-parseable).
// level can be "debug", "info", "warn", "error".
func Setup(level, format string) {
	SetupWriter(os.Stderr, level, format)
}

// SetupWriter configures the default slog logger writing to w.
func SetupWriter(w io.Writer, level, format string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(w, opts)
	default:
		handler = slog.NewTextHandler(w, opts)
	}

	slog.SetDefault(slog.New(handler))
}
