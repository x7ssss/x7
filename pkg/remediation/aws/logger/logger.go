package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level defines log level severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
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
	default:
		return "UNKNOWN"
	}
}

// Logger provides structured, thread-safe console logging.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Tier(tier int, name string, msg string, args ...any)
	Success(msg string, args ...any)
}

type standardLogger struct {
	mu     sync.Mutex
	out    io.Writer
	errOut io.Writer
	level  Level
	json   bool
}

// NewLogger creates a new Logger with the specified level and output streams.
func NewLogger(level Level, json bool) Logger {
	return &standardLogger{
		out:    os.Stdout,
		errOut: os.Stderr,
		level:  level,
		json:   json,
	}
}

// NewCustomLogger creates a Logger writing to custom writers (helpful for tests).
func NewCustomLogger(out io.Writer, errOut io.Writer, level Level, json bool) Logger {
	return &standardLogger{
		out:    out,
		errOut: errOut,
		level:  level,
		json:   json,
	}
}

func (l *standardLogger) log(w io.Writer, lvl Level, prefix string, msg string, args ...any) {
	if lvl < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	formattedMsg := msg
	if len(args) > 0 {
		formattedMsg = fmt.Sprintf(msg, args...)
	}

	if l.json {
		// Suppress human logs to stdout when JSON output is active, redirect essential logs to stderr
		timestamp := time.Now().UTC().Format(time.RFC3339)
		fmt.Fprintf(l.errOut, `{"time":"%s","level":"%s","message":%q}`+"\n", timestamp, lvl.String(), formattedMsg)
		return
	}

	timestamp := time.Now().Format("15:04:05")
	fmt.Fprintf(w, "[%s] %-5s %s%s\n", timestamp, lvl.String(), prefix, formattedMsg)
}

func (l *standardLogger) Debug(msg string, args ...any) {
	l.log(l.out, LevelDebug, "", msg, args...)
}

func (l *standardLogger) Info(msg string, args ...any) {
	l.log(l.out, LevelInfo, "", msg, args...)
}

func (l *standardLogger) Warn(msg string, args ...any) {
	l.log(l.errOut, LevelWarn, "⚠️  ", msg, args...)
}

func (l *standardLogger) Error(msg string, args ...any) {
	l.log(l.errOut, LevelError, "❌ ", msg, args...)
}

func (l *standardLogger) Tier(tier int, name string, msg string, args ...any) {
	prefix := fmt.Sprintf("⏩ [Tier %d: %s] ", tier, name)
	l.log(l.out, LevelInfo, prefix, msg, args...)
}

func (l *standardLogger) Success(msg string, args ...any) {
	l.log(l.out, LevelInfo, "✅ ", msg, args...)
}
