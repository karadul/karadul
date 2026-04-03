package log

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents log severity.
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
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return LevelDebug
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Format is the log output format.
type Format int

const (
	FormatText Format = iota
	FormatJSON
)

// Logger is a structured logger.
type Logger struct {
	mu     sync.Mutex
	out    io.Writer
	level  Level
	format Format
	fields []field
}

type field struct {
	key string
	val interface{}
}

// New creates a new Logger writing to out.
func New(out io.Writer, level Level, format Format) *Logger {
	if out == nil {
		out = os.Stderr
	}
	return &Logger{out: out, level: level, format: format}
}

// Default is the package-level default logger.
var Default = New(os.Stderr, LevelInfo, FormatText)

// With returns a new Logger with additional fields attached.
func (l *Logger) With(args ...interface{}) *Logger {
	fields := make([]field, len(l.fields))
	copy(fields, l.fields)
	for i := 0; i+1 < len(args); i += 2 {
		fields = append(fields, field{
			key: fmt.Sprintf("%v", args[i]),
			val: args[i+1],
		})
	}
	return &Logger{
		out:    l.out,
		level:  l.level,
		format: l.format,
		fields: fields,
	}
}

func (l *Logger) log(level Level, msg string, args []interface{}) {
	if level < l.level {
		return
	}
	now := time.Now()

	// Merge base fields + call-site args
	allFields := make([]field, len(l.fields))
	copy(allFields, l.fields)
	for i := 0; i+1 < len(args); i += 2 {
		allFields = append(allFields, field{
			key: fmt.Sprintf("%v", args[i]),
			val: args[i+1],
		})
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.format == FormatJSON {
		m := map[string]interface{}{
			"time":  now.UTC().Format(time.RFC3339Nano),
			"level": level.String(),
			"msg":   msg,
		}
		for _, f := range allFields {
			m[f.key] = f.val
		}
		b, _ := json.Marshal(m)
		fmt.Fprintf(l.out, "%s\n", b)
		return
	}

	// Text format: level=info time=... msg="..." key=val ...
	fmt.Fprintf(l.out, "level=%s time=%s msg=%q",
		level.String(),
		now.UTC().Format("2006-01-02T15:04:05.000Z"),
		msg,
	)
	for _, f := range allFields {
		fmt.Fprintf(l.out, " %s=%v", f.key, f.val)
	}
	fmt.Fprintln(l.out)
}

func (l *Logger) Debug(msg string, args ...interface{}) { l.log(LevelDebug, msg, args) }
func (l *Logger) Info(msg string, args ...interface{})  { l.log(LevelInfo, msg, args) }
func (l *Logger) Warn(msg string, args ...interface{})  { l.log(LevelWarn, msg, args) }
func (l *Logger) Error(msg string, args ...interface{}) { l.log(LevelError, msg, args) }

// Package-level helpers using Default.
func Debug(msg string, args ...interface{}) { Default.Debug(msg, args...) }
func Info(msg string, args ...interface{})  { Default.Info(msg, args...) }
func Warn(msg string, args ...interface{})  { Default.Warn(msg, args...) }
func Error(msg string, args ...interface{}) { Default.Error(msg, args...) }

func SetLevel(level Level) {
	Default.mu.Lock()
	Default.level = level
	Default.mu.Unlock()
}

func SetFormat(format Format) {
	Default.mu.Lock()
	Default.format = format
	Default.mu.Unlock()
}
