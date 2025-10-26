package logging

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog.Logger with additional functionality
type Logger struct {
	logger zerolog.Logger
}

// Config holds logging configuration
type Config struct {
	Level          string // debug, info, warn, error
	Format         string // json, console
	Caller         bool   // Include caller information
	TimeFormat     string // Time format for logs
	SamplingRate   int    // Sample 1 in N debug messages (0 = no sampling)
}

// DefaultConfig returns default logging configuration
func DefaultConfig() *Config {
	return &Config{
		Level:        "info",
		Format:       "json",
		Caller:       true,
		TimeFormat:   time.RFC3339Nano,
		SamplingRate: 0, // No sampling by default
	}
}

// New creates a new structured logger
func New(cfg *Config) *Logger {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Set time format
	zerolog.TimeFieldFormat = cfg.TimeFormat

	// Parse log level
	logLevel := parseLogLevel(cfg.Level)

	// Create output writer
	var output io.Writer = os.Stdout
	if cfg.Format == "console" {
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
	}

	// Create base logger
	logger := zerolog.New(output).
		Level(logLevel).
		With().
		Timestamp().
		Logger()

	// Add caller information if enabled
	if cfg.Caller {
		logger = logger.With().Caller().Logger()
	}

	// Add sampling if configured
	if cfg.SamplingRate > 0 {
		logger = logger.Sample(&zerolog.BasicSampler{N: uint32(cfg.SamplingRate)})
	}

	return &Logger{logger: logger}
}

// parseLogLevel converts string level to zerolog.Level
func parseLogLevel(level string) zerolog.Level {
	switch level {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}

// WithField adds a field to the logger
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{
		logger: l.logger.With().Interface(key, value).Logger(),
	}
}

// WithFields adds multiple fields to the logger
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	logger := l.logger.With()
	for k, v := range fields {
		logger = logger.Interface(k, v)
	}
	return &Logger{logger: logger.Logger()}
}

// WithRequestID adds a request ID to the logger
func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{
		logger: l.logger.With().Str("request_id", requestID).Logger(),
	}
}

// WithUserID adds a user ID to the logger
func (l *Logger) WithUserID(userID string) *Logger {
	return &Logger{
		logger: l.logger.With().Str("user_id", userID).Logger(),
	}
}

// WithClientID adds a client ID to the logger
func (l *Logger) WithClientID(clientID string) *Logger {
	return &Logger{
		logger: l.logger.With().Str("client_id", clientID).Logger(),
	}
}

// WithError adds an error to the logger
func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		logger: l.logger.With().Err(err).Logger(),
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	l.logger.Debug().Msg(msg)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logger.Debug().Msgf(format, args...)
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.logger.Info().Msg(msg)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	l.logger.Info().Msgf(format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.logger.Warn().Msg(msg)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.logger.Warn().Msgf(format, args...)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.logger.Error().Msg(msg)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logger.Error().Msgf(format, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string) {
	l.logger.Fatal().Msg(msg)
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.logger.Fatal().Msgf(format, args...)
}

// Panic logs a panic message and panics
func (l *Logger) Panic(msg string) {
	l.logger.Panic().Msg(msg)
}

// Panicf logs a formatted panic message and panics
func (l *Logger) Panicf(format string, args ...interface{}) {
	l.logger.Panic().Msgf(format, args...)
}

// Event returns a new log event for chaining
type Event struct {
	event *zerolog.Event
}

// Debug returns a debug event
func (l *Logger) DebugEvent() *Event {
	return &Event{event: l.logger.Debug()}
}

// Info returns an info event
func (l *Logger) InfoEvent() *Event {
	return &Event{event: l.logger.Info()}
}

// Warn returns a warn event
func (l *Logger) WarnEvent() *Event {
	return &Event{event: l.logger.Warn()}
}

// Error returns an error event
func (l *Logger) ErrorEvent() *Event {
	return &Event{event: l.logger.Error()}
}

// Str adds a string field to the event
func (e *Event) Str(key, val string) *Event {
	e.event = e.event.Str(key, val)
	return e
}

// Strs adds a string slice field to the event
func (e *Event) Strs(key string, vals []string) *Event {
	e.event = e.event.Strs(key, vals)
	return e
}

// Int adds an int field to the event
func (e *Event) Int(key string, val int) *Event {
	e.event = e.event.Int(key, val)
	return e
}

// Int64 adds an int64 field to the event
func (e *Event) Int64(key string, val int64) *Event {
	e.event = e.event.Int64(key, val)
	return e
}

// Dur adds a duration field to the event
func (e *Event) Dur(key string, val time.Duration) *Event {
	e.event = e.event.Dur(key, val)
	return e
}

// Err adds an error field to the event
func (e *Event) Err(err error) *Event {
	e.event = e.event.Err(err)
	return e
}

// Bool adds a boolean field to the event
func (e *Event) Bool(key string, val bool) *Event {
	e.event = e.event.Bool(key, val)
	return e
}

// Interface adds an interface field to the event
func (e *Event) Interface(key string, val interface{}) *Event {
	e.event = e.event.Interface(key, val)
	return e
}

// Msg sends the event with a message
func (e *Event) Msg(msg string) {
	e.event.Msg(msg)
}

// Msgf sends the event with a formatted message
func (e *Event) Msgf(format string, args ...interface{}) {
	e.event.Msgf(format, args...)
}

// GetZerolog returns the underlying zerolog.Logger
func (l *Logger) GetZerolog() zerolog.Logger {
	return l.logger
}
