package log

import (
	"encoding/json"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func GetLoggerConfig(logLevel string, stdouts []string, stderrs []string, encoding string) zap.Config {
	level := zap.InfoLevel
	if logLevel == "debug" {
		level = zap.DebugLevel
	}
	if logLevel == "error" {
		level = zap.ErrorLevel
	}
	if logLevel == "warn" {
		level = zap.WarnLevel
	}
	if logLevel == "fatal" {
		level = zap.FatalLevel
	}

	// Get a new logger
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timegenerated"
	encoderCfg.LevelKey = "log.level"
	encoderCfg.EncodeTime = zapcore.RFC3339TimeEncoder
	encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	config := zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		Development:       false,
		DisableCaller:     true,
		DisableStacktrace: false,
		Sampling:          nil,
		Encoding:          encoding,
		EncoderConfig:     encoderCfg,
		OutputPaths:       stdouts,
		ErrorOutputPaths:  stderrs,
		InitialFields:     map[string]interface{}{
			//"pid": os.Getpid(),
		},
	}

	return config
}

// GetLogger returns a new logger with the specified log level.
//
// Parameters:
// - logLevel: a string representing the log level ("debug", "error", "warn", "fatal")
//
// Return type(s):
// - *zap.Logger: a pointer to the logger
func GetLogger(logLevel string) *zap.Logger {
	return zap.Must(GetLoggerConfig(logLevel, []string{"stdout"}, []string{"stderr"}, "json").Build())
}

func PrettyPrintStruct(data any) string {
	prettyJSON, _ := json.MarshalIndent(data, "", "  ")
	return string(prettyJSON)
}

func LogApiMessage(logger *zap.Logger, priority, message string) {
	if strings.ToUpper(priority) == "INFO" {
		logger.Info(message,
			zap.String("event.dataset", os.Getenv("API_NAME")))
	} else if strings.ToUpper(priority) == "WARN" {
		logger.Warn(message,
			zap.String("event.dataset", os.Getenv("API_NAME")))
	} else if strings.ToUpper(priority) == "ERROR" {
		logger.Error(message,
			zap.String("event.dataset", os.Getenv("API_NAME")))
	} else if strings.ToUpper(priority) == "FATAL" {
		logger.Error(message,
			zap.String("event.dataset", os.Getenv("API_NAME")))
	} else if strings.ToUpper(priority) == "DEBUG" {
		logger.Debug(message,
			zap.String("event.dataset", os.Getenv("API_NAME")))
	}
}
