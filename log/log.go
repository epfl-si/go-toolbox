package log

import (
	"encoding/json"

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
