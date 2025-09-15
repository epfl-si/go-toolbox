package log

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
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
//   - logLevel: a string representing the log level ("debug", "error", "warn", "fatal")
//     "info" is the default log level (in case you pass an invalid level)
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

// LogApi logs a message at the specified level with context information
func LogApi(logger *zap.Logger, level string, ctx *gin.Context, message string) {
	reqMethod := ctx.Request.Method
	reqUri := ctx.Request.RequestURI
	statusCode := ctx.Writer.Status()

	// Request IP - consistent handling for all levels
	clientIP := ctx.GetHeader("X-Forwarded-For")
	if clientIP == "" {
		clientIP = ctx.ClientIP()
	}

	// UUID - consistent handling for all levels
	uuid := ctx.GetHeader("X-Krakend-UUID")
	if uuid == "" {
		val, _ := ctx.Get("uuid")
		uuid = fmt.Sprintf("%v", val)
	}

	userIdValue, _ := ctx.Get("userId")
	userId := ""
	if userIdValue != nil {
		userId = fmt.Sprintf("%v", userIdValue)
	}

	// Common fields for all log levels
	fields := []zap.Field{
		zap.String("event.dataset", os.Getenv("API_NAME")),
		zap.String("http.request.method", reqMethod),
		zap.String("url.path", reqUri),
		zap.Int("http.response.status_code", statusCode),
		zap.String("client.address", clientIP),
		zap.String("user.id", userId),
		zap.String("uuid", uuid),
	}

	// Add processing_time for debug and info levels
	if strings.ToUpper(level) != "ERROR" {
		fields = append(fields, zap.Int64("processing_time", ctx.GetInt64("processing_time")))
	}

	// Log at the appropriate level
	switch strings.ToUpper(level) {
	case "DEBUG":
		logger.Debug(message, fields...)
	case "INFO":
		logger.Info(message, fields...)
	case "ERROR":
		logger.Error(message, fields...)
	case "WARN":
		logger.Warn(message, fields...)
	default:
		logger.Info(message, fields...) // Default to Info level
	}
}

func LogApiInfo(logger *zap.Logger, ctx *gin.Context, message string) {
	LogApi(logger, "INFO", ctx, message)
}

func LogApiDebug(logger *zap.Logger, ctx *gin.Context, message string) {
	LogApi(logger, "DEBUG", ctx, message)
}

func LogApiError(logger *zap.Logger, ctx *gin.Context, message string) {
	LogApi(logger, "ERROR", ctx, message)
}

func LogApiCustom(logger *zap.Logger, level string, method string, uri string, status int, body string, msg string) {
	if level == "info" {
		logger.Info(msg,
			zap.String("event.dataset", os.Getenv("API_NAME")),
			zap.String("http.request.method", method),
			zap.String("url.path", uri),
			zap.Int("http.response.status_code", status),
		)
	}
	if level == "error" {
		logger.Error(msg,
			zap.String("event.dataset", os.Getenv("API_NAME")),
			zap.String("http.request.method", method),
			zap.String("url.path", uri),
			zap.Int("http.response.status_code", status),
		)
	}
}
