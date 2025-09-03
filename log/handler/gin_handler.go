// Package handler for gin logging handler
package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// LoggingResponse is the response structure for logging level endpoints
type LoggingResponse struct {
	Level string `json:"level"`
}

// GetLogging returns the current logging level
//
// use in routes.go :
//
//	import toolbox_handler "github.com/epfl-si/go-toolbox/log/handler"
//	...
//	// GetLogging returns the current logging level
//	router.GET("/log/leel", toolbox_handler.GetLogging(s.Log))  // s.Log being a zap logger
//
// @Summary     Get the current logging level
// @Tags        log
// @Produce     json
// @Success     200  {object} LoggingResponse
// @Router      /log/level [get]
func GetLogging(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var response LoggingResponse
		currentLevel := log.Level()

		log.Sugar().Warnf("AA Current logging level SHOULD MAYBE be different than %s", zap.String("level", currentLevel.String()))
		log.Sugar().Infof("Current logging level is indeed %s", currentLevel.String())
		log.Sugar().Debugf("Current logging detail level is very precisely %s", currentLevel.String())

		response.Level = currentLevel.String()
		c.JSON(http.StatusOK, response)
	}
}

// IncreaseLoggingLevel is the handler to increase the logging level
//
// use in routes.go :
//
//	import toolbox_handler "github.com/epfl-si/go-toolbox/log/handler"
//	...
//	router.GET("/log/decrease", toolbox_handler.IncreaseLogging(s.Log, s.Atom))  // s.Log being a zap logger, s.Atom being a zap.AtomicLevel
//
// @Summary     Increase the logging threshold/level and thus DECREASE the verbosity
// @Tags        log
// @Produce     json
// @Success     200  {object} LoggingResponse
// @Router      /log/decrease [get]
func IncreaseLoggingLevel(log *zap.Logger, atom *zap.AtomicLevel) gin.HandlerFunc {
	return func(c *gin.Context) {
		var response LoggingResponse

		switch log.Level() {
		case zap.DebugLevel:
			log.Info("Increasing logging level to info")
			atom.SetLevel(zap.InfoLevel)
			response.Level = "info"
		case zap.InfoLevel:
			log.Info("Increasing logging level to warn")
			atom.SetLevel(zap.WarnLevel)
			response.Level = "warn"
		case zap.WarnLevel:
			log.Info("Increasing logging level to error")
			atom.SetLevel(zap.ErrorLevel)
			response.Level = "error"
		case zap.ErrorLevel:
			log.Info("Logging level is already at Error")
			response.Level = "error"
		}
		c.JSON(http.StatusOK, response)
	}
}

// DecreaseLoggingLevel is the handler to decrease the logging level
//
// use in routes.go :
//
//	import toolbox_handler "github.com/epfl-si/go-toolbox/log/handler"
//	...
//	router.GET("/levlog/increase", toolbox_handler.DecreaseLogging(s.Log, s.Atom))  // s.Log being a zap logger, s.Atom being a zap.AtomicLevel
//
// @Summary     Decrease the logging threshold/level and thus INCREASE the verbosity
// @Tags        log
// @Produce     json
// @Success     200  {object} LoggingResponse
// @Router      /log/increase [get]
func DecreaseLoggingLevel(log *zap.Logger, atom *zap.AtomicLevel) gin.HandlerFunc {
	return func(c *gin.Context) {
		var response LoggingResponse

		switch log.Level() {
		case zap.DebugLevel:
			log.Info("Logging level is already debug")
			response.Level = "debug"
		case zap.InfoLevel:
			log.Info("Decreasing logging level to debug")
			atom.SetLevel(zap.DebugLevel)
			response.Level = "debug"
		case zap.WarnLevel:
			log.Info("Decreasing logging level to info")
			atom.SetLevel(zap.InfoLevel)
			response.Level = "info"
		case zap.ErrorLevel:
			log.Info("Decreasing logging level to warn")
			atom.SetLevel(zap.WarnLevel)
			response.Level = "warn"
		case zap.FatalLevel:
			log.Info("Decreasing logging level to error")
			atom.SetLevel(zap.ErrorLevel)
			response.Level = "error"
		}

		c.JSON(http.StatusOK, response)
	}
}

// SetLoggingLevel is the handler to set the log priority level
//
// use in routes.go :
//
//	import toolbox_handler "github.com/epfl-si/go-toolbox/log/handler"
//	...
//	router.GET("/log/set", toolbox_handler.SetLoggingLevel(s.Log, s.Atom, "info"))  // s.Log being a zap.Logger, s.Atom being a zap.AtomicLevel
//
// @Summary     Set the logging threshold/level based on query-string ("debug", "info", "warn", "error")
// @Tags        log
// @Produce     json
// @Success     200  {object} LoggingResponse
// @Router      /log/set [post]
func SetLoggingLevel(log *zap.Logger, atom *zap.AtomicLevel) gin.HandlerFunc {
	return func(c *gin.Context) {
		var response LoggingResponse
		var level = c.Query("level")

		switch strings.ToLower(level) {
		case "debug":
			log.Info("Logging level set to : debug")
			atom.SetLevel(zap.DebugLevel)
			response.Level = "debug"
		case "info":
			log.Info("Logging level set to : info")
			atom.SetLevel(zap.InfoLevel)
			response.Level = "info"
		case "warn":
			log.Info("Logging level set to : warn")
			atom.SetLevel(zap.WarnLevel)
			response.Level = "warn"
		case "error":
			log.Info("Logging level set to : error")
			atom.SetLevel(zap.ErrorLevel)
			response.Level = "error"
		}

		c.JSON(http.StatusOK, response)
	}
}
