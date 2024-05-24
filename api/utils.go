package api

import (
	"strings"

	api "github.com/epfl-si/go-toolbox/api/models"
	"github.com/gin-gonic/gin"
)

func MakeError(c *gin.Context, errorType string, status int, message string, detail string, help string, errors []api.ErrorDetail) *api.Error {
	if errorType == "" {
		errorType = GetHttpStatusCategory(status)
	}

	// "instance" is URL path
	instance := c.Request.RequestURI
	// remove first group which contains the API internal name ("/groups-api")
	idx := strings.Index(instance[1:], "/")
	if idx != -1 {
		instance = instance[idx+1:]
	}

	return &api.Error{
		Type:     errorType,
		Title:    message,
		Status:   status,
		Detail:   detail,
		Instance: instance,
		Help:     help,
		Errors:   errors,
	}
}

func GetHttpStatusCategory(status int) string {
	switch {
	case status >= 100 && status < 200:
		return "information"
	case status >= 200 && status < 300:
		return "success"
	case status >= 300 && status < 400:
		return "redirection"
	case status >= 400 && status < 500:
		return "client error"
	case status >= 500 && status < 600:
		return "server error"
	default:
		return "unknown"
	}
}
