package api

import api "github.com/epfl-si/go-toolbox/api/models"

func MakeError(errorType string, status int, message string, detail string, instance string, help string) *api.Error {
	if errorType == "" {
		errorType = GetHttpStatusCategory(status)
	}
	return &api.Error{
		Type:     errorType,
		Title:    message,
		Status:   status,
		Detail:   detail,
		Instance: instance,
		Help:     help,
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
