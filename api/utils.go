package api

import api "github.com/epfl-si/go-toolbox/api/models"

func MakeError(errorType string, status int, message string, detail string, instance string, help string) *api.Error {
	return &api.Error{
		Type:     errorType,
		Title:    message,
		Status:   status,
		Detail:   detail,
		Instance: instance,
		Help:     help,
	}
}
