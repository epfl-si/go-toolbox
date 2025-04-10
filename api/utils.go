package api

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	api "github.com/epfl-si/go-toolbox/api/models"
	"github.com/epfl-si/go-toolbox/messages"
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

func LowercaseQueryParameters(c *gin.Context) {
	// alter query parameters to lowercase
	// Retrieve query parameters
	queryParams := c.Request.URL.Query()
	// Convert query parameters to lower case
	newQuery := url.Values{}
	for key, values := range queryParams {
		lowerCaseKey := strings.ToLower(key)
		for _, value := range values {
			newQuery.Add(lowerCaseKey, value)
		}
	}
	// Create a new URL with the modified query parameters
	newURL := *c.Request.URL
	newURL.RawQuery = newQuery.Encode()
	// Update the request URL
	c.Request.URL = &newURL
}

func GetContext(c *gin.Context) (api.Context, error) {
	lang, _ := c.Get("lang")
	langStr := fmt.Sprintf("%s", lang)

	userIdValue, _ := c.Get("userId")
	userId := fmt.Sprintf("%s", userIdValue)
	if userId == "" {
		return api.Context{}, errors.New(messages.GetMessage(langStr, "NoUserId"))
	}

	userTypeValue, _ := c.Get("userType")
	userType := fmt.Sprintf("%s", userTypeValue)

	scopesValue, _ := c.Get("scopes")
	scopes := []string{}
	if scopesValue != nil {
		scopes, _ = scopesValue.([]string)
	}

	isRootValue, exists := c.Get("isRoot")
	isRoot := false
	if exists {
		isRoot = isRootValue.(bool)
	}

	userIdOverridedValue, _ := c.Get("userIdOverrided")
	userIdOverrided := fmt.Sprintf("%s", userIdOverridedValue)

	// authorizations
	authorizationsValue, _ := c.Get("authorizations")
	authorizations := make(map[string][]string)
	if authorizationsValue != nil {
		authorizations = authorizationsValue.(map[string][]string)
	}

	// accreds
	accredsValue, _ := c.Get("accreds")
	accreds := []api.ClaimAccred{}
	if accredsValue != nil {
		accreds = accredsValue.([]api.ClaimAccred)
	}

	// cfs
	cfsValue, _ := c.Get("cfs")
	cfs := []string{}
	if cfsValue != nil {
		cfs = cfsValue.([]string)
	}

	return api.Context{
		UserId:          userId,
		UserType:        userType,
		Lang:            langStr,
		Scopes:          scopes,
		IsRoot:          isRoot,
		UserIdOverrided: userIdOverrided,
		Authorizations:  authorizations,
		Accreds:         accreds,
		CFs:             cfs,
	}, nil
}
