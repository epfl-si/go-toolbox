package testing

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"

	api_models "github.com/epfl-si/go-toolbox/api/models"
	"github.com/epfl-si/go-toolbox/log"
	"github.com/gin-gonic/gin"
	"github.com/wI2L/jsondiff"
	"go.uber.org/zap"
)

// MakeRequest makes an HTTP request with the specified verb, URL, payload, schema, and value.
//
// Parameters:
// - verb string: the HTTP verb (GET, POST, PUT, etc.)
// - url string: the URL to make the request to
// - payload string: the payload to include in the request
// - schema string: the type of authentication schema to use (basic, bearer, etc.)
// - value string: the value used for authentication (bearer token for bearer schema, username for basic schema)
//
// Return type(s):
// - *http.Response: the HTTP response
// - error: an error, if any, encountered during the request
func MakeRequest(verb string, url string, payload string, schema string, value string) (*http.Response, error) {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport}

	bodyReader := bytes.NewReader([]byte(payload))

	req, err := http.NewRequest(verb, "http://localhost:8080"+url, bodyReader)
	if err != nil {
		return nil, err
	}

	// set credentials depending on schema
	if schema == "basic" {
		req.SetBasicAuth(value, "1234")
	}
	if schema == "bearer" {
		req.Header.Add("Authorization", "Bearer "+value)
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error calling %s: %s", "http://localhost:8080"+url, err.Error())
		return nil, err
	}

	return resp, nil
}

// CompareResponses compares the actual response with the reference file and returns a boolean indicating the result, a string representing any differences, and an error if any.
//
// Parameters:
// - actual string: the JSON string we want to test against the reference file
// - referenceFilename string: the name of the reference file to compare
//
// Return type(s):
// - bool: whether the actual response matches the reference file
// - string: a string representing any differences
// - error: an error, if any, encountered during the comparison
func CompareResponses(actual string, referenceFilename string) (bool, string, error) {
	var v1, v2 interface{}

	// marshal actual response date
	json.Unmarshal([]byte(actual), &v1)

	// read 'expected' data from file
	pwd, _ := os.Getwd()
	rootPath := strings.ReplaceAll(pwd, "internal/api", "")
	b, err := os.ReadFile(rootPath + "assets/tests/" + referenceFilename)
	if err != nil {
		return false, "", err
	}
	json.Unmarshal(b, &v2)

	if reflect.DeepEqual(v1, v2) {
		return true, "", nil
	} else {
		patch, err := jsondiff.CompareJSON([]byte(actual), b)
		if err != nil {
			return false, "", err
		}
		diffs, err := json.MarshalIndent(patch, "", "    ")
		if err != nil {
			return false, "", err
		}
		//fmt.Printf("%s\n", string(diffs))
		return false, string(diffs), nil
	}
}

// Generic getter for mock files
func GetMockGeneric(logger *zap.Logger, c *gin.Context) {
	version := c.Param("apiversion")

	filePath := strings.ReplaceAll(c.Request.URL.Path, fmt.Sprintf("/mocks/%s/", version), "")
	// Check if the last character is '/' and remove it if true
	if len(filePath) > 0 && filePath[len(filePath)-1] == '/' {
		filePath = filePath[:len(filePath)-1]
	}
	filePath = strings.ReplaceAll(filePath, "/", "_")

	// Add params in path
	params := ""
	queryParams := c.Request.URL.Query()
	for key, value := range queryParams {
		if value[0] == "" {
			continue
		}
		params += fmt.Sprintf("_%s=%s", key, strings.Join(value, ","))
	}

	filePath = "/home/dinfo/mocks/" + version + "/GET_" + filePath + params + ".json"

	b, err := os.ReadFile(filePath)
	if err != nil {
		log.LogApiError(logger, c, "cannot read mock file '"+filePath+"'")
		c.JSON(http.StatusInternalServerError, gin.H{"details": "cannot read mock file '" + filePath + "'"})
		return
	}
	log.LogApiInfo(logger, c, "Mock file read successfully: '"+filePath+"'")

	httpStatus := http.StatusOK

	// If it can Unmarshal the response into an error, then it means it is an error and we want to retrieve its Status
	var apiError api_models.Error
	err = json.Unmarshal(b, &apiError)
	if err == nil {
		httpStatus = apiError.Status
	}

	c.Data(httpStatus, "application/json", b)
}
