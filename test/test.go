package log

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/wI2L/jsondiff"
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
