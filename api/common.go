package api

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
)

// CallApi calls the API with the specified HTTP verb, URL, payload, user ID, and password.
//
// It returns a pointer to http.Response and an error.
func CallApi(verb string, url string, payload string, userId string, password string) (*http.Response, error) {
	if os.Getenv("API_USERID") == "" || os.Getenv("API_USERPWD") == "" {
		return nil, fmt.Errorf("missing API_USERID or API_USERPWD environment variable")
	}

	//fmt.Printf("--------- call %s:%s\n", verb, url)
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport}

	bodyReader := bytes.NewReader([]byte(payload))
	req, err := http.NewRequest(verb, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	// if credentials defined, pass them
	if userId != "" {
		req.SetBasicAuth(userId, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("error calling %s: %s", url, err.Error())
		return nil, err
	}
	if resp.StatusCode >= 400 {
		resBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error calling %s: ReadAll body: %s", url, err.Error())
		}
		return nil, fmt.Errorf("error calling %s: statusCode: %d, body: %s", url, resp.StatusCode, string(resBytes))
	}

	return resp, nil
}

// checkEnvironment checks the environment for required variables.
//
// Returns an error if something's wrong
func checkEnvironment() error {
	if os.Getenv("API_GATEWAY_URL") == "" {
		return fmt.Errorf("missing API_GATEWAY_URL environment variable, possible values are 'https://api-test.epfl.ch', 'https://api-preprod.epfl.ch', 'https://api.epfl.ch'")
	}
	return nil
}
