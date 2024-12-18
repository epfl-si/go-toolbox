package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/epfl-si/go-toolbox/log"
	"golang.org/x/net/http2"
)

// CallApi calls the API with the specified HTTP verb, URL, payload, user ID, and password.
//
// It returns a pointer to http.Response and an error.
func CallApi(verb string, url string, payload string, userId string, password string) ([]byte, *http.Response, error) {
	if os.Getenv("API_USERID") == "" || os.Getenv("API_USERPWD") == "" {
		return nil, nil, fmt.Errorf("missing API_USERID or API_USERPWD environment variable")
	}

	//fmt.Printf("--------- call %s:%s\n", verb, url)
	client := &http.Client{}

	// Create an HTTP/2 transport and attach it to the client
	http2Transport := &http2.Transport{}
	client.Transport = http2Transport

	bodyReader := bytes.NewReader([]byte(payload))
	req, err := http.NewRequest(verb, url, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	// if credentials defined, pass them
	if userId != "" {
		req.SetBasicAuth(userId, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("error calling %s: %s", url, err.Error())
		return nil, resp, err
	}
	defer resp.Body.Close()

	resBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp, fmt.Errorf("error calling %s: ReadAll body: %s, response: %s", url, err.Error(), log.PrettyPrintStruct(resp))
	}

	if resp.StatusCode >= 400 {
		return resBytes, resp, fmt.Errorf("error calling %s: statusCode: %d, body: %s", url, resp.StatusCode, string(resBytes))
	}

	return resBytes, resp, nil
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
