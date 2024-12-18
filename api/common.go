package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// CallApi calls the API with the specified HTTP verb, URL, payload, user ID, and password.
//
// It returns a pointer to http.Response and an error.
func CallApi(verb string, url string, payload string, userId string, password string) ([]byte, *http.Response, error) {
	if os.Getenv("API_USERID") == "" || os.Getenv("API_USERPWD") == "" {
		return nil, nil, fmt.Errorf("missing API_USERID or API_USERPWD environment variable")
	}

	transport := &http.Transport{
		ForceAttemptHTTP2: false, // Disable HTTP/2
	}

	//fmt.Printf("--------- call %s:%s\n", verb, url)
	client := &http.Client{
		Transport: transport,
		Timeout:   240 * time.Second,
	}

	bodyReader := bytes.NewReader([]byte(payload))
	req, err := http.NewRequest(verb, url, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept-Encoding", "identity")

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
		return nil, resp, fmt.Errorf("error calling %s: ReadAll body: %s, response.Content-Length: %d, response.Transfer-Encoding: %s, HTTP Version: %s (Major: %d, Minor: %d)", url, err.Error(), resp.ContentLength, resp.Header.Get("Transfer-Encoding"), resp.Proto, resp.ProtoMajor, resp.ProtoMinor)
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
