package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

const maxResponseBodySize = 1 * 1024 * 1024 // 1MB — EPFL API responses are structured JSON for a single person; realistic max is ~100KB

var (
	httpClient     *http.Client
	httpClientOnce sync.Once
)

func getHTTPClient() *http.Client {
	httpClientOnce.Do(func() {
		transport := &http.Transport{
			ForceAttemptHTTP2:   false,                                                  // Disable HTTP/2
			TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{}, // Disable HTTP/2 upgrades
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     60 * time.Second,
		}

		httpClient = &http.Client{
			Transport: transport,
			Timeout:   240 * time.Second,
		}
	})
	return httpClient
}

// oversizedResponseDiag builds a diagnostic string for responses that exceeded the size limit.
// It includes the Content-Length header, an approximate item count, and a body preview.
func oversizedResponseDiag(resp *http.Response, partial []byte) string {
	contentLength := resp.Header.Get("Content-Length")
	if contentLength == "" {
		contentLength = fmt.Sprintf("%d", resp.ContentLength)
	}
	// Approximate item count: JSON arrays look like [{...},{...}] so "},{" appears N-1 times.
	itemCount := bytes.Count(partial, []byte("},{")) + 1
	preview := partial
	if len(preview) > 256 {
		preview = preview[:256]
	}
	return fmt.Sprintf("content-length=%s approx-items=%d body-preview=%s", contentLength, itemCount, preview)
}

// CallApi calls the API with the specified HTTP verb, URL, payload, user ID, and password.
//
// It returns a pointer to http.Response and an error.
func CallApi(verb string, url string, payload string, userId string, password string) ([]byte, *http.Response, error) {
	client := getHTTPClient()

	bodyReader := bytes.NewReader([]byte(payload))
	req, err := http.NewRequest(verb, url, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Add("Accept-Encoding", "identity")
	// cache control
	if os.Getenv("API_NOCACHE") == "1" {
		req.Header.Add("Cache-Control", "no-cache")
	}

	// if credentials defined, pass them
	if userId != "" {
		req.SetBasicAuth(userId, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		fmt.Printf("error calling %s: %s", url, err.Error())
		return nil, resp, err
	}
	defer resp.Body.Close()

	limited := &io.LimitedReader{R: resp.Body, N: maxResponseBodySize + 1}
	resBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, resp, fmt.Errorf("error calling %s: ReadAll body: %s, response.Content-Length: %d, response.Transfer-Encoding: %s, HTTP Version: %s (Major: %d, Minor: %d)", url, err.Error(), resp.ContentLength, resp.Header.Get("Transfer-Encoding"), resp.Proto, resp.ProtoMajor, resp.ProtoMinor)
	}
	if limited.N == 0 {
		return nil, resp, fmt.Errorf("error calling %s: response body exceeded %d bytes limit: %s", url, maxResponseBodySize, oversizedResponseDiag(resp, resBytes))
	}

	if resp.StatusCode >= 400 {
		return resBytes, resp, fmt.Errorf("error calling %s: statusCode: %d, body: %s", url, resp.StatusCode, resBytes)
	}

	return resBytes, resp, nil
}

// CallApiWithCtx calls the API with the specified HTTP verb, URL, payload, user ID, and password,
// with context support for cancellation and timeout.
//
// It returns a pointer to http.Response and an error.
func CallApiWithCtx(ctx context.Context, verb string, url string, payload string, userId string, password string) ([]byte, *http.Response, error) {
	client := getHTTPClient()

	bodyReader := bytes.NewReader([]byte(payload))
	req, err := http.NewRequestWithContext(ctx, verb, url, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Add("Accept-Encoding", "identity")
	// cache control
	if os.Getenv("API_NOCACHE") == "1" {
		req.Header.Add("Cache-Control", "no-cache")
	}

	// if credentials defined, pass them
	if userId != "" {
		req.SetBasicAuth(userId, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		fmt.Printf("error calling %s: %s", url, err.Error())
		return nil, resp, err
	}
	defer resp.Body.Close()

	limited := &io.LimitedReader{R: resp.Body, N: maxResponseBodySize + 1}
	resBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, resp, fmt.Errorf("error calling %s: ReadAll body: %s, response.Content-Length: %d, response.Transfer-Encoding: %s, HTTP Version: %s (Major: %d, Minor: %d)", url, err.Error(), resp.ContentLength, resp.Header.Get("Transfer-Encoding"), resp.Proto, resp.ProtoMajor, resp.ProtoMinor)
	}
	if limited.N == 0 {
		return nil, resp, fmt.Errorf("error calling %s: response body exceeded %d bytes limit: %s", url, maxResponseBodySize, oversizedResponseDiag(resp, resBytes))
	}

	if resp.StatusCode >= 400 {
		return resBytes, resp, fmt.Errorf("error calling %s: statusCode: %d, body: %s", url, resp.StatusCode, resBytes)
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
	if os.Getenv("API_USERID") == "" {
		return fmt.Errorf("missing API_USERID environment variable, it must contain an API Gateway user id authorized on the endpoint you're trying to call")
	}
	if os.Getenv("API_USERPWD") == "" {
		return fmt.Errorf("missing API_USERPWD environment variable, it must contain the password of the API_USERID authorized on the endpoint you're trying to call")
	}
	return nil
}
