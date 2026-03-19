package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const maxResponseBodySize = 4 * 1024 * 1024 // 4MB — oversized responses are logged but not treated as errors

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
		fmt.Printf("warning: response from %s exceeded %d bytes limit (truncated): %s\n", url, maxResponseBodySize, oversizedResponseDiag(resp, resBytes))
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
		fmt.Printf("warning: response from %s exceeded %d bytes limit (truncated): %s\n", url, maxResponseBodySize, oversizedResponseDiag(resp, resBytes))
	}

	if resp.StatusCode >= 400 {
		return resBytes, resp, fmt.Errorf("error calling %s: statusCode: %d, body: %s", url, resp.StatusCode, resBytes)
	}

	return resBytes, resp, nil
}

// tokenResponse represents the OAuth2 token response for client credentials flow
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// userTokenResponse represents the OAuth2 token response including id_token (authorization code flow)
type userTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// GetToken implements OAuth2 client credentials flow to obtain an access token.
// It makes a POST request to the token endpoint and returns the access token.
// Token expiration and refresh logic should be handled by the caller.
func GetToken(ctx context.Context, tokenURL, clientID, clientSecret, scope string) (string, error) {
	if tokenURL == "" {
		return "", fmt.Errorf("tokenURL must not be empty")
	}
	if clientID == "" {
		return "", fmt.Errorf("clientID must not be empty")
	}
	if clientSecret == "" {
		return "", fmt.Errorf("clientSecret must not be empty")
	}

	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", clientSecret)
	formData.Set("scope", scope)

	client := getHTTPClient()

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	resBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(resBytes))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(resBytes, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// ExchangeAuthCode redeems an OAuth2 authorization code for access and id tokens.
// It uses the authorization_code grant type (server-side redemption).
func ExchangeAuthCode(ctx context.Context, tenantID, clientID, clientSecret, code, redirectURI, scope string) (string, string, error) {
	if tenantID == "" {
		return "", "", fmt.Errorf("tenantID must not be empty")
	}
	if clientID == "" {
		return "", "", fmt.Errorf("clientID must not be empty")
	}
	if clientSecret == "" {
		return "", "", fmt.Errorf("clientSecret must not be empty")
	}
	if code == "" {
		return "", "", fmt.Errorf("code must not be empty")
	}
	if redirectURI == "" {
		return "", "", fmt.Errorf("redirectURI must not be empty")
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", clientSecret)
	formData.Set("code", code)
	formData.Set("redirect_uri", redirectURI)
	formData.Set("scope", scope)

	client := getHTTPClient()

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("failed to create auth code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("auth code exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	resBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read auth code response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return "", "", fmt.Errorf("auth code exchange returned %d: %s", resp.StatusCode, string(resBytes))
	}

	var tokenResp userTokenResponse
	if err := json.Unmarshal(resBytes, &tokenResp); err != nil {
		return "", "", fmt.Errorf("failed to parse auth code response: %w", err)
	}

	return tokenResp.AccessToken, tokenResp.IDToken, nil
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
