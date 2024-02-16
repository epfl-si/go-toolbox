package misc

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
)

func CallApi(verb string, url string, payload string, userId string, password string) (*http.Response, error) {
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
		fmt.Printf("Error calling %s: %s", url, err.Error())
		return nil, err
	}

	return resp, nil
}
