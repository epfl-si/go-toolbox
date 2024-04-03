package notifier

import (
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"strings"
)

// Get an i18nzed message (stored in <lang>.json files in assets folder)
func Notify(args map[string]string) error {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport}

	args["app"] = os.Getenv("NOTIFIER_APP")
	args["caller"] = os.Getenv("NOTIFIER_CALLER")
	args["password"] = os.Getenv("NOTIFIER_PWD")

	// build URL
	argsArray := []string{}
	for key, value := range args {
		argsArray = append(argsArray, key+"="+value)
	}
	argsStr := strings.Join(argsArray, "&")

	req, err := http.NewRequest("GET", os.Getenv("NOTIFIER")+"?"+argsStr, nil)
	if err != nil {
		return errors.New("NotifierInvalidRequest")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New("NotifierInvalidResponse")
	}

	return nil
}
