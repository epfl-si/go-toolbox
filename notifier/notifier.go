package notifier

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/epfl-si/go-toolbox/notifier/models"
	"github.com/gofrs/uuid"
)

// Get an i18nzed message (stored in <lang>.json files in assets folder)
func Notify(args map[string]string) error {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport}

	if os.Getenv("NOTIFIER_APP") == "" || os.Getenv("NOTIFIER_CALLER") == "" || os.Getenv("NOTIFIER_PWD") == "" || os.Getenv("NOTIFIER") == "" {
		return errors.New("NotifierEmptyEnvironmentVariables")
	}
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

func NotifyNew(args map[string]string) error {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport}

	if os.Getenv("NOTIFIER_PWD") == "" || os.Getenv("NOTIFIER_URL") == "" {
		return errors.New("go-toolbox: NotifyNew: missing NOTIFIER_PWD or NOTIFIER_URL environment variable")
	}

	eventType := args["type"]
	if eventType == "" {
		return errors.New("go-toolbox: NotifyNew: missing 'type' argument")
	}
	// remove 'type' key from args
	delete(args, "type")

	// build event
	uuid, _ := uuid.NewV4()
	event := models.Event{
		UUID:      fmt.Sprintf("%v", uuid),
		EventType: eventType,
		Args:      args,
		Status:    0,
	}
	// marshal event
	marshalledEvent, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("go-toolbox: NotifyNew: Marshall failure: %s", err.Error())
	}

	//fmt.Printf("--------- %s\n", string(marshalledEvent))
	req, err := http.NewRequest("POST", os.Getenv("NOTIFIER_URL"), strings.NewReader(string(marshalledEvent)))
	if err != nil {
		return fmt.Errorf("go-toolbox: NotifyNew: NewRequest failure: %s", err.Error())
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	// pass credentials
	req.Header.Set("X-Krakend-Secret", os.Getenv("NOTIFIER_PWD"))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("go-toolbox: NotifyNew: Do failure: %s", err.Error())
	}
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("go-toolbox: NotifyNew: StatusCode is invalid: %d", resp.StatusCode)
	}

	return nil
}
