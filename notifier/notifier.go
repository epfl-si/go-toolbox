package notifier

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/epfl-si/go-toolbox/api"
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
	if os.Getenv("NOTIFIER_USERID") == "" || os.Getenv("NOTIFIER_USERPWD") == "" || os.Getenv("NOTIFIER_URL") == "" || os.Getenv("NOTIFIER_APP") == "" {
		return errors.New("go-toolbox: NotifyNew: missing NOTIFIER_USERID, NOTIFIER_USERPWD, NOTIFIER_APP or NOTIFIER_URL environment variable")
	}

	eventType := args["type"]
	if eventType == "" {
		return errors.New("go-toolbox: NotifyNew: missing 'type' argument")
	}
	requester := args["requester"]
	if eventType == "" {
		return errors.New("go-toolbox: NotifyNew: missing 'requester' argument")
	}
	// remove 'type' and 'requester' keys from args
	delete(args, "type")
	delete(args, "requester")

	// build event
	uuid, _ := uuid.NewV4()
	event := models.Event{
		UUID:      fmt.Sprintf("%v", uuid),
		EventType: eventType,
		Requester: requester,
		App:       os.Getenv("NOTIFIER_APP"),
		Args:      args,
		Status:    0,
	}
	// marshal event
	marshalledEvent, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("go-toolbox: NotifyNew: Marshall failure: %s", err.Error())
	}

	resBytes, res, err := api.CallApi("POST", os.Getenv("NOTIFIER_URL"), string(marshalledEvent), os.Getenv("NOTIFIER_USERID"), os.Getenv("NOTIFIER_USERID"))
	if err != nil {
		return fmt.Errorf("go-toolbox: NotifyNew: CallApi failure: %s", err.Error())
	}
	if res.StatusCode >= 400 {
		return fmt.Errorf("go-toolbox: NotifyNew: StatusCode is invalid: %d, response: %s", res.StatusCode, string(resBytes))
	}

	return nil
}
