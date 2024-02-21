package misc

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

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
		fmt.Printf("Error calling %s: %s", url, err.Error())
		return nil, err
	}

	return resp, nil
}

func GetPerson(persId string) (*api.Person, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/persons/%s", persId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	// unmarshall response
	var entity api.Person
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, 0, err
	}

	return &entity, res.StatusCode, nil
}

func GetUnit(unitId string) (*api.Unit, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/units/%s", unitId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	// unmarshall response
	var entity api.Unit
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, 0, err
	}

	return &entity, res.StatusCode, nil
}

// accredId is persId:unitId
func GetAccred(accredId string) (*api.Accred, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/accreds/%s", accredId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	// unmarshall response
	var entity api.Accred
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, 0, err
	}

	return &entity, res.StatusCode, nil
}

type AccredsResponse struct {
	Accreds []*api.Accred `json:"accreds"`
	Count   int64         `json:"count"`
}

func GetAccreds(persIds string, unitIds string) ([]*api.Accred, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/accreds?persid=%s&unitid=%s", persIds, unitIds), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities AccredsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Accreds, entities.Count, res.StatusCode, nil
}

func GetAccredsFromUrl(url string) ([]*api.Accred, int64, int, error) {
	res, err := CallApi("GET", url, "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities AccredsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Accreds, entities.Count, res.StatusCode, nil
}

type AuthorizationsResponse struct {
	Authorizations []*api.Authorization `json:"authorizations"`
	Count          int64                `json:"count"`
}

func GetAuthorizations(persIds string, resIds string, authType string, authIds string) ([]*api.Authorization, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/authorizations?persid=%s&resid=%s&type=%s&authid=%s", persIds, resIds, authType, authIds), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities AuthorizationsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Authorizations, entities.Count, res.StatusCode, nil
}

func GetAuthorizationsFromUrl(url string) ([]*api.Authorization, int64, int, error) {
	res, err := CallApi("GET", url, "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities AuthorizationsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Authorizations, entities.Count, res.StatusCode, nil
}

func checkEnvironment() error {
	if os.Getenv("API_GATEWAY_URL") == "" {
		return fmt.Errorf("missing API_GATEWAY_URL environment variable, possible values are 'https://api-test.epfl.ch', 'https://api-preprod.epfl.ch', 'https://api.epfl.ch'")
	}
	return nil
}
