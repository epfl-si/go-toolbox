package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetAccred: get a accred
//
// Parameters:
// - accredId string: the <sciper>:<unitid> of the accred
//
// Return type(s):
// - *api.Accred: the accred
// - int: response http status code
// - error: any error encountered
func GetAccred(accredId string) (*api.Accred, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/accreds/%s", accredId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetAccred: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.Accred
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetAccred: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type AccredsResponse struct {
	Accreds []*api.Accred `json:"accreds"`
	Count   int64         `json:"count"`
}

// GetAccreds retrieves accreditations for the given persons and unit IDs.
//
// Parameters:
// - persIds string: the person IDs (scipers separated by a comma)
// - unitIds string: the unit IDs (unit IDs separated by a comma)
//
// Return type(s):
// - []*api.Accred: slice of accreditations
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetAccreds(persIds string, unitIds string) ([]*api.Accred, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/accreds?persid=%s&unitid=%s&alldata=1", persIds, unitIds), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetAccreds: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities AccredsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetAccreds: Unmarshal: %s", err.Error())
	}

	return entities.Accreds, entities.Count, res.StatusCode, nil
}

// GetAccredsFromUrl: retrieves accreditations from the given URL
//
// Parameter(s):
// - url string: the URL to retrieve accreditations from
//
// Return type(s):
// - []*api.Accred: slice of accreditations
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetAccredsFromUrl(url string) ([]*api.Accred, int64, int, error) {
	resBytes, res, err := CallApi("GET", url, "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetAccredsFromUrl: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities AccredsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetAccredsFromUrl: Unmarshal: %s", err.Error())
	}

	return entities.Accreds, entities.Count, res.StatusCode, nil
}
