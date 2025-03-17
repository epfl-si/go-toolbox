package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetUnit: retrieves a unit by its ID or name
//
// Parameters:
// - unitId string: the ID or name of the unit to retrieve
//
// Return type(s):
// - *api.Unit: the unit
// - int: response http status code
// - error: any error encountered
func GetUnit(unitId string) (*api.Unit, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/units/%s", unitId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetUnit: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.Unit
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetUnit: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type UnitsResponse struct {
	Units []*api.Unit `json:"units"`
	Count int64       `json:"count"`
}

// GetUnits: retrieves units
//
// Parameters:
// - query string: the query to search
//
// Return type(s):
// - []*api.Unit: the matching units
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetUnits(query string) ([]*api.Unit, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/units?query=%s", query), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetUnits: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities UnitsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetUnits: Unmarshal: %s", err.Error())
	}

	return entities.Units, entities.Count, res.StatusCode, nil
}

// GetUnitsByIds: retrieves units
//
// Parameters:
// - ids string: comma separated list of unit ids to retrieve
//
// Return type(s):
// - []*api.Unit: the matching units
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetUnitsByIds(ids string) ([]*api.Unit, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("POST", os.Getenv("API_GATEWAY_URL")+"/v1/getter", `{"endpoint":"/v1/units", "params": {"ids":"`+ids+`"}}`, os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetUnitsByIds: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities UnitsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetUnitsByIds: Unmarshal: %s", err.Error())
	}

	return entities.Units, entities.Count, res.StatusCode, nil
}

// GetFund: retrieves a fund by its ID
//
// Parameters:
// - id string: the ID of the fund to retrieve
//
// Return type(s):
// - *api.Fund: the fund
// - int: response http status code
// - error: any error encountered
func GetFund(id string) (*api.Fund, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/funds/%s", id), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetFund: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.Fund
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetFund: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type FundsResponse struct {
	Funds []*api.Fund `json:"funds"`
	Count int64       `json:"count"`
}

// GetFunds: retrieves funds
//
// Parameters:
// - label string: search string on fund label
// - unitids: comma separated list of unit IDs
// - cfs: comma separated list of unit CFs
//
// Return type(s):
// - []*api.Fund: the matching funds
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetFunds(label, unitIds, cfs string) ([]*api.Fund, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/funds?label=%s&unitids=%s&cfs=%s", label, unitIds, cfs), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetFunds: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities FundsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetFunds: Unmarshal: %s", err.Error())
	}

	return entities.Funds, entities.Count, res.StatusCode, nil
}

// GetFundsByIds: retrieves funds
//
// Parameters:
// - ids string: comma separated list of funds ids to retrieve
//
// Return type(s):
// - []*api.Fund: the matching funds
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetFundsByIds(ids string) ([]*api.Fund, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("POST", os.Getenv("API_GATEWAY_URL")+"/v1/getter", `{"endpoint":"/v1/funds", "params": {"ids":"`+ids+`"}}`, os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetFundsByIds: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities FundsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetFundsByIds: Unmarshal: %s", err.Error())
	}

	return entities.Funds, entities.Count, res.StatusCode, nil
}

type UnitTypesResponse struct {
	UnitTypes []*api.UnitType `json:"unittypes"`
}

// GetUnitTypes: retrieves unit types
//
// Return type(s):
// - []*api.UnitType: the matching units
// - int: response http status code
// - error: any error encountered
func GetUnitTypes(query string) ([]*api.UnitType, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	resBytes, res, err := CallApi("GET", os.Getenv("API_GATEWAY_URL")+"/v1/unittypes", "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetUnitTypes: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities UnitTypesResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetUnitTypes: Unmarshal: %s", err.Error())
	}

	return entities.UnitTypes, res.StatusCode, nil
}
