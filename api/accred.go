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

	var res *http.Response
	var resBytes []byte

	if os.Getenv("LOCAL_DATA") != "" {
		res = &http.Response{}
		res.StatusCode = http.StatusOK
		resBytes = []byte(os.Getenv("LOCAL_DATA"))
	} else {
		resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/accreds/%s", accredId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
		if err != nil {
			return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetAccred: CallApi: %s", err.Error())
		}
	}

	// unmarshall response
	var entity api.Accred
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		// if error, try to unmarshall from AccredV0 (which refers to PositionV0 where restricted field is a string)
		var entityV0 api.AccredV0
		err2 := json.Unmarshal(resBytes, &entityV0)
		if err2 != nil {
			// if error, try to unmarshall from AccredV0 (which refers to PositionV0 where restricted field is a string)
			return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetAccred: Unmarshal: %s", err.Error())
		}

		entity = *AccredV0ToAccred(&entityV0)
	}

	return &entity, res.StatusCode, nil
}

type AccredsResponse struct {
	Accreds []*api.Accred `json:"accreds"`
	Count   int64         `json:"count"`
}
type AccredsV0Response struct {
	Accreds []*api.AccredV0 `json:"accreds"`
	Count   int64           `json:"count"`
}

// GetAccreds retrieves accreditations for the given persons and unit IDs.
//
// Parameters:
// - persIds string: the person IDs (scipers separated by a comma)
// - unitIds string: the unit IDs (unit IDs separated by a comma)
// - params map[string]string: any other parameter available on /v1/accreds (eg. state=active,inactive)
//
// Return type(s):
// - []*api.Accred: slice of accreditations
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetAccreds(persIds string, unitIds string, params map[string]string) ([]*api.Accred, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var res *http.Response
	var resBytes []byte

	otherParams := ""
	for key, value := range params {
		otherParams += fmt.Sprintf("&%s=%s", key, value)
	}

	if os.Getenv("LOCAL_DATA") != "" {
		res = &http.Response{}
		res.StatusCode = http.StatusOK
		resBytes = []byte(os.Getenv("LOCAL_DATA"))
	} else {
		resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/accreds?persid=%s&unitid=%s&alldata=1&pagesize=0%s", persIds, unitIds, otherParams), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
		if err != nil {
			return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetAccreds: CallApi: %s", err.Error())
		}
	}

	// unmarshall response
	var entities AccredsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		// if error, try to unmarshall from AccredV0 (which refers to PositionV0 where restricted field is a string)
		var entitiesV0 AccredsV0Response
		err2 := json.Unmarshal(resBytes, &entitiesV0)
		if err2 != nil {
			// if error, try to unmarshall from AccredV0 (which refers to PositionV0 where restricted field is a string)
			return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetAccreds: Unmarshal: %s", err.Error())
		}

		entities.Accreds = make([]*api.Accred, 0)
		for _, accredV0 := range entitiesV0.Accreds {
			accred := AccredV0ToAccred(accredV0)
			entities.Accreds = append(entities.Accreds, accred)
		}
		entities.Count = entitiesV0.Count
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

func AccredV0ToAccred(accredV0 *api.AccredV0) *api.Accred {
	accred := &api.Accred{
		PersId:     accredV0.PersId,
		Person:     accredV0.Person,
		UnitId:     accredV0.UnitId,
		Unit:       accredV0.Unit,
		StatusId:   accredV0.StatusId,
		ClassId:    accredV0.ClassId,
		PositionId: accredV0.PositionId,
		Duration:   accredV0.Duration,
		CreatorId:  accredV0.CreatorId,
		Creator:    accredV0.Creator,
		Comment:    accredV0.Comment,
		Origin:     accredV0.Origin,
		AuthorId:   accredV0.AuthorId,
		Author:     accredV0.Author,
		Revalman:   accredV0.Revalman,
		Order:      accredV0.Order,
		StartDate:  accredV0.StartDate,
		EndDate:    accredV0.EndDate,
		RevalDate:  accredV0.RevalDate,
		CreatedAt:  accredV0.CreatedAt,
		ValidFrom:  accredV0.ValidFrom,
		ValidTo:    accredV0.ValidTo,
		Status:     accredV0.Status,
		Class:      accredV0.Class,
	}

	if accredV0.Position != nil {
		accred.Position = &api.Position{
			Id:             accredV0.PositionId,
			LabelFr:        accredV0.Position.LabelFr,
			LabelEn:        accredV0.Position.LabelEn,
			LabelXX:        accredV0.Position.LabelXX,
			LabelInclusive: accredV0.Position.LabelInclusive,
			Restricted:     accredV0.Position.Restricted == "y",
			ValidFrom:      accredV0.Position.ValidFrom,
			ValidTo:        accredV0.Position.ValidTo,
		}
	}

	return accred
}
