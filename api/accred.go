package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	api_models "github.com/epfl-si/go-toolbox/api/models"
)

// GetAccred: get a accred
//
// Parameters:
// - accredId string: the <sciper>:<unitid> of the accred
//
// Return type(s):
// - *api_models.Accred: the accred
// - int: response http status code
// - error: any error encountered
func GetAccred(accredId string) (*api_models.Accred, int, error) {

	var res *http.Response
	var resBytes []byte
	var err error

	err = checkEnvironment()
	if err != nil {
		log.Fatal(err.Error())
	}

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
	var entity api_models.Accred
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		// if error, try to unmarshall from AccredV0 (which refers to PositionV0 where restricted field is a string)
		var entityV0 api_models.AccredV0
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
	Accreds []*api_models.Accred `json:"accreds"`
	Count   int64                `json:"count"`
}
type AccredsV0Response struct {
	Accreds []*api_models.AccredV0 `json:"accreds"`
	Count   int64                  `json:"count"`
}

// GetAccreds retrieves accreditations for the given persons and unit IDs.
//
// Parameters:
// - persIds string: the person IDs (scipers separated by a comma)
// - unitIds string: the unit IDs (unit IDs separated by a comma)
// - params map[string]string: any other parameter available on /v1/accreds (eg. state=active,inactive)
//
// Return type(s):
// - []*api_models.Accred: slice of accreditations
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetAccreds(persIds string, unitIds string, params map[string]string) ([]*api_models.Accred, int64, int, error) {
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

		entities.Accreds = make([]*api_models.Accred, 0)
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
// - []*api_models.Accred: slice of accreditations
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetAccredsFromUrl(url string) ([]*api_models.Accred, int64, int, error) {
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

func AccredV0ToAccred(accredV0 *api_models.AccredV0) *api_models.Accred {
	accred := &api_models.Accred{
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
		accred.Position = &api_models.Position{
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

// GetAccredPrivateEmails: get all private emails
//
// Parameter(s):
// - persId string: TODO
//
// Return type(s):
// - []api_models.PrivateEmail: all private emails
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetAccredPrivateEmails(persId string) ([]api_models.PrivateEmail, int64, int, error) {

	var res *http.Response
	var resBytes []byte
	var privateEmailsResponse api_models.PrivateEmailsResponse
	var err error

	err = checkEnvironment()
	if err != nil {
		log.Fatal(err.Error())
	}

	url := os.Getenv("API_GATEWAY_URL") + "/v1/accreds/privateemails"

	// TODO PersId handling (but doesn't work with api_models.PrivateEmailsResponse)
	// if persId != "" {
	// 	if !toolbox_regexp.IsPersId(persId) {
	// 		return privateEmailsResponse.PrivateEmails, 0, http.StatusBadRequest, fmt.Errorf("go-toolbox: GetAccredPrivateEmails: InvalidPersid: %s", persId)
	// 	}

	// 	url += "/" + persId
	// }

	resBytes, res, err = CallApi("GET", url, "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return privateEmailsResponse.PrivateEmails, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetAccredPrivateEmails: CallApi: %s", err.Error())
	}

	err = json.Unmarshal(resBytes, &privateEmailsResponse)
	if err != nil {
		return privateEmailsResponse.PrivateEmails, privateEmailsResponse.Count, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetAccredPrivateEmails: Unmarshal: %s", err.Error())
	}

	return privateEmailsResponse.PrivateEmails, privateEmailsResponse.Count, res.StatusCode, nil
}
