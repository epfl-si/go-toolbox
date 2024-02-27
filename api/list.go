package api

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetList: retrieves a list by its ID or name
//
// Parameters:
// - listId string: the ID or name of the list to retrieve.
//
// Return type(s):
// - *api.List: the list
// - int: response http status code
// - error: any error encountered
func GetList(listId string) (*api.List, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/lists/%s", listId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	// unmarshall response
	var entity api.List
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, 0, err
	}

	return &entity, res.StatusCode, nil
}
