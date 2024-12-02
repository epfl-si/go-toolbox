package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetGroup: retrieves a group by its ID or name
//
// Parameters:
// - groupId string: the ID or name of the group to retrieve
//
// Return type(s):
// - *api.Group: the group
// - int: response http status code
// - error: any error encountered
func GetGroup(groupId string) (*api.Group, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/groups/%s", groupId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entity api.Group
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return &entity, res.StatusCode, nil
}

type GroupsResponse struct {
	Groups []*api.Group `json:"groups"`
	Count  int64        `json:"count"`
}

// GetGroups: retrieves groups
//
// Parameters:
// - name string: name of a group
// - owner string: sciper of the owner of a group
// - admin string: sciper of the admin of a group
// - member string: ID of a member of a group
//
// Return type(s):
// - []*api.Group: groups
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetGroups(name, owner, admin, member string) ([]*api.Group, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/groups?name=%s&owner=%s&admin=%s&member=%s", name, owner, admin, member), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entities GroupsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	return entities.Groups, entities.Count, res.StatusCode, nil
}

type GroupPersonsResponse struct {
	Persons []*api.Member `json:"persons"`
}

// GetGroupPersons: retrieves persons in a group by its ID or name
//
// Parameters:
// groupId string - the ID or name of the group to retrieve.
//
// Return type(s):
// - []*api.Member: group's persons
// - int: response http status code
// - error: any error encountered
func GetGroupPersons(groupId string) ([]*api.Member, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/groups/%s/persons", groupId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entities GroupPersonsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return entities.Persons, res.StatusCode, nil
}

type MembersResponse struct {
	Members []*api.Member `json:"members"`
}

// GetGroupMembers: retrieves members of a group by its ID or name
//
// Parameters:
// - groupId string: the ID or name of the group to retrieve
//
// Return type(s):
// - MembersResponse: group's members
// - int: response http status code
// - error: any error encountered
func GetGroupMembers(groupId string) ([]*api.Member, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/groups/%s/members", groupId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entities MembersResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return entities.Members, res.StatusCode, nil
}

// GetGroupAdmins: retrieves admins of a group by its ID or name
//
// Parameters:
// - groupId string: the ID or name of the group to retrieve
//
// Return type(s):
// - []*api.Member: group's admins
// - int: response http status code
// - error: any error encountered
func GetGroupAdmins(groupId string) ([]*api.Member, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/groups/%s/admins", groupId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entities MembersResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return entities.Members, res.StatusCode, nil
}

type MembershipsResponse struct {
	Memberships map[string][]*api.Group `json:"memberships"`
}

// GetMemberships: retrieve all memberships
//
// Return type(s):
// - MembershipsResponse: memberships
// - int: response http status code
// - error: any error encountered
func GetMemberships() (map[string][]*api.Group, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", os.Getenv("API_GATEWAY_URL")+"/v1/groups/memberships", "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// unmarshall response
	var memberships MembershipsResponse
	err = json.Unmarshal(resBytes, &memberships)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return memberships.Memberships, res.StatusCode, nil
}
