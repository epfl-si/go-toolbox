package api_test

import (
	"os"
	"testing"

	"github.com/epfl-si/go-toolbox/api"
	"github.com/stretchr/testify/assert"
)

func TestGetAccred(t *testing.T) {
	setEnv()

	// read data from upper "assets" folder
	// legacy structure
	b, err := os.ReadFile("../assets/get_accredV0.json")
	assert.NoError(t, err)
	os.Setenv("LOCAL_DATA", string(b))
	// we don't care of the passed param, it's overrided by content of get_accred.json
	accred, _, err := api.GetAccred("123456:123456")
	assert.NoError(t, err)
	assert.Equal(t, 268229, accred.PersId)
	assert.Equal(t, 14290, accred.UnitId)

	// new structure
	b, err = os.ReadFile("../assets/get_accred.json")
	assert.NoError(t, err)
	os.Setenv("LOCAL_DATA", string(b))
	// we don't care of the passed param, it's overrided by content of get_accred.json
	accred, _, err = api.GetAccred("123456:123456")
	assert.NoError(t, err)
	assert.Equal(t, 268229, accred.PersId)
	assert.Equal(t, 14290, accred.UnitId)
}

func TestGetAccreds(t *testing.T) {
	setEnv()

	// read data from upper "assets" folder
	// legacy structure
	b, err := os.ReadFile("../assets/get_accredsV0.json")
	assert.NoError(t, err)
	os.Setenv("LOCAL_DATA", string(b))
	// we don't care of the passed param, it's overrided by content of get_accred.json
	accreds, _, _, err := api.GetAccreds("", "")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(accreds))
	assert.Equal(t, 268229, accreds[0].PersId)
	assert.Equal(t, 14290, accreds[0].UnitId)

	// new structure
	b, err = os.ReadFile("../assets/get_accreds.json")
	assert.NoError(t, err)
	os.Setenv("LOCAL_DATA", string(b))
	// we don't care of the passed param, it's overrided by content of get_accred.json
	accreds, _, _, err = api.GetAccreds("", "")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(accreds))
	assert.Equal(t, 268229, accreds[0].PersId)
	assert.Equal(t, 14290, accreds[0].UnitId)
}

func TestGetGuests(t *testing.T) {
	setEnv()

	guests, _, _, err := api.GetGuests("", "")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(guests))

	guests, _, _, err = api.GetGuests("", "disabled")
	assert.NoError(t, err)
	assert.Equal(t, 0, len(guests))

	guests, _, _, err = api.GetGuests("doe", "")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(guests))
	assert.Equal(t, "Doe John", guests[0].Display)
}

func TestGetGuestsByIds(t *testing.T) {
	setEnv()

	guests, _, _, err := api.GetGuestsByIds("G00001")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(guests))
}

func setEnv() {
	os.Setenv("API_GATEWAY_URL", "http://localhost:8080")
	os.Setenv("API_USERID", "M01234")
	os.Setenv("API_USERPWD", "azerty")
}
