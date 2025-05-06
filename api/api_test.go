package api_test

import (
	"os"
	"testing"

	"github.com/epfl-si/go-toolbox/api"
	"github.com/stretchr/testify/assert"
)

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
