package notifier_test

import (
	"os"
	"strings"
	"testing"

	"github.com/epfl-si/go-toolbox/notifier"
	"github.com/stretchr/testify/assert"
)

func TestNotifyNew(t *testing.T) {
	args := map[string]string{
		"type":   "test",
		"persid": "123456",
		"unitid": "14290",
	}

	// test if config is not provided
	err := notifier.NotifyNew(args)
	assert.Equal(t, true, strings.Contains(err.Error(), "missing NOTIFIER_PWD or NOTIFIER_URL environment variable"))

	// set config
	os.Setenv("NOTIFIER_URL", "https://notify-dev.epfl.ch")
	os.Setenv("NOTIFIER_PWD", "secret")
	err = notifier.NotifyNew(args)
	assert.Equal(t, true, strings.Contains(err.Error(), "StatusCode is invalid: 401"))
}
