package messages

import (
	"fmt"
)

// define const map to contain messages per language
var messages = map[string]map[string]string{
	"InvalidTokenFormat": {
		"fr": "Le format du JWT est invalide",
		"en": "Invalid token format",
	},
	"UnableToDecodeBase64": {
		"fr": "Impossible de décoder le base64",
		"en": "Unable to decode base64",
	},
	"UnableToParseToken": {
		"fr": "Impossible de parser le token",
		"en": "Unable to parse token",
	},
}

// Get an i18nzed message (stored in <lang>.json files in assets folder)
func GetMessage(lang string, msg string, values ...string) string {
	localization := messages[msg][lang]

	//fmt.Println("localization=" + localization)
	if len(values) > 0 {
		for i := range values {
			localization = fmt.Sprintf(localization, values[i])
		}
	}

	return localization
}
