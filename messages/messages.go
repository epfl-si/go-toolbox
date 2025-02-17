package messages

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
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
func GetLocalMessage(lang string, msg string, values ...string) string {
	localization := messages[msg][lang]

	//fmt.Println("localization=" + localization)
	if len(values) > 0 {
		for i := range values {
			localization = fmt.Sprintf(localization, values[i])
		}
	}

	return localization
}

func GetMessage(lang string, msg string, values ...string) string {
	bundle := i18n.NewBundle(language.French)
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	// load translation files
	_, err := bundle.LoadMessageFile("i18n/fr.toml")
	if err != nil {
		fmt.Println("Could not load fr.toml file: " + err.Error())
	}
	_, err2 := bundle.LoadMessageFile("i18n/en.toml")
	if err2 != nil {
		fmt.Println("Could not load en.toml file: " + err.Error())
	}

	localizer := i18n.NewLocalizer(bundle, lang)

	localizeConfig := i18n.LocalizeConfig{
		MessageID: msg,
	}
	localization, _ := localizer.Localize(&localizeConfig)

	// fallback to initial message if no translation found
	if localization == "" {
		localization = msg
	}

	//fmt.Println("localization=" + localization)
	if len(values) > 0 {
		// convert "values" to a "...any"
		newValues := make([]interface{}, len(values))
		for i := range values {
			newValues[i] = values[i]
		}
		localization = fmt.Sprintf(localization, newValues...)
	}

	return localization
}
