package regexp

import (
	"regexp"
)

var regexpPersid *regexp.Regexp
var regexpService *regexp.Regexp
var regexpGuest *regexp.Regexp
var regexpGroup *regexp.Regexp

func init() {
	regexpPersid = regexp.MustCompile(`^\d{6}$`)
	regexpService = regexp.MustCompile(`^M\d{5}$`)
	regexpGuest = regexp.MustCompile(`^G\d{5}$`)
	regexpGroup = regexp.MustCompile(`^S\d{5}$`)
}

// IsPersId reports whether the 're' value corresponds to a person's sciper
func IsPersId(re string) bool {
	return regexpPersid.Match([]byte(re))
}

// IsService reports whether the 're' value corresponds to a service ID
func IsService(re string) bool {
	return regexpService.Match([]byte(re))
}

// IsGuest reports whether the 're' value corresponds to a guest ID
func IsGuest(re string) bool {
	return regexpGuest.Match([]byte(re))
}

// IsGroup reports whether the 're' value corresponds to a group ID
func IsGroup(re string) bool {
	return regexpGroup.Match([]byte(re))
}
