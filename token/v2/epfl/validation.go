package epfl

import "fmt"

// ValidateUniqueID validates EPFL UniqueID format
func ValidateUniqueID(uniqueID string) error {
	if uniqueID == "" {
		return nil // Optional field
	}

	if !sciperPattern.MatchString(uniqueID) && !servicePattern.MatchString(uniqueID) {
		return fmt.Errorf("invalid uniqueid: must be 6 digits (SCIPER) or M+5digits (service)")
	}

	return nil
}
