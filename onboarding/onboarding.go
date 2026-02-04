package onboarding

import "time"

const (
	AUDIT                     = "AUDIT"
	AUDIT_EDOC                = "AUDIT_EDOC"
	BAMA                      = "BAMA"
	BAMA_MOBILITE             = "BAMA_MOBILITE"
	BAMA_MOBILITE_AVEC_PROJET = "BAMA_MOBILITE_AVEC_PROJET"
	BAMA_MOBILITE_MNIS_SUISSE = "BAMA_MOBILITE_MNIS_SUISSE"
	BAMA_MOBILITE_SANS_PROJET = "BAMA_MOBILITE_SANS_PROJET"
	CDOC                      = "CDOC"
	EDOC                      = "EDOC"
	EFC                       = "EFC"
	EXTERNAL                  = "External"
	FBM                       = "FBM"
	MAX_ONBOARDING_FOR_EDOC   = -61 * 24 * time.Hour  // 2 months
	MAX_ONBOARDING_FOR_EFC    = -15 * 24 * time.Hour  // 15 days
	MAX_ONBOARDING_FOR_STAFF  = -3 * 24 * time.Hour   // 3 days
	MAX_ONBOARDING_PERIOD     = -120 * 24 * time.Hour // For anyone : max onboarding 4 months before
	PROFESSOR                 = "Professor"
	SERVICE                   = "Service"
	STAFF                     = "Staff"
	STUDENT                   = "Student"
)

var AllowedStudentTypes = map[string]bool{
	AUDIT_EDOC:                true,
	AUDIT:                     true,
	BAMA_MOBILITE_AVEC_PROJET: true,
	BAMA_MOBILITE_MNIS_SUISSE: true,
	BAMA_MOBILITE_SANS_PROJET: true,
	BAMA_MOBILITE:             true,
	BAMA:                      true,
	CDOC:                      true,
	EDOC:                      true,
	EFC:                       true,
	STUDENT:                   true,
}

var AllowedOnboardingTypes = map[string]bool{
	STAFF:                     true,
	STUDENT:                   true,
	EXTERNAL:                  true,
	AUDIT:                     true,
	AUDIT_EDOC:                true,
	EFC:                       true,
	EDOC:                      true,
	CDOC:                      true,
	BAMA:                      true,
	BAMA_MOBILITE:             true,
	BAMA_MOBILITE_AVEC_PROJET: true,
	BAMA_MOBILITE_SANS_PROJET: true,
	BAMA_MOBILITE_MNIS_SUISSE: true,
}
