package onboarding

const (
	STAFF                     = "Staff"
	STUDENT                   = "Student"
	EXTERNAL                  = "External"
	SERVICE                   = "Service"
	AUDIT                     = "AUDIT"
	AUDIT_EDOC                = "AUDIT_EDOC"
	EFC                       = "EFC"
	EDOC                      = "EDOC"
	CDOC                      = "CDOC"
	BAMA                      = "BAMA"
	BAMA_MOBILITE             = "BAMA_MOBILITE"
	BAMA_MOBILITE_AVEC_PROJET = "BAMA_MOBILITE_AVEC_PROJET"
	BAMA_MOBILITE_SANS_PROJET = "BAMA_MOBILITE_SANS_PROJET"
	BAMA_MOBILITE_MNIS_SUISSE = "BAMA_MOBILITE_MNIS_SUISSE"
)

var AllowedStudentTypes = map[string]bool{
	STUDENT:                   true,
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
