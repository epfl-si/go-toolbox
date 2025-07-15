package api

type UPNsResponse struct {
	UPNs  []UserPrincipalName `json:"UPNs"`
	Count int64               `json:"count"`
}
