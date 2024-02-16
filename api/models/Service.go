package api

import "time"

type Service struct {
	Id          int        `json:"-"`
	AlphanumId  string     `json:"id"`
	Name        string     `json:"name"`
	Label       string     `json:"label"`
	OwnerId     int        `json:"ownerid"`
	Owner       Person     `json:"owner"`
	UnitId      int        `json:"unitid"`
	Unit        Unit       `json:"unit"`
	Description string     `json:"description"`
	Tequila     string     `json:"tequila"`
	LDAP        string     `json:"ldap"`
	AD          string     `json:"ad"`
	Radius      string     `json:"radius"`
	SCO         string     `json:"sco"`
	Uid         int        `json:"uid"`
	Gid         int        `json:"gid"`
	Email       string     `json:"email"`
	Lifetime    int        `json:"lifetime"` // value in months
	CreatedAt   time.Time  `json:"createdat"`
	RemovedAt   *time.Time `json:"removedat"`
	RenewedAt   *time.Time `json:"renewedat"`
	RemindedAt  *time.Time `json:"remindedat"`
}
