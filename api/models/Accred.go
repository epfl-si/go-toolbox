package api

import (
	"time"
)

// Create a model with gorm anotation
type Accred struct {
	PersId     int        `json:"persid"`
	Person     *Person    `json:"person"`
	UnitId     int        `json:"unitid"`
	Unit       *Unit      `json:"unit"`
	StatusId   int        `json:"statusid"`
	ClassId    int        `json:"classid"`
	PositionId int        `json:"positionid"`
	Duration   string     `json:"duration"`
	CreatorId  string     `json:"creatorid"`
	Creator    *Person    `json:"creator"`
	Comment    string     `json:"comment"`
	Origin     string     `json:"origin"`
	AuthorId   string     `json:"authorid"`
	Author     *Person    `json:"author"`
	Revalman   string     `json:"manualreval"`
	Order      int        `json:"order"`
	StartDate  time.Time  `json:"startdate"`
	EndDate    *time.Time `json:"enddate"`
	RevalDate  *time.Time `json:"revalidatedat"`
	CreatedAt  time.Time  `json:"createdat"`
	ValidFrom  time.Time  `json:"-"`
	ValidTo    *time.Time `json:"-"`
	Status     *Status    `json:"status"`
	Class      *Class     `json:"class"`
	Position   *Position  `json:"position"`
}
