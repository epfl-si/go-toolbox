package api

import (
	"time"
)

type Authorization struct {
	Type             string     `json:"type"`
	Attribution      string     `json:"attribution"`
	AuthId           int        `json:"authid"`
	PersId           int        `json:"persid"`
	Person           *Person    `json:"person,omitempty"`
	ResourceId       string     `json:"resourceid"`
	Resource         *Resource  `json:"resource,omitempty"`
	AccredUnitId     int        `json:"accredunitid"`
	Accred           *Accred    `json:"accred,omitempty"`
	Value            string     `json:"value"`
	EndDate          *time.Time `json:"enddate"`
	State            string     `json:"state"`
	Status           string     `json:"status"`
	WorkflowId       int        `json:"workflowid"`
	LabelFr          string     `json:"labelfr"`
	LabelEn          string     `json:"labelen"`
	Name             string     `json:"name"`
	ReasonType       string     `json:"reasontype,omitempty"`
	ReasonId         string     `json:"reasonid,omitempty"`
	ReasonResourceId string     `json:"reasonresourceid,omitempty"`
	ReasonHolderId   string     `json:"reasonholderid,omitempty"`
}
