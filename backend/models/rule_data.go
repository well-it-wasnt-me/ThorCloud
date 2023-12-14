package models

import (
	"time"

	"github.com/lib/pq"
)

type RuleData struct {
	UID            string         `json:"uid" gorm:"primaryKey"`
	Description    string         `json:"description"`
	Active         bool           `json:"active"`
	LastRun        time.Time      `json:"last_run"`
	Severity       string         `json:"severity"`
	RuleCategory   string         `json:"rule_category"`
	RiskCategories pq.StringArray `json:"risk_categories" gorm:"type:text[]"`
	CvssScore      float64        `json:"cvss_score,omitempty"`
	Name           string         `json:"name,omitempty"`
	YamlTemplate   string         `json:"yaml_template,omitempty"`
}
