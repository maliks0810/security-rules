package models

// ExecuteRulesRequest is the POST body for /executeRules. Bundles the
// three primary scope / behavior knobs the endpoint used to read from
// query string. Params carries the optional ${NAME} placeholder
// substitutions the RULE_CATALOG_SOURCE strings can reference
// (previously the param_NAME=VALUE query args); keys are the
// upper-cased placeholder name without the ${…} wrapper.
type ExecuteRulesRequest struct {
	// Filter value. When RuleType is CATALOG or RULE it matches
	// RULE_CATALOG.NAME (or RULE.RULE_NAME under RULE); under GROUP it
	// matches RULE_GROUP.NAME. Empty or "All" runs every catalog.
	RuleName string `json:"rule_name" example:"Security Master"`
	// One of CATALOG | GROUP | RULE. Empty is equivalent to CATALOG.
	RuleType string `json:"rule_type" example:"GROUP" enums:"CATALOG,GROUP,RULE"`
	// 'Y' or 'N' — substituted into any ${IS_REFRESH} placeholder in
	// the RULE_CATALOG_SOURCE. Defaults to 'Y' when empty.
	IsRefresh string `json:"is_refresh" example:"Y" enums:"Y,N"`
	// Extra ${NAME} placeholder substitutions keyed by placeholder name
	// (upper-cased, no ${…}). Optional. Empty values become SQL NULL.
	Params map[string]string `json:"params,omitempty"`
}
