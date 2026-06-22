package models

// Rule represents one RULE_CATALOG row returned by GET_RULES. The
// RULE_COMMAND is the catalog's RULE_CATALOG_SOURCE SQL; when ExecuteRule
// runs it, the result set is expected to include a RULE_ID column per row
// identifying which underlying rule produced that row.
type Rule struct {
	RuleCatalogID   int    `json:"rule_catalog_id"`
	RuleCatalogName string `json:"rule_catalog_name"`
	RuleCommand     string `json:"rule_command"`
	Environment     string `json:"environment"`
}
