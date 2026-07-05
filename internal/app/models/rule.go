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

// RuleName carries a single RULE row's name and friendly description as
// returned by GET_RULE_NAMES — used by the rule tree view (it renders
// description when non-empty, falls back to name) and to populate the
// Exceptions header subtitle when a specific rule is selected.
type RuleName struct {
	RuleName        string `json:"rule_name"`
	RuleDescription string `json:"rule_description"`
}

// RuleGroup is one row from RULE_GROUP surfaced through SP_GET_RULE_GROUPS.
// FlagStatusVisible drives the "show STATUS filter + column" UI on the
// Exceptions grid; FlagCommentsVisible drives the "show COMMENTS column"
// (editable free-text) — both are opt-in per rule group.
type RuleGroup struct {
	Name                string `json:"name"`
	FlagStatusVisible   bool   `json:"flag_status_visible"`
	FlagCommentsVisible bool   `json:"flag_comments_visible"`
}
