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
	// RevertToNewCriteria is the RULE_CATALOG.REVERT_TO_NEW_CRITERIA
	// column value: the name of a stored procedure that ExecuteRules
	// invokes after the archive/insert/inherit steps to re-evaluate the
	// catalog's non-New rows and flip any that no longer meet the
	// exception criteria back to STATUS_ID = 1 ('New'). Empty when the
	// catalog opted out of the revert workflow.
	RevertToNewCriteria string `json:"revert_to_new_criteria,omitempty"`
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
// Flags drive opt-in UI on the Exceptions grid:
//   - FlagStatusVisible   → STATUS filter panel + column
//   - FlagCommentsVisible → editable COMMENTS column
//   - FlagSuppressDate    → editable SUPPRESS_DATE column
//   - FlagAssignToVisible → editable ASSIGN TO column (per-row dropdown
//     of DM_USER values, distinct from the Assets grid's per-asset one).
type RuleGroup struct {
	Name                string `json:"name"`
	FlagStatusVisible   bool   `json:"flag_status_visible"`
	FlagCommentsVisible bool   `json:"flag_comments_visible"`
	FlagSuppressDate    bool   `json:"flag_suppress_date"`
	FlagAssignToVisible bool   `json:"flag_assign_to_visible"`
}
