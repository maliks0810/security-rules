package models

type Rule struct {
	RuleID      int    `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	RuleCommand string `json:"rule_command"`
	Environment string `json:"environment"`
}
