package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetDMUsers() ([]models.DMUser, error) {
	return repositories.GetDMUsers()
}

func GetDMRole(user string) (string, error) {
	return repositories.GetDMRole(user)
}

func GetRuleGroupsForUser(user string) ([]models.RuleGroup, error) {
	return repositories.GetRuleGroupsForUser(user)
}

func UpdateUserPreferences(user, ruleGroup, ruleCatalog, columnOrder string) (int, error) {
	return repositories.UpdateUserPreferences(user, ruleGroup, ruleCatalog, columnOrder)
}
