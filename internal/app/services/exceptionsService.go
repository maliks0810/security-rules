package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetExceptionTypes() ([]string, error) {
	return repositories.GetExceptionTypes()
}

func GetExceptionStatus() ([]string, error) {
	return repositories.GetExceptionStatus()
}

func GetSeverityTypes() ([]string, error) {
	return repositories.GetSeverityTypes()
}

func GetPriorityTypes() ([]string, error) {
	return repositories.GetPriorityTypes()
}

func GetExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern string) ([]models.Exception, error) {
	return repositories.GetExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern)
}

func InsertExceptions(exceptions []models.Exception) error {
	return repositories.InsertExceptions(exceptions)
}

func UpdateExceptions(exceptions []models.Exception) error {
	return repositories.UpdateExceptions(exceptions)
}

func UpdateExceptionStatus(assetID string, ruleID int, complete bool) (int, error) {
	return repositories.UpdateExceptionStatus(assetID, ruleID, complete)
}

func UpdateAssignTo(assetID, assignTo string) (int, error) {
	return repositories.UpdateAssignTo(assetID, assignTo)
}
