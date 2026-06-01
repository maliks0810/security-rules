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

func GetSecurityExceptions(aladdinID, exceptionType, severity, priority, ruleType, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern string) ([]models.SecurityException, error) {
	return repositories.GetSecurityExceptions(aladdinID, exceptionType, severity, priority, ruleType, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern)
}

func InsertSecurityExceptions(exceptions []models.SecurityException) error {
	return repositories.InsertSecurityExceptions(exceptions)
}

func UpdateSecurityException(e models.SecurityException) error {
	return repositories.UpdateSecurityException(e)
}

func UpdateExceptionStatus(assetID string, ruleID int) (int, error) {
	return repositories.UpdateExceptionStatus(assetID, ruleID)
}

func UpdateAssignTo(assetID, assignTo string) (int, error) {
	return repositories.UpdateAssignTo(assetID, assignTo)
}
