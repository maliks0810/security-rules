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

func GetSecurityExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern string) ([]models.SecurityException, error) {
	return repositories.GetSecurityExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern)
}

func GetExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern string) ([]models.Exception, error) {
	return repositories.GetExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern)
}

func InsertSecurityExceptions(exceptions []models.SecurityException) error {
	return repositories.InsertSecurityExceptions(exceptions)
}

func InsertExceptions(exceptions []models.Exception) error {
	return repositories.InsertExceptions(exceptions)
}

func UpdateSecurityException(e models.SecurityException) error {
	return repositories.UpdateSecurityException(e)
}

func UpdateExceptions(exceptions []models.Exception) error {
	return repositories.UpdateExceptions(exceptions)
}

func UpdateSecurityExceptionStatus(assetID string, ruleID int) (int, error) {
	return repositories.UpdateSecurityExceptionStatus(assetID, ruleID)
}

func UpdateExceptionStatus(assetID string, ruleID int, complete bool) (int, error) {
	return repositories.UpdateExceptionStatus(assetID, ruleID, complete)
}

func UpdateSecurityAssignTo(assetID, assignTo string) (int, error) {
	return repositories.UpdateSecurityAssignTo(assetID, assignTo)
}

func UpdateAssignTo(assetID, assignTo string) (int, error) {
	return repositories.UpdateAssignTo(assetID, assignTo)
}
