package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetExceptionTypes() ([]string, error) {
	return repositories.GetExceptionTypes()
}

func GetExceptionState() ([]string, error) {
	return repositories.GetExceptionState()
}

func GetExceptionStatus() ([]string, error) {
	return repositories.GetExceptionStatus()
}

func UpdateExceptionStatus(exceptionID int64, statusName string) (int, error) {
	return repositories.UpdateExceptionStatus(exceptionID, statusName)
}

func UpdateExceptionComments(exceptionID int64, comments string) (int, error) {
	return repositories.UpdateExceptionComments(exceptionID, comments)
}

func GetSeverityTypes() ([]string, error) {
	return repositories.GetSeverityTypes()
}

func GetPriorityTypes() ([]string, error) {
	return repositories.GetPriorityTypes()
}

func GetExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern string) ([]models.Exception, error) {
	return repositories.GetExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern)
}

func InsertExceptions(exceptions []models.Exception) error {
	return repositories.InsertExceptions(exceptions)
}

func UpdateExceptions(exceptions []models.Exception) error {
	return repositories.UpdateExceptions(exceptions)
}

func UpdateExceptionState(assetID string, ruleID int, complete bool) (int, error) {
	return repositories.UpdateExceptionState(assetID, ruleID, complete)
}

func UpdateAssignTo(assetID, assignTo string) (int, error) {
	return repositories.UpdateAssignTo(assetID, assignTo)
}
