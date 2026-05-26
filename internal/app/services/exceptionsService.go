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

func GetSeverityType() ([]string, error) {
	return repositories.GetSeverityType()
}

func GetPriorityType() ([]string, error) {
	return repositories.GetPriorityType()
}

func GetSecurityExceptions(aladdinID, exceptionType, severity, priority, ruleType, ruleName, ruleGroup, exceptionStatus, assignTo string) ([]models.SecurityException, error) {
	return repositories.GetSecurityExceptions(aladdinID, exceptionType, severity, priority, ruleType, ruleName, ruleGroup, exceptionStatus, assignTo)
}

func InsertSecurityExceptions(exceptions []models.SecurityException) error {
	return repositories.InsertSecurityExceptions(exceptions)
}
