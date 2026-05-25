package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetExceptionTypes() ([]string, error) {
	return repositories.GetExceptionTypes()
}

func GetSeverityType() ([]string, error) {
	return repositories.GetSeverityType()
}

func GetPriorityType() ([]string, error) {
	return repositories.GetPriorityType()
}

func GetSecurityExceptions(aladdinID, exceptionType, severity, priority string) ([]models.SecurityException, error) {
	return repositories.GetSecurityExceptions(aladdinID, exceptionType, severity, priority)
}

func InsertSecurityExceptions(exceptions []models.SecurityException) error {
	return repositories.InsertSecurityExceptions(exceptions)
}
