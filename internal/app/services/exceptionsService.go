package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetSecurityExceptions(aladdinID string) ([]models.SecurityException, error) {
	return repositories.GetSecurityExceptions(aladdinID)
}

func InsertSecurityExceptions(exceptions []models.SecurityException) error {
	return repositories.InsertSecurityExceptions(exceptions)
}
