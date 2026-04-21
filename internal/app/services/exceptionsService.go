package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetSecurityExceptions(aladdinID string) ([]models.SecurityException, error) {
	return repositories.GetSecurityExceptions(aladdinID)
}
