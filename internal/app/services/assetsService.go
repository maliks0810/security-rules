package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetAssets(exceptionType, severity, priority, ruleCatalog, ruleName, exceptionStatus, assignTo string) ([]models.Asset, error) {
	return repositories.GetAssets(exceptionType, severity, priority, ruleCatalog, ruleName, exceptionStatus, assignTo)
}
