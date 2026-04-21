package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetAssets() ([]models.Asset, error) {
	return repositories.GetAssets()
}
