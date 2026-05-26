package services

import (
	"securityrules/security-rules/internal/app/repositories"
)

func GetDMUsers() ([]string, error) {
	return repositories.GetDMUsers()
}
