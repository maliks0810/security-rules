package services

import (
	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetSecurityExceptions(aladdinID string) ([]models.SecurityException, error) {
	return repositories.GetSecurityExceptions(aladdinID)
}

func InsertSecurityExceptions(exceptions []models.SecurityException) error {
	if err := repositories.InsertSecurityExceptions(exceptions); err != nil {
		return err
	}
	events.Publish(events.Event{
		Type:    "security_exception.inserted",
		Payload: exceptions,
	})
	return nil
}
