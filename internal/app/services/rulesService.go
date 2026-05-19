package services

import (
	"fmt"

	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
	"securityrules/security-rules/internal/utils/log"
)

func GetRules(processType string) ([]models.Rule, error) {
	return repositories.GetRules(processType)
}

func ExecuteRules(processType, assetID string, idBbGlobal ...string) error {
	rules, err := repositories.GetRules(processType)
	if err != nil {
		return err
	}

	numberOfExceptions := 0
	for _, r := range rules {
		exceptions, err := repositories.ExecuteRule(r.RuleCommand, r.RuleID, assetID, idBbGlobal...)
		if err != nil {
			return err
		}
		numberOfExceptions += len(exceptions)
		if len(exceptions) == 0 {
			continue
		}
		if err := InsertSecurityExceptions(exceptions); err != nil {
			return err
		}
	}

	log.Logger.Info(fmt.Sprintf("rulesService: ExecuteRules - generated %d exceptions for asset %s", numberOfExceptions, assetID))

	if numberOfExceptions > 0 {
		events.Publish(events.Event{
			Type: "security_exception.inserted",
			Payload: map[string]any{
				"asset_id": assetID,
				"count":    numberOfExceptions,
			},
		})
	}

	return nil
}
