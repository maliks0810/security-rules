package services

import (
	"fmt"

	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
	"securityrules/security-rules/internal/utils/log"
)

func GetRules(processType, ruleType string) ([]models.Rule, error) {
	return repositories.GetRules(processType, ruleType)
}

func GetRuleGroups() ([]string, error) {
	return repositories.GetRuleGroups()
}

func GetRuleTypes(ruleGroup string) ([]string, error) {
	return repositories.GetRuleTypes(ruleGroup)
}

func ExecuteRules(processType, assetID string, idBbGlobal ...string) error {
	rules, err := repositories.GetRules(processType, "")
	if err != nil {
		return err
	}

	// Snapshot the existing exceptions for this asset so we can diff the
	// rule-run results against them in memory. We only keep RULE_ID tuples
	// (the grain of SECURITY_EXCEPTION is (ASSET_ID, RULE_ID)).
	existing, err := repositories.GetSecurityExceptions(assetID, "", "", "", "", "", "", "", "", "")
	if err != nil {
		return err
	}
	existingRuleIDs := make(map[int]bool, len(existing))
	for _, x := range existing {
		existingRuleIDs[x.RuleID] = true
	}

	// Classify each new exception as INSERT (new rule_id) or UPDATE (existing).
	touched := make(map[int]bool)
	var inserts []models.SecurityException
	var updates []models.SecurityException
	for _, r := range rules {
		exceptions, err := repositories.ExecuteRule(r.RuleCommand, r.RuleID, assetID, idBbGlobal...)
		if err != nil {
			return err
		}
		for _, e := range exceptions {
			if existingRuleIDs[e.RuleID] {
				updates = append(updates, e)
			} else {
				inserts = append(inserts, e)
			}
			touched[e.RuleID] = true
		}
	}

	if len(inserts) > 0 {
		if err := InsertSecurityExceptions(inserts); err != nil {
			return err
		}
	}
	for _, e := range updates {
		if err := repositories.UpdateSecurityException(e); err != nil {
			return err
		}
	}

	// Anything in the original snapshot that the rule run did not touch:
	// mark Complete if still Pending.
	completed := 0
	for ruleID := range existingRuleIDs {
		if touched[ruleID] {
			continue
		}
		n, err := repositories.UpdateExceptionStatus(assetID, ruleID)
		if err != nil {
			return err
		}
		completed += n
	}

	generated := len(inserts) + len(updates)
	log.Logger.Info(fmt.Sprintf(
		"rulesService: ExecuteRules - asset %s: generated %d exceptions",
		assetID, generated,
	))

	if generated > 0 || completed > 0 {
		events.Publish(events.Event{
			Type: "security_exception.inserted",
			Payload: map[string]any{
				"asset_id": assetID,
				"count":    generated,
			},
		})
	}

	return nil
}
