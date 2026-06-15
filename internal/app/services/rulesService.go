package services

import (
	"fmt"

	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
	"securityrules/security-rules/internal/utils/log"
)

func GetRules(processType, ruleCatalog string) ([]models.Rule, error) {
	return repositories.GetRules(processType, ruleCatalog)
}

func GetRuleGroups() ([]string, error) {
	return repositories.GetRuleGroups()
}

func GetRuleCatalogs(ruleGroup string) ([]string, error) {
	return repositories.GetRuleCatalogs(ruleGroup)
}

// ExecuteSecurityRules is the legacy orchestration that writes to
// SECURITY_EXCEPTION via the old SP family. Kept around so we can swap
// flows without losing functionality.
func ExecuteSecurityRules(processType, assetID string, idBbGlobal ...string) error {
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
		exceptions, err := repositories.ExecuteSecurityRule(r.RuleCommand, r.RuleID, r.RuleName, assetID, idBbGlobal...)
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
		n, err := repositories.UpdateSecurityExceptionStatus(assetID, ruleID)
		if err != nil {
			return err
		}
		completed += n
	}

	generated := len(inserts) + len(updates)
	log.Logger.Info(fmt.Sprintf(
		"rulesService: ExecuteSecurityRules - asset %s: generated %d exceptions",
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

// ExecuteRules is the new orchestration that writes to the slim EXCEPTION
// table. Diff key is (RuleID, AssetID), scoped to the rules being run
// across all assets — the rule SQL can produce rows for any asset:
//
//   - (RuleID, AssetID) is in the produced set but not in the snapshot →
//     INSERT a new exception.
//   - (RuleID, AssetID) is in both the snapshot and produced set →
//     TOUCH_EXCEPTION_AUDIT (bumps MODIFIED_DATE / MODIFIED_BY only;
//     status and other fields left intact).
//   - (RuleID, AssetID) is in the snapshot but not in the produced set →
//     UPDATE_EXCEPTION_STATUS (flips Pending to Complete).
func ExecuteRules(processType, assetID string, idBbGlobal ...string) error {
	rules, err := repositories.GetRules(processType, "")
	if err != nil {
		return err
	}

	runRuleIDs := make(map[int]bool, len(rules))
	for _, r := range rules {
		runRuleIDs[r.RuleID] = true
	}

	// Snapshot existing (RuleID, AssetID) pairs across all assets, but
	// scoped to the rules we're about to evaluate. We compare against
	// these to decide insert vs touch vs complete.
	existing, err := repositories.GetExceptions("", "", "", "", "", "", "", "", "", "")
	if err != nil {
		return err
	}
	type ruleAsset struct {
		RuleID  int
		AssetID string
	}
	existingKeys := make(map[ruleAsset]bool)
	for _, x := range existing {
		if runRuleIDs[x.RuleID] {
			existingKeys[ruleAsset{x.RuleID, x.AssetID}] = true
		}
	}

	// Run each rule and split the produced exceptions into inserts (new
	// keys) vs touches (existing keys).
	producedKeys := make(map[ruleAsset]bool)
	var inserts []models.Exception
	var touches []models.Exception
	for _, r := range rules {
		exceptions, err := repositories.ExecuteRule(r.RuleCommand, r.RuleID, r.RuleName, assetID, idBbGlobal...)
		if err != nil {
			return err
		}
		for _, e := range exceptions {
			key := ruleAsset{e.RuleID, e.AssetID}
			if producedKeys[key] {
				continue
			}
			producedKeys[key] = true
			if existingKeys[key] {
				touches = append(touches, e)
			} else {
				inserts = append(inserts, e)
			}
		}
	}

	if len(inserts) > 0 {
		if err := InsertExceptions(inserts); err != nil {
			return err
		}
	}
	for _, e := range touches {
		if _, err := repositories.UpdateExceptionStatus(e.AssetID, e.RuleID, false); err != nil {
			return err
		}
	}

	// Anything that existed before but is no longer produced gets marked
	// Complete (status flips to 4 + audit columns bumped).
	completed := 0
	for k := range existingKeys {
		if producedKeys[k] {
			continue
		}
		n, err := repositories.UpdateExceptionStatus(k.AssetID, k.RuleID, true)
		if err != nil {
			return err
		}
		completed += n
	}

	generated := len(inserts) + len(touches)
	log.Logger.Info(fmt.Sprintf(
		"rulesService: ExecuteRules - asset %s: inserted %d, touched %d, completed %d",
		assetID, len(inserts), len(touches), completed,
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
