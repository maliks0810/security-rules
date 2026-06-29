package services

import (
	"fmt"

	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
	"securityrules/security-rules/internal/utils/log"
)

func GetRules(ruleName, ruleType string) ([]models.Rule, error) {
	return repositories.GetRules(ruleName, ruleType)
}

func GetRuleGroups() ([]string, error) {
	return repositories.GetRuleGroups()
}

func GetRuleCatalogs(ruleGroup string) ([]string, error) {
	return repositories.GetRuleCatalogs(ruleGroup)
}

func GetRuleNames(ruleCatalog string) ([]string, error) {
	return repositories.GetRuleNames(ruleCatalog)
}

// ExecuteRules is the new orchestration that writes to the slim EXCEPTION
// table. GetRules now returns one row per RULE_CATALOG; we run each
// catalog's RULE_CATALOG_SOURCE exactly once and the result rows carry
// their own RULE_ID, so a single query feeds many rules in one shot.
// Diff key is (RuleID, AssetID), built from the produced rule IDs.
//
//   - (RuleID, AssetID) is in the produced set but not in the snapshot →
//     INSERT a new exception.
//   - (RuleID, AssetID) is in both the snapshot and produced set →
//     UPDATE_EXCEPTION (re-flags STATUS_ID to Pending and refreshes
//     EXCEPTION_DATE/TIME, ISSUE_DESCRIPTION, and RESULT_DATA from the
//     re-fired rule's result row).
//   - (RuleID, AssetID) is in the snapshot but not in the produced set →
//     UPDATE_EXCEPTION_STATUS (flips Pending to Complete). Scoped to the
//     rule IDs we actually produced this run, so rules not covered by any
//     catalog source aren't accidentally marked Complete.
func ExecuteRules(ruleName, ruleType, assetID string, idBbGlobal ...string) error {
	catalogs, err := repositories.GetRules(ruleName, ruleType)
	if err != nil {
		return err
	}

	type ruleAsset struct {
		RuleID  int
		AssetID string
	}

	// Run each catalog source once. Each result row carries its own
	// RULE_ID, so collect the produced exceptions and the set of rule
	// IDs that participated this run.
	runRuleIDs := make(map[int]bool)
	producedKeys := make(map[ruleAsset]bool)
	var produced []models.Exception
	for _, c := range catalogs {
		exceptions, err := repositories.ExecuteRule(c.RuleCommand, c.RuleCatalogID, c.RuleCatalogName, assetID, idBbGlobal...)
		if err != nil {
			return err
		}
		for _, e := range exceptions {
			key := ruleAsset{e.RuleID, e.AssetID}
			if producedKeys[key] {
				continue
			}
			producedKeys[key] = true
			runRuleIDs[e.RuleID] = true
			produced = append(produced, e)
		}
	}

	// Snapshot existing (RuleID, AssetID) pairs across all assets, scoped
	// to the rule IDs the catalogs actually produced this round.
	existing, err := repositories.GetExceptions("", "", "", "", "", "", "", "", "", "")
	if err != nil {
		return err
	}
	existingKeys := make(map[ruleAsset]bool)
	for _, x := range existing {
		if runRuleIDs[x.RuleID] {
			existingKeys[ruleAsset{x.RuleID, x.AssetID}] = true
		}
	}

	// Split produced into inserts (new keys) vs touches (existing keys).
	var inserts []models.Exception
	var touches []models.Exception
	for _, e := range produced {
		key := ruleAsset{e.RuleID, e.AssetID}
		if existingKeys[key] {
			touches = append(touches, e)
		} else {
			inserts = append(inserts, e)
		}
	}

	if len(inserts) > 0 {
		if err := InsertExceptions(inserts); err != nil {
			return err
		}
	}
	if len(touches) > 0 {
		if err := UpdateExceptions(touches); err != nil {
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
	scope := assetID
	if scope == "" {
		scope = "all assets"
	}
	log.Logger.Info(fmt.Sprintf(
		"rulesService: ExecuteRules - asset %s: inserted %d, touched %d, completed %d",
		scope, len(inserts), len(touches), completed,
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

// ExecuteSecurityRules is a copy of ExecuteRules. It currently mirrors the
// same orchestration end-to-end (same catalog-driven diff, same insert /
// touch / complete branches, same event publish) and exists as a separate
// entry point so the security-rule flow can diverge from the generic
// ExecuteRules contract later without disturbing existing callers.
func ExecuteSecurityRules(ruleName, ruleType, assetID string, idBbGlobal ...string) error {
	catalogs, err := repositories.GetRules(ruleName, ruleType)
	if err != nil {
		return err
	}

	type ruleAsset struct {
		RuleID  int
		AssetID string
	}

	// Run each catalog source once. Each result row carries its own
	// RULE_ID, so collect the produced exceptions and the set of rule
	// IDs that participated this run.
	runRuleIDs := make(map[int]bool)
	producedKeys := make(map[ruleAsset]bool)
	var produced []models.Exception
	for _, c := range catalogs {
		exceptions, err := repositories.ExecuteRule(c.RuleCommand, c.RuleCatalogID, c.RuleCatalogName, assetID, idBbGlobal...)
		if err != nil {
			return err
		}
		for _, e := range exceptions {
			key := ruleAsset{e.RuleID, e.AssetID}
			if producedKeys[key] {
				continue
			}
			producedKeys[key] = true
			runRuleIDs[e.RuleID] = true
			produced = append(produced, e)
		}
	}

	// Snapshot existing (RuleID, AssetID) pairs across all assets, scoped
	// to the rule IDs the catalogs actually produced this round.
	existing, err := repositories.GetExceptions("", "", "", "", "", "", "", "", "", "")
	if err != nil {
		return err
	}
	existingKeys := make(map[ruleAsset]bool)
	for _, x := range existing {
		if runRuleIDs[x.RuleID] {
			existingKeys[ruleAsset{x.RuleID, x.AssetID}] = true
		}
	}

	// Split produced into inserts (new keys) vs touches (existing keys).
	var inserts []models.Exception
	var touches []models.Exception
	for _, e := range produced {
		key := ruleAsset{e.RuleID, e.AssetID}
		if existingKeys[key] {
			touches = append(touches, e)
		} else {
			inserts = append(inserts, e)
		}
	}

	if len(inserts) > 0 {
		if err := InsertExceptions(inserts); err != nil {
			return err
		}
	}
	if len(touches) > 0 {
		if err := UpdateExceptions(touches); err != nil {
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
	scope := assetID
	if scope == "" {
		scope = "all assets"
	}
	log.Logger.Info(fmt.Sprintf(
		"rulesService: ExecuteSecurityRules - asset %s: inserted %d, touched %d, completed %d",
		scope, len(inserts), len(touches), completed,
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
