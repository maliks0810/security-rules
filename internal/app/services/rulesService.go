package services

import (
	"fmt"
	"time"

	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
	"securityrules/security-rules/internal/utils/log"
)

func GetRules(ruleName, ruleType string) ([]models.Rule, error) {
	return repositories.GetRules(ruleName, ruleType)
}

func GetRuleGroups() ([]models.RuleGroup, error) {
	return repositories.GetRuleGroups()
}

func GetRuleCatalogs(ruleGroup string) ([]string, error) {
	return repositories.GetRuleCatalogs(ruleGroup)
}

func GetRuleNames(ruleCatalog string) ([]models.RuleName, error) {
	return repositories.GetRuleNames(ruleCatalog)
}

// ExecuteRules runs every catalog in (ruleName, ruleType) scope after first
// wiping the day's EXCEPTION rows for that same scope via DELETE_EXCEPTIONS.
// Every row produced by every catalog source is INSERTED verbatim — no
// (RuleID, AssetID) dedupe, no touch/complete branches, no diff against
// existing rows, no SSE event. The grain of the result set is whatever
// each RULE_CATALOG_SOURCE returns. Use ExecuteSecurityRules for the
// asset-scoped, incremental flow that dedupes and touches/completes.
func ExecuteRules(ruleName, ruleType string, params map[string]string) error {
	catalogs, err := repositories.GetRules(ruleName, ruleType)
	if err != nil {
		return err
	}

	archived, err := repositories.ArchiveExceptions(ruleName, ruleType)
	if err != nil {
		return err
	}

	var produced []models.Exception
	for _, c := range catalogs {
		exceptions, err := repositories.ExecuteRule(c.RuleCommand, c.RuleCatalogID, c.RuleCatalogName, "", params)
		if err != nil {
			return err
		}
		produced = append(produced, exceptions...)
	}

	if len(produced) > 0 {
		if err := InsertExceptions(produced); err != nil {
			return err
		}
	}

	// After inserting the fresh batch, carry the last-known STATUS_ID
	// forward from EXCEPTION_HIST so previously-triaged rows don't reset
	// to "New". Best-effort: log-and-continue on error, since a failed
	// inheritance shouldn't blow up the whole run.
	inherited := 0
	if n, ierr := repositories.InheritExceptionStatuses(ruleName, ruleType); ierr != nil {
		log.Logger.Warn(fmt.Sprintf(
			"rulesService: ExecuteRules - InheritExceptionStatuses failed, continuing: %v", ierr,
		))
	} else {
		inherited = n
	}

	log.Logger.Info(fmt.Sprintf(
		"rulesService: ExecuteRules - rule_name=%q rule_type=%q: archived %d, inserted %d, inherited %d",
		ruleName, ruleType, archived, len(produced), inherited,
	))

	events.Publish(events.Event{
		Type: "rules.executed",
		Payload: map[string]any{
			"rule_name": ruleName,
			"rule_type": ruleType,
			"count":     len(produced),
			"time":      time.Now().UTC().Format(time.RFC3339),
		},
	})
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
		exceptions, err := repositories.ExecuteRule(c.RuleCommand, c.RuleCatalogID, c.RuleCatalogName, assetID, nil, idBbGlobal...)
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
		n, err := repositories.UpdateExceptionState(k.AssetID, k.RuleID, true)
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
