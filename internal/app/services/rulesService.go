package services

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
	"securityrules/security-rules/internal/utils/log"
)

// One mutex per (rule_name, rule_type) scope so two concurrent
// /executeRules invocations for the same scope serialize instead of
// racing on archive-then-insert. sync.Map lets us lazily create per-key
// mutexes without a global lock. Belt-and-suspenders with the POST
// route change — the POST kills ingress-level retries; this mutex
// covers the double-click / caller-initiated concurrent case.
var executeRulesMu sync.Map

// ErrRuleScopeNotFound signals that the caller supplied a specific
// scope (rule_name != "" / "All") but no RULE_CATALOG matched. The
// handler unwraps this via errors.Is and turns it into an HTTP 404
// instead of a generic 500 or a silent 200-with-zero-inserts.
var ErrRuleScopeNotFound = errors.New("no catalog matched the requested scope")

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

func GetRulesForGroup(ruleGroup string) ([]models.RuleForGroup, error) {
	return repositories.GetRulesForGroup(ruleGroup)
}

// ExecuteRules runs every catalog in (req.RuleName, req.RuleType) scope,
// then — only after every catalog has succeeded — moves the day's
// existing EXCEPTION rows for that same scope into EXCEPTION_HIST (via
// SP_ARCHIVE_EXCEPTIONS) and inserts the newly-produced rows verbatim.
// Archiving is deferred so that if any catalog fails, EXCEPTION keeps
// the previous run's rows intact and callers can retry without a data
// gap. No (RuleID, AssetID) dedupe, no touch/complete branches, no diff
// against existing rows. Use ExecuteSecurityRules for the asset-scoped
// incremental flow.
//
// The signature takes ExecuteRulesRequest so the handler can hand it
// straight from the POST body without unpacking; is_refresh missing /
// empty defaults to "Y" up front. Returns the number of exceptions
// inserted this run so the handler can populate
// ExecuteRulesResponse.ExceptionCount.
func ExecuteRules(req models.ExecuteRulesRequest) (int, error) {
	if strings.TrimSpace(req.IsRefresh) == "" {
		req.IsRefresh = "Y"
	}
	// Serialize per-scope. Key on the exact RuleName / RuleType the
	// caller passed so distinct scopes still run in parallel.
	scopeKey := strings.ToUpper(strings.TrimSpace(req.RuleType)) + "|" + req.RuleName
	muAny, _ := executeRulesMu.LoadOrStore(scopeKey, &sync.Mutex{})
	mu := muAny.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	catalogs, err := repositories.GetRules(req.RuleName, req.RuleType)
	if err != nil {
		return 0, err
	}

	// A specific scope (RuleName set and not "All") that resolves to
	// zero catalogs is a client error, not a silent success — the
	// caller almost certainly mistyped the group/catalog/rule name.
	// Wrap ErrRuleScopeNotFound so the handler can turn it into 404
	// while still logging the exact scope that missed.
	specificScope := req.RuleName != "" && !strings.EqualFold(req.RuleName, "All")
	if specificScope && len(catalogs) == 0 {
		return 0, fmt.Errorf("%w: rule_type=%q rule_name=%q", ErrRuleScopeNotFound, req.RuleType, req.RuleName)
	}

	// When rule_type = RULE, the caller's rule_name identifies a
	// specific rule inside the catalog. Surface it to the RULE_CATALOG
	// sources as ${RULE_NAME}. Clone the params map so we don't mutate
	// what the handler built; sources that don't reference ${RULE_NAME}
	// just no-op on ReplaceAll, so this is safe to always thread.
	catalogParams := req.Params
	if strings.EqualFold(req.RuleType, "RULE") && req.RuleName != "" {
		catalogParams = make(map[string]string, len(req.Params)+1)
		for k, v := range req.Params {
			catalogParams[k] = v
		}
		catalogParams["RULE_NAME"] = req.RuleName
	}

	// Per-catalog fail-fast: any DB error from the underlying SP call
	// (bad IS_REFRESH signature, RECON proc that panicked, a Snowflake
	// syntax error in a hand-edited RULE_CATALOG_SOURCE, etc.) surfaces
	// straight back to the /executeRules handler so the operator gets a
	// 500 with the real backend message. Archive hasn't run yet, so
	// EXCEPTION still holds the previous run's rows — no data gap.
	var produced []models.Exception
	for _, c := range catalogs {
		exceptions, err := repositories.ExecuteRule(c.RuleCommand, c.RuleCatalogID, c.RuleCatalogName, req.IsRefresh, catalogParams)
		if err != nil {
			log.Logger.Error(fmt.Sprintf(
				"rulesService: ExecuteRules - catalog %q (id=%d) failed: %v",
				c.RuleCatalogName, c.RuleCatalogID, err,
			))
			return 0, fmt.Errorf("catalog %q (id=%d): %w", c.RuleCatalogName, c.RuleCatalogID, err)
		}
		// Per-catalog produced count — surfaces which source's row count
		// looks wrong when a scope-wide total diverges from expectations
		// (e.g. an SP that reads EXCEPTION as input and double-counts
		// because archive is now deferred until the loop finishes).
		log.Logger.Info(fmt.Sprintf(
			"rulesService: ExecuteRules - catalog %q (id=%d) produced %d rows",
			c.RuleCatalogName, c.RuleCatalogID, len(exceptions),
		))
		produced = append(produced, exceptions...)
	}

	// All catalogs succeeded — now archive today's EXCEPTION rows for
	// this scope into EXCEPTION_HIST (stamped with a per-date BATCH_ID)
	// and insert the freshly-produced batch. Archive-then-insert
	// ordering keeps EXCEPTION from holding two generations of the
	// same (RuleID, AssetID) key mid-transition.
	//
	// Stale-date housekeeping (SP_ARCHIVE_STALE_DATES) is deliberately
	// NOT called from here — an external cron runs the SP directly on
	// Snowflake to sweep pre-today rows into HIST.
	archived, err := repositories.ArchiveExceptions(req.RuleName, req.RuleType)
	if err != nil {
		return 0, err
	}

	if len(produced) > 0 {
		if err := InsertExceptions(produced); err != nil {
			return 0, err
		}
	}

	// After inserting the fresh batch, carry the last-known STATUS_ID
	// forward from EXCEPTION_HIST so previously-triaged rows don't reset
	// to "New". Best-effort: log-and-continue on error, since a failed
	// inheritance shouldn't blow up the whole run.
	inherited := 0
	if n, ierr := repositories.InheritExceptionStatuses(req.RuleName, req.RuleType); ierr != nil {
		log.Logger.Warn(fmt.Sprintf(
			"rulesService: ExecuteRules - InheritExceptionStatuses failed, continuing: %v", ierr,
		))
	} else {
		inherited = n
	}

	// Per-catalog revert-to-New workflow. Each RULE_CATALOG row can
	// declare a stored procedure in REVERT_TO_NEW_CRITERIA that
	// re-evaluates its non-New EXCEPTION rows and flips any that no
	// longer satisfy the exception criteria back to STATUS_ID = 1.
	// Runs after inheritance so a row that inherited Accept/Suppress
	// yesterday still gets a chance to revert today if its underlying
	// values drifted. Dedup by SP name so a scope that spans multiple
	// catalogs sharing the same revert SP only calls it once.
	// Best-effort: log-and-continue on failure so a bad revert SP
	// doesn't break the whole run.
	seenRevertSPs := make(map[string]struct{}, len(catalogs))
	reverted := 0
	for _, c := range catalogs {
		sp := strings.TrimSpace(c.RevertToNewCriteria)
		if sp == "" {
			continue
		}
		if _, dup := seenRevertSPs[sp]; dup {
			continue
		}
		seenRevertSPs[sp] = struct{}{}
		if n, rerr := repositories.ExecuteRevertToNewCriteria(sp); rerr != nil {
			log.Logger.Warn(fmt.Sprintf(
				"rulesService: ExecuteRules - ExecuteRevertToNewCriteria(%q) failed, continuing: %v", sp, rerr,
			))
		} else {
			reverted += n
		}
	}

	log.Logger.Info(fmt.Sprintf(
		"rulesService: ExecuteRules - rule_name=%q rule_type=%q: archived %d, inserted %d, inherited %d, reverted %d",
		req.RuleName, req.RuleType, archived, len(produced), inherited, reverted,
	))

	events.Publish(events.Event{
		Type: "rules.executed",
		Payload: map[string]any{
			"rule_name": req.RuleName,
			"rule_type": req.RuleType,
			"count":     len(produced),
			"time":      time.Now().UTC().Format(time.RFC3339),
		},
	})
	return len(produced), nil
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
		exceptions, err := repositories.ExecuteSecurityRule(c.RuleCommand, c.RuleCatalogID, c.RuleCatalogName, assetID, "N", nil, idBbGlobal...)
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
