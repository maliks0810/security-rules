package services

import (
	"strconv"
	"strings"
	"sync"

	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
	"securityrules/security-rules/internal/utils/log"
)

// Process-local cache for SP_GET_RULES_FOR_GROUP results, keyed by
// lowercased RULE_GROUP.NAME. Sits in front of every read so the
// LHS tree — which fires one lookup per group scope switch and
// used to cost a full Snowflake round-trip each — resolves as a
// map lookup after the first miss.
//
// Population paths:
//   * Startup warmup: WarmRulesForGroupCache walks every row in
//     RULE_GROUP and populates the cache for each. One-time cost
//     at boot amortized across every subsequent LHS click.
//   * Cache miss / nil slot: GetRulesForGroup falls through to
//     Snowflake and populates the slot on the way back — covers
//     rule groups added AFTER startup and any that failed to warm.
//   * Explicit refresh: RefreshRulesByGroup(name) or
//     RefreshAllRulesByGroup() — the /refreshRulesByGroup endpoint
//     calls whichever path matches its query param.
//
// A nil slot (missing key) triggers the miss-through-to-SP path.
// An empty-but-present slot (group exists but has zero rules) is
// a valid cached value and won't re-hit Snowflake.
var rulesForGroupCache sync.Map // key: string, value: []models.RuleForGroup

func rulesForGroupCacheKey(ruleGroup string) string {
	return strings.ToLower(strings.TrimSpace(ruleGroup))
}

// getRulesForGroupCached returns the cached rows for the group.
// Nil / missing / non-slice slot triggers the miss-through path,
// which populates the cache with the SP result and returns.
func getRulesForGroupCached(ruleGroup string) ([]models.RuleForGroup, error) {
	key := rulesForGroupCacheKey(ruleGroup)
	if v, ok := rulesForGroupCache.Load(key); ok {
		if rows, ok := v.([]models.RuleForGroup); ok && rows != nil {
			return rows, nil
		}
	}
	return refreshRulesForGroupFromDB(ruleGroup)
}

// refreshRulesForGroupFromDB unconditionally hits Snowflake and
// rewrites the cache slot for the group.
func refreshRulesForGroupFromDB(ruleGroup string) ([]models.RuleForGroup, error) {
	rows, err := repositories.GetRulesForGroup(ruleGroup)
	if err != nil {
		return nil, err
	}
	if rows == nil {
		// Store an empty (non-nil) slice so a subsequent miss check
		// treats "group exists, zero rules" as a valid cached value
		// instead of re-hitting the SP.
		rows = []models.RuleForGroup{}
	}
	rulesForGroupCache.Store(rulesForGroupCacheKey(ruleGroup), rows)
	log.Logger.Info("rulesForGroupCache: refreshed from DB (rule_group=" +
		ruleGroup + ", rows=" + strconv.Itoa(len(rows)) + ")")
	return rows, nil
}

// WarmRulesForGroupCache populates the cache for every row in
// RULE_GROUP. Called once at process startup after DB init so the
// first LHS click never eats a Snowflake round-trip. Failures for
// individual groups are logged and skipped — a single bad group
// mustn't abort the boot sequence. Returns the number of groups
// successfully warmed.
func WarmRulesForGroupCache() (int, error) {
	groups, err := repositories.GetRuleGroups()
	if err != nil {
		log.Logger.Info(
			"rulesForGroupCache: warm skipped, GetRuleGroups failed: " + err.Error(),
		)
		return 0, err
	}
	warmed := 0
	for _, g := range groups {
		if strings.TrimSpace(g.Name) == "" {
			continue
		}
		if _, err := refreshRulesForGroupFromDB(g.Name); err != nil {
			log.Logger.Info("rulesForGroupCache: warm failed for '" +
				g.Name + "': " + err.Error())
			continue
		}
		warmed++
	}
	log.Logger.Info("rulesForGroupCache: warm complete (" +
		strconv.Itoa(warmed) + "/" + strconv.Itoa(len(groups)) + " groups)")
	return warmed, nil
}

// RefreshRulesByGroup forces a Snowflake round-trip and rewrites
// the cache slot for the single named group. Caller of the
// /refreshRulesByGroup endpoint uses this when they know exactly
// which group's rules changed.
func RefreshRulesByGroup(ruleGroup string) ([]models.RuleForGroup, error) {
	return refreshRulesForGroupFromDB(ruleGroup)
}

// RefreshAllRulesByGroup re-warms every group in RULE_GROUP. Same
// entry point as the startup warmup, exposed via the
// /refreshRulesByGroup endpoint when called without a group name
// (bulk-invalidation path — use after DDL / seed changes that
// touched many groups). Returns the number successfully refreshed.
func RefreshAllRulesByGroup() (int, error) {
	return WarmRulesForGroupCache()
}
