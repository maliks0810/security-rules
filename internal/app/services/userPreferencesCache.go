package services

import (
	"strings"
	"sync"

	"securityrules/security-rules/internal/app/repositories"
	"securityrules/security-rules/internal/utils/log"
)

// Process-local cache for SP_GET_USER_PREFERENCES results, keyed by
// "user|ruleGroup|ruleCatalog" (all lowercased so scope-name casing
// drift never opens a duplicate slot). Sits in front of every read
// so scope switches on the LHS tree — which fire one lookup per
// click and used to cost a full Snowflake round-trip each — resolve
// as a map lookup after the first miss.
//
// Cache invalidation:
//   * On successful UpdateUserPreferences (in-process defense so
//     the next read never sees the pre-update value even if the
//     client forgets to explicitly refresh).
//   * On explicit RefreshUserPreferences — the /refreshUserPreferences
//     endpoint fires this from the frontend right after Save Column
//     Order to guarantee the cache carries the just-persisted value.
//
// An empty string is a valid cached value ("no saved layout for this
// scope"); caching it prevents thundering-herd re-fetches of
// non-existent rows for common empty-scope clicks.
var userPreferencesCache sync.Map // key: string, value: string

func userPrefsCacheKey(user, ruleGroup, ruleCatalog string) string {
	return strings.ToLower(strings.TrimSpace(user)) + "|" +
		strings.ToLower(strings.TrimSpace(ruleGroup)) + "|" +
		strings.ToLower(strings.TrimSpace(ruleCatalog))
}

// getUserPreferencesCached returns the cached column layout for the
// tuple. On a cache miss it hits Snowflake via the repository,
// stores the result (including the empty-string "no saved layout"
// case), and returns.
func getUserPreferencesCached(user, ruleGroup, ruleCatalog string) (string, error) {
	key := userPrefsCacheKey(user, ruleGroup, ruleCatalog)
	if v, ok := userPreferencesCache.Load(key); ok {
		if s, ok := v.(string); ok {
			return s, nil
		}
	}
	// Miss: populate from Snowflake and cache the result.
	return refreshUserPreferencesFromDB(user, ruleGroup, ruleCatalog)
}

// refreshUserPreferencesFromDB unconditionally hits Snowflake and
// writes the result into the cache. Shared between the miss path
// above and the explicit RefreshUserPreferences entry point.
func refreshUserPreferencesFromDB(user, ruleGroup, ruleCatalog string) (string, error) {
	columnOrder, err := repositories.GetUserPreferences(user, ruleGroup, ruleCatalog)
	if err != nil {
		return "", err
	}
	key := userPrefsCacheKey(user, ruleGroup, ruleCatalog)
	userPreferencesCache.Store(key, columnOrder)
	log.Logger.Info("userPreferencesCache: refreshed from DB (user=" +
		user + ", rule_group=" + ruleGroup +
		", rule_catalog=" + ruleCatalog + ")")
	return columnOrder, nil
}

// invalidateUserPreferences drops the cache entry for the tuple.
// Called from UpdateUserPreferences so a subsequent read either
// re-populates via a miss or via the explicit refresh path — never
// serves a pre-update value.
func invalidateUserPreferences(user, ruleGroup, ruleCatalog string) {
	userPreferencesCache.Delete(userPrefsCacheKey(user, ruleGroup, ruleCatalog))
}
