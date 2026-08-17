package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetDMUsers() ([]models.DMUser, error) {
	return repositories.GetDMUsers()
}

func GetDMRole(user string) (string, error) {
	return repositories.GetDMRole(user)
}

func GetRuleGroupsForUser(user string) ([]models.RuleGroup, error) {
	return repositories.GetRuleGroupsForUser(user)
}

// UpdateUserPreferences persists the operator's new column layout
// and eagerly invalidates the cache entry for that scope so the
// next GetUserPreferences either re-populates via a miss or via
// the caller's explicit /refreshUserPreferences call — never
// serves a pre-update value.
func UpdateUserPreferences(user, ruleGroup, ruleCatalog, columnOrder string) (int, error) {
	status, err := repositories.UpdateUserPreferences(user, ruleGroup, ruleCatalog, columnOrder)
	if err != nil {
		return status, err
	}
	invalidateUserPreferences(user, ruleGroup, ruleCatalog)
	return status, nil
}

// GetUserPreferences reads through the process-local cache — see
// userPreferencesCache.go for the miss / refresh semantics. Empty
// string comes back for "no saved layout for this scope" (a valid
// cached value); the client falls back to the canonical default
// column order.
func GetUserPreferences(user, ruleGroup, ruleCatalog string) (string, error) {
	return getUserPreferencesCached(user, ruleGroup, ruleCatalog)
}

// RefreshUserPreferences forces a Snowflake round-trip and rewrites
// the cache slot for the (user, ruleGroup, ruleCatalog) tuple with
// the freshly-fetched value. Called by the /refreshUserPreferences
// endpoint after Save Column Order — so the just-persisted layout
// is the cached one — and available for any admin flow that
// suspects cache drift.
func RefreshUserPreferences(user, ruleGroup, ruleCatalog string) (string, error) {
	return refreshUserPreferencesFromDB(user, ruleGroup, ruleCatalog)
}
