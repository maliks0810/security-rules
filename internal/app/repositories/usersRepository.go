package repositories

import (
	"database/sql"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"
	sqlutil "securityrules/security-rules/internal/utils/sql"
)

// GetDMRole returns DM_USER.ROLE for the supplied display name.
// Powers the frontend gate that decides whether Bulk Assign / Bulk
// Status buttons show and whether the per-row Assign To column is
// editable. Unknown user → "" (empty), which the caller treats as
// the least-privileged default. Called by the DqMonitorPage on
// mount with the current operator's user (Okta-resolved once
// integration lands; hard-coded pre-cutover).
func GetDMRole(user string) (string, error) {
	if strings.TrimSpace(user) == "" {
		return "", nil
	}
	var role sql.NullString
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("usersRepository: GetDMRole - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_GET_DM_ROLE(?)", user)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&role); err != nil {
				return "", err
			}
		}
		return sqlutil.NullStr(role), nil
	}
	log.Logger.Info("usersRepository: GetDMRole - using POSTGRES database environment")
	if postgres.DB == nil {
		return "", sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT * FROM public."SP_GET_DM_ROLE"($1)`,
		user,
	).Scan(&role)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return sqlutil.NullStr(role), nil
}

// GetRuleGroupsForUser returns the subset of RULE_GROUP rows the
// given operator (userName) is authorized to see via
// RULE_GROUP_AUTHORIZATION.ACCESS_LIST. Column shape matches
// rulesRepository.GetRuleGroups so callers (the LHS tree feed) can
// consume either fn without reshape. Empty userName → empty result
// (no privileges by default). See SP_GET_RULE_GROUPS_FOR_USER for
// the ACCESS_LIST → DM_USER.EMAIL matching semantics.
//
// Named GetRuleGroupsForUser (not GetRuleGroups) because the
// unfiltered variant already lives in rulesRepository.go under the
// same `repositories` package — Go doesn't allow two funcs with the
// same name in one package.
func GetRuleGroupsForUser(userName string) ([]models.RuleGroup, error) {
	if strings.TrimSpace(userName) == "" {
		return []models.RuleGroup{}, nil
	}

	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("usersRepository: GetRuleGroups - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL SP_GET_RULE_GROUPS_FOR_USER(?)", userName)
	} else {
		log.Logger.Info("usersRepository: GetRuleGroups - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(
			`SELECT * FROM public."SP_GET_RULE_GROUPS_FOR_USER"($1)`,
			userName,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := []models.RuleGroup{}
	for rows.Next() {
		var (
			name            sql.NullString
			statusVisible   sql.NullBool
			commentsVisible sql.NullBool
			suppressDate    sql.NullBool
			assignToVisible sql.NullBool
		)
		if err := rows.Scan(&name, &statusVisible, &commentsVisible, &suppressDate, &assignToVisible); err != nil {
			return nil, err
		}
		groups = append(groups, models.RuleGroup{
			Name:                sqlutil.NullStr(name),
			FlagStatusVisible:   statusVisible.Valid && statusVisible.Bool,
			FlagCommentsVisible: commentsVisible.Valid && commentsVisible.Bool,
			FlagSuppressDate:    suppressDate.Valid && suppressDate.Bool,
			FlagAssignToVisible: assignToVisible.Valid && assignToVisible.Bool,
		})
	}
	return groups, nil
}

// UpdateUserPreferences upserts a per-operator UI preference row
// into USER_PREFERENCES for the (user, rule group, rule catalog)
// tuple. Today the only persisted field is columnOrder (an opaque
// JSON string the client encodes). Pass ruleCatalog as "" when the
// LHS tree is at the group root — the row is then scoped to the
// whole group and RULE_CATALOG_ID is stored NULL.
//
// Returns the proc's status code verbatim:
//   0 — no-op (unknown user, group, or explicit catalog name).
//   1 — inserted a new preferences row.
//   2 — updated an existing preferences row.
func UpdateUserPreferences(user, ruleGroup, ruleCatalog, columnOrder string) (int, error) {
	if strings.TrimSpace(user) == "" {
		return 0, nil
	}
	if strings.TrimSpace(ruleGroup) == "" {
		return 0, nil
	}
	var status sql.NullInt64
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("usersRepository: UpdateUserPreferences - using SNOWFLAKE database environment")
		rows, err := snowflake.Query(
			"CALL SP_UPDATE_USER_PREFERENCES(?, ?, ?, ?)",
			user, ruleGroup, ruleCatalog, columnOrder,
		)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&status); err != nil {
				return 0, err
			}
		}
		if !status.Valid {
			return 0, nil
		}
		return int(status.Int64), nil
	}
	log.Logger.Info("usersRepository: UpdateUserPreferences - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_UPDATE_USER_PREFERENCES"($1, $2, $3, $4)`,
		user, ruleGroup, ruleCatalog, columnOrder,
	).Scan(&status)
	if err != nil {
		return 0, err
	}
	if !status.Valid {
		return 0, nil
	}
	return int(status.Int64), nil
}

// ClearUserPreferences deletes the saved column layout for the
// (user, rule group, rule catalog) scope so the grid falls back to
// its canonical default order. Powers Settings → Reset Column
// Headers. Pass ruleCatalog as "" when the LHS tree is at the group
// root — the SP then targets the row whose RULE_CATALOG_ID IS NULL.
// Only that one scope's row is removed; the user's other saved
// layouts are untouched.
//
// Returns the proc's row count: 0 when nothing was deleted (unknown
// user / group / catalog, or simply no saved layout — callers treat
// that as success, since "no saved layout" is the target state), 1
// when the row was removed.
func ClearUserPreferences(user, ruleGroup, ruleCatalog string) (int, error) {
	if strings.TrimSpace(user) == "" {
		return 0, nil
	}
	if strings.TrimSpace(ruleGroup) == "" {
		return 0, nil
	}
	var affected sql.NullInt64
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("usersRepository: ClearUserPreferences - using SNOWFLAKE database environment")
		rows, err := snowflake.Query(
			"CALL SP_CLEAR_USER_PREFERENCES(?, ?, ?)",
			user, ruleGroup, ruleCatalog,
		)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&affected); err != nil {
				return 0, err
			}
		}
		if !affected.Valid {
			return 0, nil
		}
		return int(affected.Int64), nil
	}
	log.Logger.Info("usersRepository: ClearUserPreferences - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_CLEAR_USER_PREFERENCES"($1, $2, $3)`,
		user, ruleGroup, ruleCatalog,
	).Scan(&affected)
	if err != nil {
		return 0, err
	}
	if !affected.Valid {
		return 0, nil
	}
	return int(affected.Int64), nil
}

// GetUserPreferences reads the saved COLUMN_ORDER for the (user,
// rule group, rule catalog) scope from USER_PREFERENCES. Pass
// ruleCatalog as "" when the LHS tree is at the group root — the
// SP matches the row where RULE_CATALOG_ID IS NULL via EQUAL_NULL /
// IS NOT DISTINCT FROM. Returns "" when no matching row exists so
// callers can fall back to the canonical default column layout.
func GetUserPreferences(user, ruleGroup, ruleCatalog string) (string, error) {
	if strings.TrimSpace(user) == "" {
		return "", nil
	}
	if strings.TrimSpace(ruleGroup) == "" {
		return "", nil
	}
	var columnOrder sql.NullString
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("usersRepository: GetUserPreferences - using SNOWFLAKE database environment")
		rows, err := snowflake.Query(
			"CALL SP_GET_USER_PREFERENCES(?, ?, ?)",
			user, ruleGroup, ruleCatalog,
		)
		if err != nil {
			return "", err
		}
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&columnOrder); err != nil {
				return "", err
			}
		}
		return sqlutil.NullStr(columnOrder), nil
	}
	log.Logger.Info("usersRepository: GetUserPreferences - using POSTGRES database environment")
	if postgres.DB == nil {
		return "", sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT * FROM public."SP_GET_USER_PREFERENCES"($1, $2, $3)`,
		user, ruleGroup, ruleCatalog,
	).Scan(&columnOrder)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return sqlutil.NullStr(columnOrder), nil
}

// GetDMUsers returns every row from DM_USER as {user, role, email}
// tuples in DM_USER.ID order. Row 0 is always the "Unassigned"
// placeholder — role + email come back empty for that row.
func GetDMUsers() ([]models.DMUser, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("usersRepository: GetDMUsers - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL SP_GET_DM_USERS()")
	} else {
		log.Logger.Info("usersRepository: GetDMUsers - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_DM_USERS"()`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []models.DMUser{}
	for rows.Next() {
		var name, role, email sql.NullString
		if err := rows.Scan(&name, &role, &email); err != nil {
			return nil, err
		}
		users = append(users, models.DMUser{
			User:  sqlutil.NullStr(name),
			Role:  sqlutil.NullStr(role),
			Email: sqlutil.NullStr(email),
		})
	}
	return users, nil
}
