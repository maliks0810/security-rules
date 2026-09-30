package repositories

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"
	sqlutil "securityrules/security-rules/internal/utils/sql"
)

// GetRuleFailureEmailRecipients resolves the email addresses to notify
// for a set of rule catalogs.
//
// The chain is: RULE_CATALOG.RULE_GROUP_ID -> the group's
// RULE_GROUP_AUTHORIZATION.ACCESS_LIST -> the DM_USER rows whose EMAIL
// appears in that list -> only those with
// FLAG_EMAIL_ON_RULE_FAILURE = 'Y'.
//
// Keyed on catalog IDs rather than on (rule_name, rule_type) because
// the caller has already resolved its scope to catalogs via GetRules.
// That makes GROUP, CATALOG and RULE scopes all work through one path
// instead of re-deriving the three-way scope logic here, and it means a
// RULE scope correctly notifies the group that owns the rule's catalog.
//
// ACCESS_LIST is a free-form comma-separated email list, so membership
// is matched the same way SP_GET_RULE_GROUPS_FOR_USER does it:
// normalize case, strip spaces, fence both sides with ',' and match
// ',<email>,'. The fencing is what stops 'joe@x.com' matching inside
// 'joesmith@x.com'.
//
// Returns a de-duplicated list — a scope spanning several catalogs in
// the same group, or a person listed in two groups' access lists, must
// not produce a repeated recipient. An empty result is a normal outcome
// (no authorization row, nobody opted in) and not an error.
func GetRuleFailureEmailRecipients(ruleCatalogIDs []int) ([]string, error) {
	if len(ruleCatalogIDs) == 0 {
		return nil, nil
	}
	// Inlined as a literal list rather than bound placeholders: these
	// are ints parsed from the DB, so there is nothing injectable, and
	// it keeps one SQL string that works on both engines despite their
	// different placeholder syntax ($1 vs ?). Same reasoning as
	// joinExceptionIDs in exceptionsRepository.go.
	parts := make([]string, 0, len(ruleCatalogIDs))
	for _, id := range ruleCatalogIDs {
		parts = append(parts, strconv.Itoa(id))
	}
	idList := strings.Join(parts, ",")

	var rows *sql.Rows
	var err error
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("notificationsRepository: GetRuleFailureEmailRecipients - using SNOWFLAKE database environment")
		rows, err = snowflake.Query(fmt.Sprintf(`
			SELECT DISTINCT du."EMAIL"
			  FROM "RULE_GROUP_AUTHORIZATION" rga
			  JOIN "DM_USER" du
			    ON ',' || REPLACE(UPPER(rga."ACCESS_LIST"), ' ', '') || ','
			       LIKE '%%,' || UPPER(du."EMAIL") || ',%%'
			 WHERE rga."RULE_GROUP_ID" IN (
			           SELECT rc."RULE_GROUP_ID"
			             FROM "RULE_CATALOG" rc
			            WHERE rc."RULE_CATALOG_ID" IN (%s)
			              AND rc."RULE_GROUP_ID" IS NOT NULL
			       )
			   AND du."EMAIL" IS NOT NULL
			   AND du."EMAIL" <> ''
			   AND UPPER(COALESCE(du."FLAG_EMAIL_ON_RULE_FAILURE", 'N')) = 'Y'`, idList))
	} else {
		log.Logger.Info("notificationsRepository: GetRuleFailureEmailRecipients - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(fmt.Sprintf(`
			SELECT DISTINCT du."EMAIL"
			  FROM public."RULE_GROUP_AUTHORIZATION" rga
			  JOIN public."DM_USER" du
			    ON ',' || REPLACE(UPPER(rga."ACCESS_LIST"), ' ', '') || ','
			       LIKE '%%,' || UPPER(du."EMAIL") || ',%%'
			 WHERE rga."RULE_GROUP_ID" IN (
			           SELECT rc."RULE_GROUP_ID"
			             FROM public."RULE_CATALOG" rc
			            WHERE rc."RULE_CATALOG_ID" IN (%s)
			              AND rc."RULE_GROUP_ID" IS NOT NULL
			       )
			   AND du."EMAIL" IS NOT NULL
			   AND du."EMAIL" <> ''
			   AND UPPER(COALESCE(du."FLAG_EMAIL_ON_RULE_FAILURE", 'N')) = 'Y'`, idList))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var emails []string
	for rows.Next() {
		var email sql.NullString
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		if e := strings.TrimSpace(sqlutil.NullStr(email)); e != "" {
			emails = append(emails, e)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return emails, nil
}
