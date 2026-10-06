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

// CatalogExceptionCount is one row of the summary that
// SendExceptionsEmail renders into the notification's HTML table:
// a rule catalog, the RULE_GROUP that owns it, and how many live
// EXCEPTION rows it currently holds.
type CatalogExceptionCount struct {
	GroupName      string
	CatalogName    string
	ExceptionCount int
}

// GetExceptionCountsByCatalog returns one row per input catalog id
// (LEFT JOINed against EXCEPTION so a catalog with zero live rows
// still appears at 0), enriched with its owning RULE_GROUP name.
// Ordered by (group name, catalog name) so the notification's table
// reads predictably across sends.
//
// The count is narrowed to rows whose EXCEPTION_STATUS.NAME is one of
// New / Hold / Challenge / Override — the statuses that represent open
// work. Accept / Suppress / Research rows are resolved and must not
// inflate the "there's work to do" figure the recipient acts on.
//
// Applies to EVERY group. This used to be gated on the
// Security-Master-family groups, with all other groups counting every
// status, which is why the email disagreed with the Number of
// Exceptions grid for some catalogs: Pricing and Valuation, Cash
// Control, Investment Operations and Trading Agreements were reporting
// resolved rows as outstanding work.
//
// Same pattern as GetRuleFailureEmailRecipients above: the id list is
// inlined (ints from the DB, nothing injectable) so one SQL string
// works on both Snowflake and Postgres despite their different
// placeholder syntaxes.
// openStatusList is the EXCEPTION_STATUS.NAME set the notification
// counts as outstanding work, as a ready-to-inline SQL literal list.
// Declared once and interpolated into both engine branches below so the
// two cannot drift apart - the previous duplicated predicate was the
// kind of thing that gets fixed on one side only.
//
// Upper-cased because the comparison upper-cases the column; keep them
// in step if a status is ever added.
const openStatusList = "'NEW','HOLD','CHALLENGE','OVERRIDE'"

func GetExceptionCountsByCatalog(ruleCatalogIDs []int) ([]CatalogExceptionCount, error) {
	if len(ruleCatalogIDs) == 0 {
		return nil, nil
	}
	parts := make([]string, 0, len(ruleCatalogIDs))
	for _, id := range ruleCatalogIDs {
		parts = append(parts, strconv.Itoa(id))
	}
	idList := strings.Join(parts, ",")

	var rows *sql.Rows
	var err error
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("notificationsRepository: GetExceptionCountsByCatalog - using SNOWFLAKE database environment")
		rows, err = snowflake.Query(fmt.Sprintf(`
			SELECT COALESCE(rg."NAME", '')        AS "GROUP_NAME",
			       COALESCE(rc."NAME", '')        AS "CATALOG_NAME",
			       SUM(CASE
			               WHEN e."EXCEPTION_ID" IS NULL THEN 0
			               WHEN UPPER(COALESCE(es."NAME", '')) IN (`+openStatusList+`) THEN 1
			               ELSE 0
			           END)                       AS "EXCEPTION_COUNT"
			  FROM "RULE_CATALOG" rc
			  LEFT JOIN "RULE_GROUP" rg
			         ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
			  LEFT JOIN "RULE" r
			         ON r."RULE_CATALOG_ID" = rc."RULE_CATALOG_ID"
			  LEFT JOIN "EXCEPTION" e
			         ON e."RULE_ID" = r."RULE_ID"
			  LEFT JOIN "EXCEPTION_STATUS" es
			         ON es."EXCEPTION_STATUS_ID" = e."STATUS_ID"
			 WHERE rc."RULE_CATALOG_ID" IN (%s)
			 GROUP BY rg."NAME", rc."NAME"
			 ORDER BY rg."NAME", rc."NAME"`, idList))
	} else {
		log.Logger.Info("notificationsRepository: GetExceptionCountsByCatalog - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(fmt.Sprintf(`
			SELECT COALESCE(rg."NAME", '')        AS "GROUP_NAME",
			       COALESCE(rc."NAME", '')        AS "CATALOG_NAME",
			       SUM(CASE
			               WHEN e."EXCEPTION_ID" IS NULL THEN 0
			               WHEN UPPER(COALESCE(es."NAME", '')) IN (`+openStatusList+`) THEN 1
			               ELSE 0
			           END)                       AS "EXCEPTION_COUNT"
			  FROM public."RULE_CATALOG" rc
			  LEFT JOIN public."RULE_GROUP" rg
			         ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
			  LEFT JOIN public."RULE" r
			         ON r."RULE_CATALOG_ID" = rc."RULE_CATALOG_ID"
			  LEFT JOIN public."EXCEPTION" e
			         ON e."RULE_ID" = r."RULE_ID"
			  LEFT JOIN public."EXCEPTION_STATUS" es
			         ON es."EXCEPTION_STATUS_ID" = e."STATUS_ID"
			 WHERE rc."RULE_CATALOG_ID" IN (%s)
			 GROUP BY rg."NAME", rc."NAME"
			 ORDER BY rg."NAME", rc."NAME"`, idList))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CatalogExceptionCount
	for rows.Next() {
		var (
			group   sql.NullString
			catalog sql.NullString
			count   sql.NullInt64
		)
		if err := rows.Scan(&group, &catalog, &count); err != nil {
			return nil, err
		}
		out = append(out, CatalogExceptionCount{
			GroupName:      sqlutil.NullStr(group),
			CatalogName:    sqlutil.NullStr(catalog),
			ExceptionCount: int(count.Int64),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

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
func GetRuleFailureEmailRecipients(ruleCatalogIDs []int, roleFilter string) ([]string, error) {
	if len(ruleCatalogIDs) == 0 {
		return nil, nil
	}
	// SP_GET_RULE_GROUP_EMAIL_LIST takes the id list as a
	// comma-separated string and does the SPLIT_TO_TABLE /
	// unnest(string_to_array) inside; matches how the bulk-status /
	// bulk-assign SPs already receive their id / rule-name lists.
	// roleFilter, when non-empty, additionally restricts the SP's
	// recipient set to DM_USER rows whose ROLE equals it
	// (case-insensitive). Empty means no role restriction — the
	// production branch of the caller.
	parts := make([]string, 0, len(ruleCatalogIDs))
	for _, id := range ruleCatalogIDs {
		parts = append(parts, strconv.Itoa(id))
	}
	idList := strings.Join(parts, ",")
	// nilIfEmpty keeps the SP's NULL / '' branch — matches the pattern
	// ArchiveExceptions / InheritExceptionStatuses use for their
	// optional scope params.
	roleArg := func() any {
		if strings.TrimSpace(roleFilter) == "" {
			return nil
		}
		return roleFilter
	}()

	var rows *sql.Rows
	var err error
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("notificationsRepository: GetRuleFailureEmailRecipients - using SNOWFLAKE database environment")
		rows, err = snowflake.Query(`CALL SP_GET_RULE_GROUP_EMAIL_LIST(?, ?)`, idList, roleArg)
	} else {
		log.Logger.Info("notificationsRepository: GetRuleFailureEmailRecipients - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_RULE_GROUP_EMAIL_LIST"($1, $2)`, idList, roleArg)
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
