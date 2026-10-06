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
// Under the Security-Master-family groups (Security Master, Security
// Master Benchmark, TOD SOD) the count is narrowed to rows whose
// EXCEPTION_STATUS.NAME is one of New / Hold / Challenge / Override —
// the statuses those groups treat as open work. Accept / Suppress /
// Research are resolved there and would inflate the "there's work to
// do" figure the recipient acts on.
//
// Every other group counts EVERY status, deliberately. Those groups do
// not run the same triage lifecycle, so their total is the number the
// recipients expect. This was briefly made uniform across all groups
// and reverted: it is the intended behaviour, not an oversight.
//
// Two filters keep this counting the same population the Number of
// Exceptions grid reads, because the email disagreed with the grid for
// a Security Master catalog:
//
//   * r."IS_ACTIVE" = 1 — SP_GET_RULES_FOR_GROUP, which builds the
//     grid's ruleName -> catalog lookup, returns active rules only. An
//     exception belonging to a DEACTIVATED rule was counted against its
//     catalog here while the grid, unable to resolve its catalog,
//     bucketed it under "Unknown". Only the catalog holding the
//     deactivated rule read high, which is why a single catalog was off.
//
//   * EXCEPTION_DATE = the table's MAX — UDF_GET_EXCEPTIONS and
//     SP_GET_EXCEPTIONS scope to one EXCEPTION_DATE, and the grid
//     defaults to the latest. This counted every row in EXCEPTION
//     whatever its date, so any pre-today rows that SP_ARCHIVE_STALE_DATES
//     (cron-driven, not part of ExecuteRules) had not yet swept were
//     counted too. MAX rather than today's date so the two agree even
//     when a run lands either side of UTC midnight.
//
// Both are JOIN conditions, not WHERE predicates, deliberately: moving
// either into WHERE would turn the outer joins inner and drop catalogs
// that have no active rules or no rows today, when they must still
// appear at 0.
//
// Same pattern as GetRuleFailureEmailRecipients above: the id list is
// inlined (ints from the DB, nothing injectable) so one SQL string
// works on both Snowflake and Postgres despite their different
// placeholder syntaxes.
// openStatusList is the EXCEPTION_STATUS.NAME set treated as
// outstanding work under the Security-Master family, and smFamilyList
// is that family. Both are ready-to-inline SQL literal lists, declared
// once and interpolated into the Snowflake and Postgres branches below
// so the two cannot drift apart - the predicate used to be duplicated,
// which is the kind of thing that gets fixed on one side only.
//
// openStatusList is upper-cased because the comparison upper-cases the
// column; keep them in step if a status is ever added. smFamilyList
// mirrors SECURITY_MASTER_FAMILY_GROUPS in the frontend.
const openStatusList = "'NEW','HOLD','CHALLENGE','OVERRIDE'"
const smFamilyList = "'Security Master', 'Security Master Benchmark', 'TOD SOD'"

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
			               WHEN rg."NAME" IN (`+smFamilyList+`)
			                    AND UPPER(COALESCE(es."NAME", '')) NOT IN (`+openStatusList+`) THEN 0
			               ELSE 1
			           END)                       AS "EXCEPTION_COUNT"
			  FROM "RULE_CATALOG" rc
			  LEFT JOIN "RULE_GROUP" rg
			         ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
			  LEFT JOIN "RULE" r
			         ON r."RULE_CATALOG_ID" = rc."RULE_CATALOG_ID"
			        AND r."IS_ACTIVE" = 1
			  LEFT JOIN "EXCEPTION" e
			         ON e."RULE_ID" = r."RULE_ID"
			        AND e."EXCEPTION_DATE" = (SELECT MAX("EXCEPTION_DATE") FROM "EXCEPTION")
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
			               WHEN rg."NAME" IN (`+smFamilyList+`)
			                    AND UPPER(COALESCE(es."NAME", '')) NOT IN (`+openStatusList+`) THEN 0
			               ELSE 1
			           END)                       AS "EXCEPTION_COUNT"
			  FROM public."RULE_CATALOG" rc
			  LEFT JOIN public."RULE_GROUP" rg
			         ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
			  LEFT JOIN public."RULE" r
			         ON r."RULE_CATALOG_ID" = rc."RULE_CATALOG_ID"
			        AND r."IS_ACTIVE" = 1
			  LEFT JOIN public."EXCEPTION" e
			         ON e."RULE_ID" = r."RULE_ID"
			        AND e."EXCEPTION_DATE" = (SELECT MAX("EXCEPTION_DATE") FROM public."EXCEPTION")
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
