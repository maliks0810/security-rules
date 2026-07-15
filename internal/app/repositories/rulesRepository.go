package repositories

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"
	sqlutil "securityrules/security-rules/internal/utils/sql"
)

// Matches a leftover ${IDENT} placeholder — valid SQL identifier chars
// only, so it never eats a legitimate `${…}` inside a quoted string.
var placeholderRe = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)

func GetRuleGroups() ([]models.RuleGroup, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRuleGroups - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL SP_GET_RULE_GROUPS()")
	} else {
		log.Logger.Info("rulesRepository: GetRuleGroups - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_RULE_GROUPS"()`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := []models.RuleGroup{}
	for rows.Next() {
		var (
			name             sql.NullString
			statusVisible    sql.NullBool
			commentsVisible  sql.NullBool
			suppressDate     sql.NullBool
			assignToVisible  sql.NullBool
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

// ArchiveExceptions calls the SP_ARCHIVE_EXCEPTIONS(P_RULE_NAME, P_RULE_TYPE)
// SP which moves today's EXCEPTION rows whose underlying RULE falls in
// the catalog scope implied by (ruleName, ruleType) into EXCEPTION_HIST
// with a per-EXCEPTION_DATE BATCH_ID (fresh count each day, starts at 1),
// then deletes the source rows from EXCEPTION. Returns the row count moved.
// Empty strings flow through as SQL NULL so the SP's "all catalogs"
// branch fires.
func ArchiveExceptions(ruleName, ruleType string) (int, error) {
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: ArchiveExceptions - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_ARCHIVE_EXCEPTIONS(?, ?)", nilIfEmpty(ruleName), nilIfEmpty(ruleType))
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("rulesRepository: ArchiveExceptions - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_ARCHIVE_EXCEPTIONS"($1, $2)`,
		nilIfEmpty(ruleName), nilIfEmpty(ruleType),
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// InheritExceptionStatuses calls SP_INHERIT_EXCEPTION_STATUSES(P_RULE_NAME,
// P_RULE_TYPE), which for every EXCEPTION row in scope copies STATUS_ID
// from the most recent EXCEPTION_HIST row for the same (RULE_ID, ASSET_ID).
// Intended to be called immediately after InsertExceptions in ExecuteRules
// so freshly-inserted rows carry the last-known triage state forward
// instead of resetting to STATUS_ID=1 ("New"). Returns the row count
// whose STATUS_ID actually changed.
func InheritExceptionStatuses(ruleName, ruleType string) (int, error) {
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: InheritExceptionStatuses - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_INHERIT_EXCEPTION_STATUSES(?, ?)", nilIfEmpty(ruleName), nilIfEmpty(ruleType))
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("rulesRepository: InheritExceptionStatuses - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_INHERIT_EXCEPTION_STATUSES"($1, $2)`,
		nilIfEmpty(ruleName), nilIfEmpty(ruleType),
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// GetRuleIDsByName returns a snapshot of RULE_NAME -> RULE_ID for every
// row in the RULE table. Used by ExecuteRule as a fallback when a
// catalog's RULE_CATALOG_SOURCE result row only carries RULE_NAME and
// not RULE_ID â€” we resolve the ID via this map so the exception still
// gets a valid foreign key.
func GetRuleIDsByName() (map[string]int, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRuleIDsByName - using SNOWFLAKE database environment")
		rows, err = snowflake.Query(`SELECT "RULE_NAME", "RULE_ID" FROM "RULE"`)
	} else {
		log.Logger.Info("rulesRepository: GetRuleIDsByName - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT "RULE_NAME", "RULE_ID" FROM public."RULE"`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	m := make(map[string]int)
	for rows.Next() {
		var name sql.NullString
		var id sql.NullInt64
		if err := rows.Scan(&name, &id); err != nil {
			return nil, err
		}
		if name.Valid && id.Valid {
			m[name.String] = int(id.Int64)
		}
	}
	return m, nil
}

func GetRuleNames(ruleCatalog string) ([]models.RuleName, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRuleNames - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL SP_GET_RULE_NAMES(?)", ruleCatalog)
	} else {
		log.Logger.Info("rulesRepository: GetRuleNames - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_RULE_NAMES"($1)`, ruleCatalog)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := []models.RuleName{}
	for rows.Next() {
		var name, description sql.NullString
		if err := rows.Scan(&name, &description); err != nil {
			return nil, err
		}
		names = append(names, models.RuleName{
			RuleName:        sqlutil.NullStr(name),
			RuleDescription: sqlutil.NullStr(description),
		})
	}
	return names, nil
}

func GetRuleCatalogs(ruleGroup string) ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRuleCatalogs - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL SP_GET_RULE_CATALOGS(?)", ruleGroup)
	} else {
		log.Logger.Info("rulesRepository: GetRuleCatalogs - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_RULE_CATALOGS"($1)`, ruleGroup)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := []string{}
	for rows.Next() {
		var name sql.NullString
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, sqlutil.NullStr(name))
	}
	return names, nil
}

func GetRules(ruleName, ruleType string) ([]models.Rule, error) {
	var rows *sql.Rows
	var err error

	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	ruleNameArg := nilIfEmpty(ruleName)
	ruleTypeArg := nilIfEmpty(ruleType)

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRules - using SNOWFLAKE database environment")
		// snowflake.Query reopens the connection and retries once if the auth token has expired.
		rows, err = snowflake.Query("CALL SP_GET_RULES(?, ?)", ruleNameArg, ruleTypeArg)
	} else {
		log.Logger.Info("rulesRepository: GetRules - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_RULES"($1, $2)`, ruleNameArg, ruleTypeArg)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.Rule
	for rows.Next() {
		var (
			ruleCatalogID   sql.NullInt64
			ruleCatalogName sql.NullString
			ruleCommand     sql.NullString
			environment     sql.NullString
		)

		if err := rows.Scan(&ruleCatalogID, &ruleCatalogName, &ruleCommand, &environment); err != nil {
			return nil, err
		}

		rules = append(rules, models.Rule{
			RuleCatalogID:   sqlutil.NullInt(ruleCatalogID),
			RuleCatalogName: sqlutil.NullStr(ruleCatalogName),
			RuleCommand:     sqlutil.NullStr(ruleCommand),
			Environment:     sqlutil.NullStr(environment),
		})
	}

	if rules == nil {
		rules = []models.Rule{}
	}
	return rules, nil
}

// resolveRuleCommand replaces every ${NAME} placeholder token in the
// RULE_CATALOG_SOURCE command with a SQL literal derived from the
// caller's arguments. Three placeholders are always resolved from
// fixed slots:
//   - ${ASSET_ID}     → single-quoted string literal (NULL when empty)
//   - ${ID_BB_GLOBAL} → single-quoted string literal (NULL when empty)
//   - ${IS_REFRESH}   → single-quoted 'Y' / 'N' for a VARCHAR param on
//     the target SP. Empty/unknown inputs fall back to 'Y' so the
//     substitution never lands NULL when the SP expects a scalar.
// Anything else the caller supplies via the params map is substituted
// after. Empty values become NULL so the SP receives a real NULL
// instead of an empty-string literal. Single quotes in string values
// are doubled per SQL escaping; inputs from HTTP query params should
// not legitimately contain quotes.
func resolveRuleCommand(
	ruleCommand, assetID, idBbGlobal string,
	isRefresh string,
	params map[string]string,
) string {
	sqlLit := func(s string) string {
		if s == "" {
			return "NULL"
		}
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	// Normalize is_refresh to 'Y' / 'N'. Anything else (empty, garbage)
	// snaps to the 'Y' default so the placeholder never expands to a
	// bare NULL against a VARCHAR-typed SP param.
	refreshLit := "'Y'"
	switch strings.ToUpper(strings.TrimSpace(isRefresh)) {
	case "N":
		refreshLit = "'N'"
	case "Y", "":
		refreshLit = "'Y'"
	default:
		refreshLit = "'Y'"
	}
	out := strings.ReplaceAll(ruleCommand, "${ASSET_ID}", sqlLit(assetID))
	out = strings.ReplaceAll(out, "${ID_BB_GLOBAL}", sqlLit(idBbGlobal))
	out = strings.ReplaceAll(out, "${IS_REFRESH}", refreshLit)
	// Extra caller-supplied placeholders. Loop order doesn't matter —
	// each replace touches a distinct ${NAME} token. Skip the three
	// names already handled above so a caller can't accidentally
	// clobber them via the params bag.
	for k, v := range params {
		if k == "ASSET_ID" || k == "ID_BB_GLOBAL" || k == "IS_REFRESH" {
			continue
		}
		out = strings.ReplaceAll(out, "${"+k+"}", sqlLit(v))
	}
	// Sweep any surviving ${IDENT} tokens to NULL so a catalog source
	// whose SP parameter names (e.g. ${P_ALADDIN_ID}, ${RULE_NAME})
	// don't line up with the three built-ins or a caller-supplied
	// param_* still executes — the SP just receives NULL for those
	// slots. Log what got auto-nulled so unresolved placeholders are
	// visible in the operator log rather than silent.
	if leftovers := placeholderRe.FindAllString(out, -1); len(leftovers) > 0 {
		log.Logger.Warn(fmt.Sprintf(
			"rulesRepository: resolveRuleCommand - auto-substituting NULL for unresolved placeholders %v",
			leftovers,
		))
		out = placeholderRe.ReplaceAllString(out, "NULL")
	}
	return out
}

// runRuleCommandAndBuild is the shared body of ExecuteRule and
// ExecuteSecurityRule. It runs the already-resolved SQL command against
// the current DB, then walks the result set into models.Exception rows.
// The two entry points differ only in whether they seed each row's
// AssetID / IdBbGlobal from caller-supplied defaults (security flow) or
// leave them blank until the SOURCE row projects them (generic flow).
// A source row's ASSET_ID / ALADDIN_ID column always wins over the
// default when present.
func runRuleCommandAndBuild(
	resolvedCommand string,
	catalogID int,
	catalogName string,
	assetIDDefault, bbgDefault string,
) ([]models.Exception, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	var rows *sql.Rows
	var err error
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		rows, err = snowflake.Query(resolvedCommand)
	} else {
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(resolvedCommand)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	ruleIdIdx, assetIdx, idBbIdx, issueIdx, ruleNameIdx := -1, -1, -1, -1, -1
	for i, c := range cols {
		switch strings.ToUpper(c) {
		case "RULE_ID":
			ruleIdIdx = i
		case "ASSET_ID", "ALADDIN_ID":
			assetIdx = i
		case "ID_BB_GLOBAL", "FIGI":
			idBbIdx = i
		case "ISSUE_DESCRIPTION":
			issueIdx = i
		case "RULE_NAME":
			ruleNameIdx = i
		}
	}

	var ruleIdByName map[string]int // lazy fallback cache
	var exceptions []models.Exception
	for rows.Next() {
		raw := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}

		rowRuleID := 0
		if ruleIdIdx >= 0 && raw[ruleIdIdx].Valid {
			if parsed, perr := strconv.Atoi(strings.TrimSpace(raw[ruleIdIdx].String)); perr == nil {
				rowRuleID = parsed
			}
		}
		// Fallback: source didn't project RULE_ID but does carry
		// RULE_NAME — resolve via RULE.RULE_NAME → RULE.RULE_ID. Lookup
		// map is built lazily and reused for every subsequent row in
		// this catalog's result set.
		if rowRuleID == 0 && ruleNameIdx >= 0 && raw[ruleNameIdx].Valid && raw[ruleNameIdx].String != "" {
			if ruleIdByName == nil {
				if m, lerr := GetRuleIDsByName(); lerr == nil {
					ruleIdByName = m
				} else {
					log.Logger.Error(fmt.Sprintf("rulesRepository: runRuleCommandAndBuild - RULE_ID fallback lookup failed: %v", lerr))
					ruleIdByName = map[string]int{}
				}
			}
			if id, ok := ruleIdByName[raw[ruleNameIdx].String]; ok {
				rowRuleID = id
			}
		}
		if rowRuleID == 0 {
			continue
		}

		rowRuleName := catalogName
		if ruleNameIdx >= 0 && raw[ruleNameIdx].Valid && raw[ruleNameIdx].String != "" {
			rowRuleName = raw[ruleNameIdx].String
		}

		ex := models.Exception{
			RuleID:        rowRuleID,
			RuleName:      rowRuleName,
			AssetID:       assetIDDefault,
			IdBbGlobal:    bbgDefault,
			ExceptionDate: now,
			ExceptionTime: now,
			StateID:       1, // Pending
			CreatedDate:   now,
			CreatedBy:     "system",
		}
		if assetIdx >= 0 && raw[assetIdx].Valid && raw[assetIdx].String != "" {
			ex.AssetID = raw[assetIdx].String
		}
		if idBbIdx >= 0 && raw[idBbIdx].Valid && raw[idBbIdx].String != "" {
			ex.IdBbGlobal = raw[idBbIdx].String
		}
		if issueIdx >= 0 {
			ex.IssueDescription = sqlutil.NullStr(raw[issueIdx])
		}
		// Suppress catalogID-unused warning when no usage path picks it
		// up elsewhere — keep it on the signature for caller-side
		// context.
		_ = catalogID

		// Serialize the full row as a JSON object keyed by column name.
		// Built by hand (not via json.Marshal on a map) because Go's
		// encoder alphabetizes map keys, and Postgres jsonb would
		// reorder them length-then-alphabetical anyway — we want SQL
		// column order. Pair with EXCEPTION.RESULT_DATA stored as json
		// (not jsonb) so the text round-trips intact.
		var buf bytes.Buffer
		buf.WriteByte('{')
		for i, c := range cols {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyJSON, err := json.Marshal(c)
			if err != nil {
				continue
			}
			buf.Write(keyJSON)
			buf.WriteByte(':')
			if raw[i].Valid {
				valJSON, err := json.Marshal(raw[i].String)
				if err != nil {
					buf.WriteString("null")
				} else {
					buf.Write(valJSON)
				}
			} else {
				buf.WriteString("null")
			}
		}
		buf.WriteByte('}')
		ex.ResultData = buf.String()
		exceptions = append(exceptions, ex)
	}

	if exceptions == nil {
		exceptions = []models.Exception{}
	}
	return exceptions, nil
}

// ExecuteRule runs a generic RULE_CATALOG_SOURCE command. Every SP
// parameter must be spelled out as a ${NAME} placeholder inside the
// SOURCE and supplied via the params bag (or via ${IS_REFRESH} for the
// refresh flag). Not asset-scoped — for the per-asset flow that fills
// ${ASSET_ID} / ${ID_BB_GLOBAL} from a URL context, call
// ExecuteSecurityRule instead.
//
// The SOURCE's result set is expected to project:
//   - RULE_ID (preferred) or RULE_NAME (falls back to a RULE-table
//     lookup for the ID);
//   - optional ASSET_ID / ALADDIN_ID and ID_BB_GLOBAL / FIGI —
//     populated onto each Exception row when present;
//   - optional ISSUE_DESCRIPTION.
// One catalog source feeds many rules — each result row is tagged with
// its own RULE_ID so we don't run the source once per rule.
func ExecuteRule(
	ruleCommand string,
	catalogID int,
	catalogName string,
	isRefresh string,
	params map[string]string,
) ([]models.Exception, error) {
	// ExecuteRule has no URL-scoped asset — leave ${ASSET_ID} /
	// ${ID_BB_GLOBAL} to resolve to NULL. Anything caller-supplied
	// (including asset ids) must live in the params bag.
	resolvedCommand := resolveRuleCommand(ruleCommand, "", "", isRefresh, params)
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: ExecuteRule - using SNOWFLAKE database environment")
	} else {
		log.Logger.Info("rulesRepository: ExecuteRule - using POSTGRES database environment")
	}
	return runRuleCommandAndBuild(resolvedCommand, catalogID, catalogName, "", "")
}

// ExecuteSecurityRule runs a RULE_CATALOG_SOURCE command in the
// asset-scoped flow: ${ASSET_ID} and ${ID_BB_GLOBAL} placeholders
// resolve from the caller's assetID / idBbGlobal args, and each
// produced Exception row's AssetID / IdBbGlobal seeds from the same
// values (overridden by the row's ASSET_ID / ID_BB_GLOBAL projection
// when present). Everything else works identically to ExecuteRule.
func ExecuteSecurityRule(
	ruleCommand string,
	catalogID int,
	catalogName string,
	assetID string,
	isRefresh string,
	params map[string]string,
	idBbGlobal ...string,
) ([]models.Exception, error) {
	bbg := ""
	if len(idBbGlobal) > 0 {
		bbg = idBbGlobal[0]
	}
	resolvedCommand := resolveRuleCommand(ruleCommand, assetID, bbg, isRefresh, params)
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: ExecuteSecurityRule - using SNOWFLAKE database environment")
	} else {
		log.Logger.Info("rulesRepository: ExecuteSecurityRule - using POSTGRES database environment")
	}
	return runRuleCommandAndBuild(resolvedCommand, catalogID, catalogName, assetID, bbg)
}
