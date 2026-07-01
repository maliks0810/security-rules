package repositories

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
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

func GetRuleGroups() ([]string, error) {
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

// DeleteExceptions calls the DELETE_EXCEPTIONS(P_RULE_NAME, P_RULE_TYPE)
// SP which wipes today's EXCEPTION rows whose underlying RULE falls in
// the catalog scope implied by (ruleName, ruleType). Returns the row count.
// Empty strings flow through as SQL NULL so the SP's "all catalogs"
// branch fires.
func DeleteExceptions(ruleName, ruleType string) (int, error) {
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: DeleteExceptions - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_DELETE_EXCEPTIONS(?, ?)", nilIfEmpty(ruleName), nilIfEmpty(ruleType))
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("rulesRepository: DeleteExceptions - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_DELETE_EXCEPTIONS"($1, $2)`,
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

// resolveRuleCommand replaces ${ASSET_ID} and ${ID_BB_GLOBAL} placeholder
// tokens in the RULE_CATALOG_SOURCE command with literals derived from the
// caller's arguments. Empty values become NULL so the SP receives a real
// NULL instead of an empty-string literal. Single quotes in the values are
// doubled per SQL escaping; the inputs are URL-sourced asset and Bloomberg
// IDs, so they should never legitimately contain quotes.
func resolveRuleCommand(ruleCommand, assetID, idBbGlobal string) string {
	sqlLit := func(s string) string {
		if s == "" {
			return "NULL"
		}
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	out := strings.ReplaceAll(ruleCommand, "${ASSET_ID}", sqlLit(assetID))
	out = strings.ReplaceAll(out, "${ID_BB_GLOBAL}", sqlLit(idBbGlobal))
	return out
}

// ExecuteRule runs a RULE_CATALOG_SOURCE command verbatim once and builds
// new-model Exception rows from the result set. Expected columns:
//   - RULE_ID  â€” preferred. When present and valid, used directly.
//   - RULE_NAME â€” required when RULE_ID is absent; ExecuteRule looks the
//     ID up from the RULE table via GetRuleIDsByName (lazy, once per
//     call). Sources that supply RULE_ID never trigger the lookup.
//   - ASSET_ID / ALADDIN_ID and ISSUE_DESCRIPTION â€” used to populate
//     the exception row.
// One catalog source feeds many rules â€” each result row is tagged with
// its own RULE_ID so we avoid running the source once per rule.
// catalogName is used as a fallback display label when a row has no
// RULE_NAME column.
func ExecuteRule(ruleCommand string, catalogID int, catalogName string, assetID string, idBbGlobal ...string) ([]models.Exception, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	bbg := ""
	if len(idBbGlobal) > 0 {
		bbg = idBbGlobal[0]
	}
	resolvedCommand := resolveRuleCommand(ruleCommand, assetID, bbg)

	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: ExecuteRule - using SNOWFLAKE database environment")
		rows, err = snowflake.Query(resolvedCommand)
	} else {
		log.Logger.Info("rulesRepository: ExecuteRule - using POSTGRES database environment")
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
		// Fallback: source didn't project a RULE_ID but does carry a
		// RULE_NAME â€” resolve via RULE.RULE_NAME -> RULE.RULE_ID. The
		// lookup map is built lazily and reused for every subsequent row
		// in this catalog's result set.
		if rowRuleID == 0 && ruleNameIdx >= 0 && raw[ruleNameIdx].Valid && raw[ruleNameIdx].String != "" {
			if ruleIdByName == nil {
				if m, lerr := GetRuleIDsByName(); lerr == nil {
					ruleIdByName = m
				} else {
					log.Logger.Error(fmt.Sprintf("rulesRepository: ExecuteRule - RULE_ID fallback lookup failed: %v", lerr))
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

		idBb := ""
		if len(idBbGlobal) > 0 {
			idBb = idBbGlobal[0]
		}
		ex := models.Exception{
			RuleID:        rowRuleID,
			RuleName:      rowRuleName,
			AssetID:       assetID,
			IdBbGlobal:    idBb,
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
		// Suppress catalogID-unused warning when no usage path picks it up
		// elsewhere â€” keep it on the signature for caller-side context.
		_ = catalogID

		// Serialize the full row as a JSON object keyed by column name.
		// Built by hand (not via json.Marshal on a map) because Go's encoder
		// alphabetizes map keys, and Postgres jsonb would reorder them
		// length-then-alphabetical anyway â€” we want SQL column order.
		// Pair with EXCEPTION.RESULT_DATA stored as json (not jsonb) so the
		// text round-trips intact.
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
