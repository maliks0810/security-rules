package repositories

import (
	"database/sql"
	"encoding/json"
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
		rows, err = snowflake.Query("CALL GET_RULE_GROUPS()")
	} else {
		log.Logger.Info("rulesRepository: GetRuleGroups - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_RULE_GROUPS"()`)
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

func GetRuleNames(ruleCatalog string) ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRuleNames - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL GET_RULE_NAMES(?)", ruleCatalog)
	} else {
		log.Logger.Info("rulesRepository: GetRuleNames - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_RULE_NAMES"($1)`, ruleCatalog)
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

func GetRuleCatalogs(ruleGroup string) ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRuleCatalogs - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL GET_RULE_CATALOGS(?)", ruleGroup)
	} else {
		log.Logger.Info("rulesRepository: GetRuleCatalogs - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_RULE_CATALOGS"($1)`, ruleGroup)
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

func GetRules(processType, ruleCatalog string) ([]models.Rule, error) {
	var rows *sql.Rows
	var err error

	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	ruleCatalogArg := nilIfEmpty(ruleCatalog)

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRules - using SNOWFLAKE database environment")
		// snowflake.Query reopens the connection and retries once if the auth token has expired.
		rows, err = snowflake.Query("CALL GET_RULES(?, ?)", processType, ruleCatalogArg)
	} else {
		log.Logger.Info("rulesRepository: GetRules - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_RULES"($1, $2)`, processType, ruleCatalogArg)
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
// new-model Exception rows from the result set. The result is expected to
// include columns RULE_ID (which rule produced the row), ASSET_ID or
// ALADDIN_ID, and ISSUE_DESCRIPTION; RULE_NAME is optional. One catalog
// source feeds many rules — each result row is tagged with its own RULE_ID
// so we avoid running the source once per rule. catalogName is used as a
// fallback display label when a row has no RULE_NAME column.
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

	ruleIdIdx, assetIdx, issueIdx, ruleNameIdx := -1, -1, -1, -1
	for i, c := range cols {
		switch strings.ToUpper(c) {
		case "RULE_ID":
			ruleIdIdx = i
		case "ASSET_ID", "ALADDIN_ID":
			assetIdx = i
		case "ISSUE_DESCRIPTION":
			issueIdx = i
		case "RULE_NAME":
			ruleNameIdx = i
		}
	}

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

		// RULE_ID is required — drop rows that don't carry it so we never
		// emit an exception without a definite rule association.
		rowRuleID := 0
		if ruleIdIdx >= 0 && raw[ruleIdIdx].Valid {
			if parsed, perr := strconv.Atoi(strings.TrimSpace(raw[ruleIdIdx].String)); perr == nil {
				rowRuleID = parsed
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
			StatusID:      1, // Pending
			CreatedDate:   now,
			CreatedBy:     "system",
		}
		if assetIdx >= 0 && raw[assetIdx].Valid && raw[assetIdx].String != "" {
			ex.AssetID = raw[assetIdx].String
		}
		if issueIdx >= 0 {
			ex.IssueDescription = sqlutil.NullStr(raw[issueIdx])
		}
		// Suppress catalogID-unused warning when no usage path picks it up
		// elsewhere — keep it on the signature for caller-side context.
		_ = catalogID

		// Serialize the full row of column results as a JSON object keyed
		// by column name so RESULT_DATA captures everything RULE_CATALOG_SOURCE
		// produced (matches the EXCEPTION.RESULT_DATA OBJECT/jsonb shape).
		resultObj := make(map[string]any, len(cols))
		for i, c := range cols {
			if raw[i].Valid {
				resultObj[c] = raw[i].String
			} else {
				resultObj[c] = nil
			}
		}
		if b, err := json.Marshal(resultObj); err == nil {
			ex.ResultData = string(b)
		}
		exceptions = append(exceptions, ex)
	}

	if exceptions == nil {
		exceptions = []models.Exception{}
	}
	return exceptions, nil
}
