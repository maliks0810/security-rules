package repositories

import (
	"database/sql"
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
			ruleID      sql.NullInt64
			ruleName    sql.NullString
			ruleCommand sql.NullString
			environment sql.NullString
		)

		if err := rows.Scan(&ruleID, &ruleName, &ruleCommand, &environment); err != nil {
			return nil, err
		}

		rules = append(rules, models.Rule{
			RuleID:      sqlutil.NullInt(ruleID),
			RuleName:    sqlutil.NullStr(ruleName),
			RuleCommand: sqlutil.NullStr(ruleCommand),
			Environment: sqlutil.NullStr(environment),
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

func ExecuteSecurityRule(ruleCommand string, ruleID int, ruleName string, assetID string, idBbGlobal ...string) ([]models.SecurityException, error) {
	runStart := time.Now().UTC().Format(time.RFC3339)

	bbg := ""
	if len(idBbGlobal) > 0 {
		bbg = idBbGlobal[0]
	}
	resolvedCommand := resolveRuleCommand(ruleCommand, assetID, bbg)

	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: ExecuteSecurityRule - using SNOWFLAKE database environment")
		rows, err = snowflake.Query(resolvedCommand)
	} else {
		log.Logger.Info("rulesRepository: ExecuteSecurityRule - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(resolvedCommand)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	runEnd := time.Now().UTC().Format(time.RFC3339)

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	assetIdx, issueIdx, ruleNameIdx := -1, -1, -1
	for i, c := range cols {
		switch strings.ToUpper(c) {
		case "ASSET_ID", "ALADDIN_ID":
			assetIdx = i
		case "ISSUE_DESCRIPTION":
			issueIdx = i
		case "RULE_NAME":
			ruleNameIdx = i
		}
	}

	var exceptions []models.SecurityException
	for rows.Next() {
		raw := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}

		// If the result set carries a RULE_NAME column, only attribute the
		// row to this rule when it matches. Lets one catalog source feed
		// multiple rules from a single query.
		if ruleNameIdx >= 0 && raw[ruleNameIdx].Valid && raw[ruleNameIdx].String != ruleName {
			continue
		}

		idBb := ""
		if len(idBbGlobal) > 0 {
			idBb = idBbGlobal[0]
		}
		ex := models.SecurityException{
			RuleID:            ruleID,
			RuleName:          ruleName,
			AssetID:           assetID,
			IdBbGlobal:        idBb,
			RunStart:          runStart,
			RunDate:           runEnd,
			RunEnd:            runEnd,
			ExceptionStatusID: 1, // Pending
			SeverityTypeID:    1, // High (default until rule-specific severity wired)
			CategoryTypeID:    1, // Trading
			ProcessTypeID:     1,
			ExceptionTypeID:   1, // Security Setup
		}
		if assetIdx >= 0 && raw[assetIdx].Valid && raw[assetIdx].String != "" {
			ex.AssetID = raw[assetIdx].String
		}
		if issueIdx >= 0 {
			ex.IssueDescription = sqlutil.NullStr(raw[issueIdx])
		}
		exceptions = append(exceptions, ex)
	}

	if exceptions == nil {
		exceptions = []models.SecurityException{}
	}
	return exceptions, nil
}

// ExecuteRule runs the rule's RULE_CATALOG_SOURCE command verbatim and
// builds new-model Exception rows from the result set (one per matching
// record). The command is expected to return ASSET_ID/ALADDIN_ID and
// ISSUE_DESCRIPTION columns; an optional RULE_NAME column, if present,
// scopes rows to the rule whose name matches (so one catalog source can
// feed multiple rules from a single query).
func ExecuteRule(ruleCommand string, ruleID int, ruleName string, assetID string, idBbGlobal ...string) ([]models.Exception, error) {
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

	assetIdx, issueIdx, ruleNameIdx := -1, -1, -1
	for i, c := range cols {
		switch strings.ToUpper(c) {
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

		if ruleNameIdx >= 0 && raw[ruleNameIdx].Valid && raw[ruleNameIdx].String != ruleName {
			continue
		}

		idBb := ""
		if len(idBbGlobal) > 0 {
			idBb = idBbGlobal[0]
		}
		ex := models.Exception{
			RuleID:        ruleID,
			RuleName:      ruleName,
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
		exceptions = append(exceptions, ex)
	}

	if exceptions == nil {
		exceptions = []models.Exception{}
	}
	return exceptions, nil
}
