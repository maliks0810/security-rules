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

func GetRuleTypes(ruleGroup string) ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRuleTypes - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL GET_RULE_TYPES(?)", ruleGroup)
	} else {
		log.Logger.Info("rulesRepository: GetRuleTypes - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_RULE_TYPES"($1)`, ruleGroup)
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

func GetRules(processType, ruleType string) ([]models.Rule, error) {
	var rows *sql.Rows
	var err error

	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	ruleTypeArg := nilIfEmpty(ruleType)

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: GetRules - using SNOWFLAKE database environment")
		// snowflake.Query reopens the connection and retries once if the auth token has expired.
		rows, err = snowflake.Query("CALL GET_RULES(?, ?)", processType, ruleTypeArg)
	} else {
		log.Logger.Info("rulesRepository: GetRules - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_RULES"($1, $2)`, processType, ruleTypeArg)
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

func ExecuteRule(storedProcedure string, ruleID int, assetID string, idBbGlobal ...string) ([]models.SecurityException, error) {
	var bbg any = nil
	if len(idBbGlobal) > 0 && idBbGlobal[0] != "" {
		bbg = idBbGlobal[0]
	}

	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("rulesRepository: ExecuteRule - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL "+storedProcedure+"(?, ?)", assetID, bbg)
	} else {
		log.Logger.Info("rulesRepository: ExecuteRule - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."`+storedProcedure+`"($1, $2)`, assetID, bbg)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	assetIdx, issueIdx := -1, -1
	for i, c := range cols {
		switch strings.ToUpper(c) {
		case "ASSET_ID", "ALADDIN_ID":
			assetIdx = i
		case "ISSUE_DESCRIPTION":
			issueIdx = i
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

		ex := models.SecurityException{
			RuleID:   ruleID,
			RuleName: storedProcedure,
			AssetID:  assetID,
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
