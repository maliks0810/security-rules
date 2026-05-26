package repositories

import (
	"database/sql"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"
	"securityrules/security-rules/internal/utils/sql"
)

func GetAssets(exceptionType, severity, priority, ruleType, ruleName, exceptionStatus, assignTo string) ([]models.Asset, error) {
	var rows *sql.Rows
	var err error

	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	typeArg := nilIfEmpty(exceptionType)
	severityArg := nilIfEmpty(severity)
	priorityArg := nilIfEmpty(priority)
	ruleTypeArg := nilIfEmpty(ruleType)
	ruleNameArg := nilIfEmpty(ruleName)
	exceptionStatusArg := nilIfEmpty(exceptionStatus)
	assignToArg := nilIfEmpty(assignTo)

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("assetsRepository: GetAssets - using SNOWFLAKE database environment")
		// snowflake.Query reopens the connection and retries once if the auth token has expired.
		rows, err = snowflake.Query("CALL GET_ASSETS(?, ?, ?, ?, ?, ?, ?)", typeArg, severityArg, priorityArg, ruleTypeArg, ruleNameArg, exceptionStatusArg, assignToArg)
	} else {
		log.Logger.Info("assetsRepository: GetAssets - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_ASSETS"($1, $2, $3, $4, $5, $6, $7)`, typeArg, severityArg, priorityArg, ruleTypeArg, ruleNameArg, exceptionStatusArg, assignToArg)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []models.Asset
	for rows.Next() {
		var (
			exceptionDate       sql.NullTime
			priority            sql.NullString
			severity            sql.NullString
			typeCol             sql.NullString
			assignTo            sql.NullString
			assetID             sql.NullString
			figi                sql.NullString
			securityDescription sql.NullString
			trader              sql.NullString
			tradingTeam         sql.NullString
			exceptionCount      sql.NullInt64
			bbgLastRefresh      sql.NullString
			allComplete         sql.NullBool
		)

		if err := rows.Scan(
			&exceptionDate, &priority, &severity, &typeCol,
			&assignTo, &assetID, &figi,
			&securityDescription, &trader, &tradingTeam,
			&exceptionCount, &bbgLastRefresh, &allComplete,
		); err != nil {
			return nil, err
		}

		assets = append(assets, models.Asset{
			ExceptionDate:       sqlutil.NullTime(exceptionDate),
			Priority:            sqlutil.NullStr(priority),
			Severity:            sqlutil.NullStr(severity),
			Type:                sqlutil.NullStr(typeCol),
			AssignTo:            sqlutil.NullStr(assignTo),
			AssetID:             sqlutil.NullStr(assetID),
			Figi:                sqlutil.NullStr(figi),
			SecurityDescription: sqlutil.NullStr(securityDescription),
			Trader:              sqlutil.NullStr(trader),
			TradingTeam:         sqlutil.NullStr(tradingTeam),
			ExceptionCount:      sqlutil.NullInt(exceptionCount),
			BbgLastRefresh:      sqlutil.NullStr(bbgLastRefresh),
			AllComplete:         allComplete.Valid && allComplete.Bool,
		})
	}

	if assets == nil {
		assets = []models.Asset{}
	}
	return assets, nil
}
