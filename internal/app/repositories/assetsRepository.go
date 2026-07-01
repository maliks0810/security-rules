package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"
	sqlutil "securityrules/security-rules/internal/utils/sql"
)

const getAssetsQueryTimeout = 30 * time.Second

func GetAssets(exceptionType, severity, priority, ruleCatalog, ruleName, exceptionState, assignTo, ruleGroup string) ([]models.Asset, error) {
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
	ruleCatalogArg := nilIfEmpty(ruleCatalog)
	ruleNameArg := nilIfEmpty(ruleName)
	exceptionStateArg := nilIfEmpty(exceptionState)
	assignToArg := nilIfEmpty(assignTo)
	ruleGroupArg := nilIfEmpty(ruleGroup)

	ctx, cancel := context.WithTimeout(context.Background(), getAssetsQueryTimeout)
	defer cancel()
	queryStart := time.Now()

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("assetsRepository: GetAssets - using SNOWFLAKE database environment")
		// snowflake.QueryContext reopens the connection and retries once if the auth token has expired.
		rows, err = snowflake.QueryContext(ctx, "CALL SP_GET_ASSETS(?, ?, ?, ?, ?, ?, ?, ?)", typeArg, severityArg, priorityArg, ruleCatalogArg, ruleNameArg, exceptionStateArg, assignToArg, ruleGroupArg)
	} else {
		log.Logger.Info("assetsRepository: GetAssets - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.QueryContext(ctx, `SELECT * FROM public."SP_GET_ASSETS"($1, $2, $3, $4, $5, $6, $7, $8)`, typeArg, severityArg, priorityArg, ruleCatalogArg, ruleNameArg, exceptionStateArg, assignToArg, ruleGroupArg)
	}
	elapsed := time.Since(queryStart)
	if err != nil {
		log.Logger.Error(fmt.Sprintf("assetsRepository: GetAssets - query failed after %s: %v", elapsed, err))
		return nil, err
	}
	log.Logger.Info(fmt.Sprintf("assetsRepository: GetAssets - query returned in %s", elapsed))
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
