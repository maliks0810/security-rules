package repositories

import (
	"database/sql"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"
)

func GetAssets() ([]models.Asset, error) {
	var db *sql.DB
	var query string

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("assetsRepository: GetAssets - using SNOWFLAKE database environment")
		db = snowflake.DB
		query = "CALL GET_ASSETS()"
	} else {
		log.Logger.Info("assetsRepository: GetAssets - using POSTGRES database environment")
		db = postgres.DB
		query = "SELECT * FROM public.\"GET_ASSETS\"()"
	}

	if db == nil {
		return nil, sql.ErrConnDone
	}

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []models.Asset
	for rows.Next() {
		var (
			exceptionDate       sql.NullTime
			priority            sql.NullString
			typeCol             sql.NullString
			assignTo            sql.NullString
			assetID             sql.NullString
			figi                sql.NullString
			securityDescription sql.NullString
			trader              sql.NullString
			tradingTeam         sql.NullString
			exceptionCount      sql.NullInt64
			bbgLastRefresh      sql.NullString
		)

		if err := rows.Scan(
			&exceptionDate, &priority, &typeCol,
			&assignTo, &assetID, &figi,
			&securityDescription, &trader, &tradingTeam,
			&exceptionCount, &bbgLastRefresh,
		); err != nil {
			return nil, err
		}

		assets = append(assets, models.Asset{
			ExceptionDate:       nullTime(exceptionDate),
			Priority:            nullStr(priority),
			Type:                nullStr(typeCol),
			AssignTo:            nullStr(assignTo),
			AssetID:             nullStr(assetID),
			Figi:                nullStr(figi),
			SecurityDescription: nullStr(securityDescription),
			Trader:              nullStr(trader),
			TradingTeam:         nullStr(tradingTeam),
			ExceptionCount:      nullInt(exceptionCount),
			BbgLastRefresh:      nullStr(bbgLastRefresh),
		})
	}

	if assets == nil {
		assets = []models.Asset{}
	}
	return assets, nil
}
