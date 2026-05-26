package repositories

import (
	"database/sql"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"
	sqlutil "securityrules/security-rules/internal/utils/sql"
)

func GetDMUsers() ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("usersRepository: GetDMUsers - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL GET_DM_USERS()")
	} else {
		log.Logger.Info("usersRepository: GetDMUsers - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_DM_USERS"()`)
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
