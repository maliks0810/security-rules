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

func GetSecurityExceptions(aladdinID string) ([]models.SecurityException, error) {
	var db *sql.DB
	var query string

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetSecurityExceptions - using SNOWFLAKE database environment")
		db = snowflake.DB
		query = "CALL GET_EXCEPTIONS(?)"
	} else {
		log.Logger.Info("exceptionsRepository: GetSecurityExceptions - using POSTGRES database environment")
		db = postgres.DB
		query = "SELECT * FROM public.\"GET_EXCEPTIONS\"($1)"
	}

	if db == nil {
		return nil, sql.ErrConnDone
	}

	rows, err := db.Query(query, aladdinID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []models.SecurityException
	for rows.Next() {
		var e models.SecurityException
		if err := rows.Scan(
			&e.SecurityExceptionID, &e.RuleID, &e.AladdinID,
			&e.RunDate, &e.RunStart, &e.ResultTypeID,
			&e.ExceptionSourceID, &e.ExceptionStatusID, &e.SeverityTypeID,
			&e.ProcessTypeID, &e.CategoryTypeID, &e.AssignTo,
			&e.AssignedBy,
			&e.IssueDescription,
			&e.CreatedDate, &e.CreatedBy, &e.ModifiedDate, &e.ModifiedBy,
		); err != nil {
			return nil, err
		}
		exceptions = append(exceptions, e)
	}

	if exceptions == nil {
		exceptions = []models.SecurityException{}
	}
	return exceptions, nil
}
