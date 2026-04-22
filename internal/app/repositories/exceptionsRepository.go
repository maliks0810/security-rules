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
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetSecurityExceptions - using SNOWFLAKE database environment")
		// snowflake.Query reopens the connection and retries once if the auth token has expired.
		rows, err = snowflake.Query("CALL GET_EXCEPTIONS(?)", aladdinID)
	} else {
		log.Logger.Info("exceptionsRepository: GetSecurityExceptions - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query("SELECT * FROM public.\"GET_EXCEPTIONS\"($1)", aladdinID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []models.SecurityException
	for rows.Next() {
		var (
			securityExceptionID sql.NullInt64
			ruleID              sql.NullInt64
			aladdinIDCol        sql.NullString
			runDate             sql.NullTime
			runStart            sql.NullTime
			resultTypeID        sql.NullInt64
			exceptionSourceID   sql.NullInt64
			exceptionStatusID   sql.NullInt64
			severityTypeID      sql.NullInt64
			processTypeID       sql.NullInt64
			categoryTypeID      sql.NullInt64
			assignTo            sql.NullString
			assignedBy          sql.NullString
			issueDescription    sql.NullString
			createdDate         sql.NullTime
			createdBy           sql.NullString
			modifiedDate        sql.NullTime
			modifiedBy          sql.NullString
		)

		if err := rows.Scan(
			&securityExceptionID, &ruleID, &aladdinIDCol,
			&runDate, &runStart, &resultTypeID,
			&exceptionSourceID, &exceptionStatusID, &severityTypeID,
			&processTypeID, &categoryTypeID, &assignTo,
			&assignedBy,
			&issueDescription,
			&createdDate, &createdBy, &modifiedDate, &modifiedBy,
		); err != nil {
			return nil, err
		}

		exceptions = append(exceptions, models.SecurityException{
			SecurityExceptionID: nullInt(securityExceptionID),
			RuleID:              nullInt(ruleID),
			AladdinID:           nullStr(aladdinIDCol),
			RunDate:             nullTime(runDate),
			RunStart:            nullTime(runStart),
			ResultTypeID:        nullInt(resultTypeID),
			ExceptionSourceID:   nullInt(exceptionSourceID),
			ExceptionStatusID:   nullInt(exceptionStatusID),
			SeverityTypeID:      nullInt(severityTypeID),
			ProcessTypeID:       nullInt(processTypeID),
			CategoryTypeID:      nullInt(categoryTypeID),
			AssignTo:            nullStr(assignTo),
			AssignedBy:          nullStr(assignedBy),
			IssueDescription:    nullStr(issueDescription),
			CreatedDate:         nullTime(createdDate),
			CreatedBy:           nullStr(createdBy),
			ModifiedDate:        nullTime(modifiedDate),
			ModifiedBy:          nullStr(modifiedBy),
		})
	}

	if exceptions == nil {
		exceptions = []models.SecurityException{}
	}
	return exceptions, nil
}
