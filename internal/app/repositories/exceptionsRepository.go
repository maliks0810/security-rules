package repositories

import (
	"database/sql"

	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/utils/log"
)

func GetSecurityExceptions(aladdinID string) ([]models.SecurityException, error) {
	var query string
	if snowflakeSelected() {
		log.Logger.Info("exceptionsRepository: GetSecurityExceptions - using SNOWFLAKE database environment")
		query = "CALL GET_EXCEPTIONS(?)"
	} else {
		log.Logger.Info("exceptionsRepository: GetSecurityExceptions - using POSTGRES database environment")
		query = "SELECT * FROM public.\"GET_EXCEPTIONS\"($1)"
	}

	rows, err := runQuery(query, aladdinID)
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
