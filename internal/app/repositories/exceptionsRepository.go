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
			ruleName            sql.NullString
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
			&securityExceptionID, &ruleName, &aladdinIDCol,
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
			SecurityExceptionID: sqlutil.NullInt(securityExceptionID),
			RuleName:            sqlutil.NullStr(ruleName),
			AladdinID:           sqlutil.NullStr(aladdinIDCol),
			RunDate:             sqlutil.NullTime(runDate),
			RunStart:            sqlutil.NullTime(runStart),
			ResultTypeID:        sqlutil.NullInt(resultTypeID),
			ExceptionSourceID:   sqlutil.NullInt(exceptionSourceID),
			ExceptionStatusID:   sqlutil.NullInt(exceptionStatusID),
			SeverityTypeID:      sqlutil.NullInt(severityTypeID),
			ProcessTypeID:       sqlutil.NullInt(processTypeID),
			CategoryTypeID:      sqlutil.NullInt(categoryTypeID),
			AssignTo:            sqlutil.NullStr(assignTo),
			AssignedBy:          sqlutil.NullStr(assignedBy),
			IssueDescription:    sqlutil.NullStr(issueDescription),
			CreatedDate:         sqlutil.NullTime(createdDate),
			CreatedBy:           sqlutil.NullStr(createdBy),
			ModifiedDate:        sqlutil.NullTime(modifiedDate),
			ModifiedBy:          sqlutil.NullStr(modifiedBy),
		})
	}

	if exceptions == nil {
		exceptions = []models.SecurityException{}
	}
	return exceptions, nil
}

func InsertSecurityExceptions(exceptions []models.SecurityException) error {
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: InsertSecurityExceptions - using SNOWFLAKE database environment")
		for _, e := range exceptions {
			rows, err := snowflake.Query(
				"CALL INSERT_SECURITY_EXCEPTION(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
				e.SecurityExceptionID, nilIfEmpty(e.RuleName),
				nilIfEmpty(e.RunDate), nilIfEmpty(e.RunStart), nil,
				e.ResultTypeID, e.ExceptionStatusID, e.SeverityTypeID, e.ProcessTypeID, e.CategoryTypeID,
				e.AssignTo, e.AssignToDate, e.ResolveDate,
				nil, e.IssueDescription, nil,
				nilIfEmpty(e.CreatedDate), e.CreatedBy, e.ModifiedBy, nilIfEmpty(e.ModifiedDate),
				e.ExceptionSourceID, nil, nil, nil,
				nil, nil, e.AssignedBy, nil, e.AladdinID,
			)
			if err != nil {
				return err
			}
			rows.Close()
		}
		return nil
	}

	log.Logger.Info("exceptionsRepository: InsertSecurityExceptions - using POSTGRES database environment")
	if postgres.DB == nil {
		return sql.ErrConnDone
	}

	for _, e := range exceptions {
		_, err := postgres.DB.Exec(
			`SELECT public."INSERT_SECURITY_EXCEPTION"($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)`,
			e.SecurityExceptionID, nilIfEmpty(e.RuleName),
			nilIfEmpty(e.RunDate), nilIfEmpty(e.RunStart), nil,
			e.ResultTypeID, e.ExceptionStatusID, e.SeverityTypeID, e.ProcessTypeID, e.CategoryTypeID,
			e.AssignTo, e.AssignToDate, e.ResolveDate,
			nil, e.IssueDescription, nil,
			nilIfEmpty(e.CreatedDate), e.CreatedBy, e.ModifiedBy, nilIfEmpty(e.ModifiedDate),
			e.ExceptionSourceID, nil, nil, nil,
			nil, nil, e.AssignedBy, nil, e.AladdinID,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
