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

func GetSeverityTypes() ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetSeverityTypes - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL GET_SEVERITY_TYPE()")
	} else {
		log.Logger.Info("exceptionsRepository: GetSeverityTypes - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_SEVERITY_TYPE"()`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	codes := []string{}
	for rows.Next() {
		var code sql.NullString
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		codes = append(codes, sqlutil.NullStr(code))
	}
	return codes, nil
}

func GetPriorityTypes() ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetPriorityTypes - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL GET_PRIORITY_TYPE()")
	} else {
		log.Logger.Info("exceptionsRepository: GetPriorityTypes - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_PRIORITY_TYPE"()`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	codes := []string{}
	for rows.Next() {
		var code sql.NullString
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		codes = append(codes, sqlutil.NullStr(code))
	}
	return codes, nil
}

func GetExceptionStatus() ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetExceptionStatus - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL GET_EXCEPTION_STATUS()")
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptionStatus - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_EXCEPTION_STATUS"()`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	codes := []string{}
	for rows.Next() {
		var code sql.NullString
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		codes = append(codes, sqlutil.NullStr(code))
	}
	return codes, nil
}

func GetExceptionTypes() ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetExceptionTypes - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL GET_EXCEPTION_TYPE()")
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptionTypes - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_EXCEPTION_TYPE"()`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	codes := []string{}
	for rows.Next() {
		var code sql.NullString
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		codes = append(codes, sqlutil.NullStr(code))
	}
	return codes, nil
}

func GetSecurityExceptions(assetID, exceptionType, severity, priority, ruleType, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern string) ([]models.SecurityException, error) {
	var rows *sql.Rows
	var err error

	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	assetArg := nilIfEmpty(assetID)
	typeArg := nilIfEmpty(exceptionType)
	severityArg := nilIfEmpty(severity)
	priorityArg := nilIfEmpty(priority)
	ruleTypeArg := nilIfEmpty(ruleType)
	ruleNameArg := nilIfEmpty(ruleName)
	ruleGroupArg := nilIfEmpty(ruleGroup)
	exceptionStatusArg := nilIfEmpty(exceptionStatus)
	assignToArg := nilIfEmpty(assignTo)
	ruleNamePatternArg := nilIfEmpty(ruleNamePattern)

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetSecurityExceptions - using SNOWFLAKE database environment")
		// snowflake.Query reopens the connection and retries once if the auth token has expired.
		rows, err = snowflake.Query("CALL GET_EXCEPTIONS(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", assetArg, typeArg, severityArg, priorityArg, ruleTypeArg, ruleNameArg, ruleGroupArg, exceptionStatusArg, assignToArg, ruleNamePatternArg)
	} else {
		log.Logger.Info("exceptionsRepository: GetSecurityExceptions - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_EXCEPTIONS"($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, assetArg, typeArg, severityArg, priorityArg, ruleTypeArg, ruleNameArg, ruleGroupArg, exceptionStatusArg, assignToArg, ruleNamePatternArg)
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
			ruleName            sql.NullString
			priority            sql.NullString
			assetIDCol          sql.NullString
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
			exceptionStatusCode sql.NullString
		)

		if err := rows.Scan(
			&securityExceptionID, &ruleID, &ruleName, &priority, &assetIDCol,
			&runDate, &runStart, &resultTypeID,
			&exceptionSourceID, &exceptionStatusID, &severityTypeID,
			&processTypeID, &categoryTypeID, &assignTo,
			&assignedBy,
			&issueDescription,
			&createdDate, &createdBy, &modifiedDate, &modifiedBy,
			&exceptionStatusCode,
		); err != nil {
			return nil, err
		}

		exceptions = append(exceptions, models.SecurityException{
			SecurityExceptionID: sqlutil.NullInt(securityExceptionID),
			RuleID:              sqlutil.NullInt(ruleID),
			RuleName:            strings.TrimSpace(sqlutil.NullStr(ruleName)),
			Priority:            sqlutil.NullStr(priority),
			AssetID:             sqlutil.NullStr(assetIDCol),
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
			ExceptionStatus:     sqlutil.NullStr(exceptionStatusCode),
		})
	}

	if exceptions == nil {
		exceptions = []models.SecurityException{}
	}
	return exceptions, nil
}

// UpdateSecurityException updates the SECURITY_EXCEPTION row identified by
// (ASSET_ID, RULE_ID) with the values from e. Mirrors the InsertSecurityException
// argument list one-for-one.
func UpdateSecurityException(e models.SecurityException) error {
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateSecurityException - using SNOWFLAKE database environment")
		rows, err := snowflake.Query(
			"CALL UPDATE_SECURITY_EXCEPTION(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			e.SecurityExceptionID, e.RuleID,
			nilIfEmpty(e.RunDate), nilIfEmpty(e.RunStart), nilIfEmpty(e.RunEnd),
			e.ResultTypeID, e.ExceptionStatusID, e.SeverityTypeID, e.ProcessTypeID, e.CategoryTypeID,
			nil, e.AssignToDate, e.ResolveDate,
			nil, e.IssueDescription, nil,
			nilIfEmpty(e.CreatedDate), e.CreatedBy, e.ModifiedBy, nilIfEmpty(e.ModifiedDate),
			e.ExceptionSourceID, e.ExceptionTypeID, nil, nil,
			nil, nil, e.AssignedBy, nil, e.AssetID,
		)
		if err != nil {
			return err
		}
		rows.Close()
		return nil
	}
	log.Logger.Info("exceptionsRepository: UpdateSecurityException - using POSTGRES database environment")
	if postgres.DB == nil {
		return sql.ErrConnDone
	}
	_, err := postgres.DB.Exec(
		`SELECT public."UPDATE_SECURITY_EXCEPTION"($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)`,
		e.SecurityExceptionID, e.RuleID,
		nilIfEmpty(e.RunDate), nilIfEmpty(e.RunStart), nilIfEmpty(e.RunEnd),
		e.ResultTypeID, e.ExceptionStatusID, e.SeverityTypeID, e.ProcessTypeID, e.CategoryTypeID,
		nil, e.AssignToDate, e.ResolveDate,
		nil, e.IssueDescription, nil,
		nilIfEmpty(e.CreatedDate), e.CreatedBy, e.ModifiedBy, nilIfEmpty(e.ModifiedDate),
		e.ExceptionSourceID, e.ExceptionTypeID, nil, nil,
		nil, nil, e.AssignedBy, nil, e.AssetID,
	)
	return err
}

// UpdateAssignTo sets ASSIGN_TO_ID for every SECURITY_EXCEPTION row of the
// given asset, resolving the user name against DM_USER. An empty assignTo
// clears the assignment (sets ASSIGN_TO_ID to NULL).
func UpdateAssignTo(assetID, assignTo string) (int, error) {
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateAssignTo - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL UPDATE_ASSIGN_TO(?, ?)", assetID, assignTo)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("exceptionsRepository: UpdateAssignTo - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."UPDATE_ASSIGN_TO"($1, $2)`,
		assetID, assignTo,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// UpdateExceptionStatus flips a Pending SECURITY_EXCEPTION row (identified
// by ASSET_ID + RULE_ID) to Complete. No-op for rows in other statuses.
func UpdateExceptionStatus(assetID string, ruleID int) (int, error) {
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateExceptionStatus - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL UPDATE_EXCEPTION_STATUS(?, ?)", assetID, ruleID)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("exceptionsRepository: UpdateExceptionStatus - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."UPDATE_EXCEPTION_STATUS"($1, $2)`,
		assetID, ruleID,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
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
				"CALL INSERT_SECURITY_EXCEPTION(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
				e.RuleID,
				nilIfEmpty(e.RunDate), nilIfEmpty(e.RunStart), nilIfEmpty(e.RunEnd),
				e.ResultTypeID, e.ExceptionStatusID, e.SeverityTypeID, e.ProcessTypeID, e.CategoryTypeID,
				nil, e.AssignToDate, e.ResolveDate,
				nil, e.IssueDescription, nil,
				nilIfEmpty(e.CreatedDate), e.CreatedBy, e.ModifiedBy, nilIfEmpty(e.ModifiedDate),
				e.ExceptionSourceID, e.ExceptionTypeID, nil, nil,
				nil, nil, e.AssignedBy, nil, e.AssetID,
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
			`SELECT public."INSERT_SECURITY_EXCEPTION"($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`,
			e.RuleID,
			nilIfEmpty(e.RunDate), nilIfEmpty(e.RunStart), nilIfEmpty(e.RunEnd),
			e.ResultTypeID, e.ExceptionStatusID, e.SeverityTypeID, e.ProcessTypeID, e.CategoryTypeID,
			nil, e.AssignToDate, e.ResolveDate,
			nil, e.IssueDescription, nil,
			nilIfEmpty(e.CreatedDate), e.CreatedBy, e.ModifiedBy, nilIfEmpty(e.ModifiedDate),
			e.ExceptionSourceID, e.ExceptionTypeID, nil, nil,
			nil, nil, e.AssignedBy, nil, e.AssetID,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
