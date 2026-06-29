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

// GetExceptions calls GET_EXCEPTIONS_2, which reads from the slim EXCEPTION
// table and joins RULE + the lookup tables. Returns the new Exception
// model (23-column shape — no dummy NULLs to fit the legacy struct).
func GetExceptions(assetID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionStatus, assignTo, ruleNamePattern string) ([]models.Exception, error) {
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
	ruleCatalogArg := nilIfEmpty(ruleCatalog)
	ruleNameArg := nilIfEmpty(ruleName)
	ruleGroupArg := nilIfEmpty(ruleGroup)
	exceptionStatusArg := nilIfEmpty(exceptionStatus)
	assignToArg := nilIfEmpty(assignTo)
	ruleNamePatternArg := nilIfEmpty(ruleNamePattern)

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetExceptions - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL GET_EXCEPTIONS(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", assetArg, typeArg, severityArg, priorityArg, ruleCatalogArg, ruleNameArg, ruleGroupArg, exceptionStatusArg, assignToArg, ruleNamePatternArg)
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptions - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."GET_EXCEPTIONS"($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, assetArg, typeArg, severityArg, priorityArg, ruleCatalogArg, ruleNameArg, ruleGroupArg, exceptionStatusArg, assignToArg, ruleNamePatternArg)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []models.Exception
	for rows.Next() {
		var (
			exceptionID      sql.NullInt64
			ruleID           sql.NullInt64
			ruleNameCol      sql.NullString
			assetIDCol       sql.NullString
			exceptionDate    sql.NullTime
			exceptionTime    sql.NullTime
			idBbGlobal       sql.NullString
			statusID         sql.NullInt64
			exceptionStatus  sql.NullString
			commentID        sql.NullInt64
			issueDescription sql.NullString
			resultData       sql.NullString
			suppressDate     sql.NullTime
			assignToID       sql.NullInt64
			assignToCol      sql.NullString
			resultTypeID     sql.NullInt64
			priorityCol      sql.NullString
			severityCol      sql.NullString
			exceptionTypeCol sql.NullString
			createdDate      sql.NullTime
			createdBy        sql.NullString
			modifiedDate     sql.NullTime
			modifiedBy       sql.NullString
		)

		if err := rows.Scan(
			&exceptionID, &ruleID, &ruleNameCol, &assetIDCol,
			&exceptionDate, &exceptionTime, &idBbGlobal,
			&statusID, &exceptionStatus, &commentID,
			&issueDescription, &resultData, &suppressDate,
			&assignToID, &assignToCol, &resultTypeID,
			&priorityCol, &severityCol, &exceptionTypeCol,
			&createdDate, &createdBy, &modifiedDate, &modifiedBy,
		); err != nil {
			return nil, err
		}

		exceptions = append(exceptions, models.Exception{
			ExceptionID:      exceptionID.Int64,
			RuleID:           sqlutil.NullInt(ruleID),
			RuleName:         strings.TrimSpace(sqlutil.NullStr(ruleNameCol)),
			AssetID:          sqlutil.NullStr(assetIDCol),
			ExceptionDate:    sqlutil.NullTime(exceptionDate),
			ExceptionTime:    sqlutil.NullTime(exceptionTime),
			IdBbGlobal:       sqlutil.NullStr(idBbGlobal),
			StatusID:         sqlutil.NullInt(statusID),
			ExceptionStatus:  sqlutil.NullStr(exceptionStatus),
			CommentID:        sqlutil.NullInt(commentID),
			IssueDescription: sqlutil.NullStr(issueDescription),
			ResultData:       sqlutil.NullStr(resultData),
			SuppressDate:     sqlutil.NullTime(suppressDate),
			AssignToID:       sqlutil.NullInt(assignToID),
			AssignTo:         sqlutil.NullStr(assignToCol),
			ResultTypeID:     sqlutil.NullInt(resultTypeID),
			Priority:         sqlutil.NullStr(priorityCol),
			Severity:         sqlutil.NullStr(severityCol),
			ExceptionType:    sqlutil.NullStr(exceptionTypeCol),
			CreatedDate:      sqlutil.NullTime(createdDate),
			CreatedBy:        sqlutil.NullStr(createdBy),
			ModifiedDate:     sqlutil.NullTime(modifiedDate),
			ModifiedBy:       sqlutil.NullStr(modifiedBy),
		})
	}

	if exceptions == nil {
		exceptions = []models.Exception{}
	}
	return exceptions, nil
}

// UpdateAssignTo sets ASSIGN_TO_ID for every EXCEPTION row of the given
// asset, resolving the user name against DM_USER. An empty assignTo
// clears the assignment (sets ASSIGN_TO_ID to NULL). Targets the slim
// EXCEPTION table via the new UPDATE_ASSIGN_TO SP.
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

// UpdateExceptionStatus stamps MODIFIED_DATE / MODIFIED_BY on every EXCEPTION
// row matching (ASSET_ID, RULE_ID). When complete is true, also flips
// STATUS_ID to 4 (Complete). When false, status is left untouched — the
// "touch" case for ExecuteRules where a rule re-fires for an existing
// (RuleID, AssetID).
func UpdateExceptionStatus(assetID string, ruleID int, complete bool) (int, error) {
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateExceptionStatus - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL UPDATE_EXCEPTION_STATUS(?, ?, ?)", assetID, ruleID, complete)
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
		`SELECT public."UPDATE_EXCEPTION_STATUS"($1, $2, $3)`,
		assetID, ruleID, complete,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// InsertExceptions writes each row to the slim EXCEPTION table via the
// 12-param INSERT_EXCEPTION SP. ExceptionDate fills EXCEPTION_DATE; when
// blank, ExceptionTime is used and the DB casts it to DATE. ExceptionTime
// flows into EXCEPTION_TIME (full timestamp). ResultData is the JSON
// column-array of results pulled from RULE_CATALOG_SOURCE — SF wraps it
// in PARSE_JSON so it binds to the OBJECT-typed param; PG casts to json.
func InsertExceptions(exceptions []models.Exception) error {
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	nilIfZero := func(n int) any {
		if n == 0 {
			return nil
		}
		return n
	}
	dateOrTime := func(e models.Exception) any {
		if e.ExceptionDate != "" {
			return e.ExceptionDate
		}
		return nilIfEmpty(e.ExceptionTime)
	}

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: InsertExceptions - using SNOWFLAKE database environment")
		for _, e := range exceptions {
			rows, err := snowflake.Query(
				"CALL INSERT_EXCEPTION(?,?,?,?,?,?,?,PARSE_JSON(?),?,?,?,?)",
				e.RuleID,
				e.AssetID,
				dateOrTime(e),
				nilIfEmpty(e.IdBbGlobal),
				e.StatusID,
				nilIfEmpty(e.ExceptionTime),
				nilIfEmpty(e.IssueDescription),
				nilIfEmpty(e.ResultData),
				nilIfZero(e.AssignToID),
				e.ResultTypeID,
				nilIfEmpty(e.CreatedDate),
				e.CreatedBy,
			)
			if err != nil {
				return err
			}
			rows.Close()
		}
		return nil
	}

	log.Logger.Info("exceptionsRepository: InsertExceptions - using POSTGRES database environment")
	if postgres.DB == nil {
		return sql.ErrConnDone
	}

	for _, e := range exceptions {
		_, err := postgres.DB.Exec(
			`SELECT public."INSERT_EXCEPTION"($1,$2,$3,$4,$5,$6,$7,$8::json,$9,$10,$11,$12)`,
			e.RuleID,
			e.AssetID,
			dateOrTime(e),
			nilIfEmpty(e.IdBbGlobal),
			e.StatusID,
			nilIfEmpty(e.ExceptionTime),
			nilIfEmpty(e.IssueDescription),
			nilIfEmpty(e.ResultData),
			nilIfZero(e.AssignToID),
			e.ResultTypeID,
			nilIfEmpty(e.CreatedDate),
			e.CreatedBy,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateExceptions updates each EXCEPTION row identified by (ASSET_ID, RULE_ID)
// via UPDATE_EXCEPTION. STATUS_ID is force-reset to 1 (Pending) inside the SP
// regardless of what the caller passes. A NULL ResultData preserves the
// existing column via COALESCE inside the SP — same pattern as ID_BB_GLOBAL
// and ASSIGN_TO_ID.
func UpdateExceptions(exceptions []models.Exception) error {
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	nilIfZero := func(n int) any {
		if n == 0 {
			return nil
		}
		return n
	}
	dateOrTime := func(e models.Exception) any {
		if e.ExceptionDate != "" {
			return e.ExceptionDate
		}
		return nilIfEmpty(e.ExceptionTime)
	}

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateExceptions - using SNOWFLAKE database environment")
		for _, e := range exceptions {
			rows, err := snowflake.Query(
				"CALL UPDATE_EXCEPTION(?,?,?,?,?,?,?,PARSE_JSON(?),?,?,?,?)",
				e.RuleID,
				e.AssetID,
				dateOrTime(e),
				nilIfEmpty(e.IdBbGlobal),
				e.StatusID,
				nilIfEmpty(e.ExceptionTime),
				nilIfEmpty(e.IssueDescription),
				nilIfEmpty(e.ResultData),
				nilIfZero(e.AssignToID),
				e.ResultTypeID,
				nilIfEmpty(e.CreatedDate),
				e.CreatedBy,
			)
			if err != nil {
				return err
			}
			rows.Close()
		}
		return nil
	}

	log.Logger.Info("exceptionsRepository: UpdateExceptions - using POSTGRES database environment")
	if postgres.DB == nil {
		return sql.ErrConnDone
	}

	for _, e := range exceptions {
		_, err := postgres.DB.Exec(
			`SELECT public."UPDATE_EXCEPTION"($1,$2,$3,$4,$5,$6,$7,$8::json,$9,$10,$11,$12)`,
			e.RuleID,
			e.AssetID,
			dateOrTime(e),
			nilIfEmpty(e.IdBbGlobal),
			e.StatusID,
			nilIfEmpty(e.ExceptionTime),
			nilIfEmpty(e.IssueDescription),
			nilIfEmpty(e.ResultData),
			nilIfZero(e.AssignToID),
			e.ResultTypeID,
			nilIfEmpty(e.CreatedDate),
			e.CreatedBy,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
