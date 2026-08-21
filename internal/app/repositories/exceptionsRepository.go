package repositories

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"
	sqlutil "securityrules/security-rules/internal/utils/sql"
)

// Package-level cache for ExpireSuppressDates so it runs at most once
// per UTC calendar day per process. SUPPRESS_DATE is DATE-granular —
// running the sweep more than once a day is pure UPDATE cost. The
// mutex protects lastExpireDate; time.Time zero value means "never
// ran", which forces the first call in the process to fire.
var (
	lastExpireDateMu sync.Mutex
	lastExpireDate   time.Time
)

// maybeExpireSuppressDates fires SP_EXPIRE_SUPPRESS_DATES at most once
// per UTC calendar day per process. All GetExceptions callers route
// through this instead of calling ExpireSuppressDates directly, so
// the underlying UPDATE runs on the first LHS tree click of the day
// and is skipped for every subsequent click / filter change / mode
// toggle. Failures don't advance lastExpireDate — the next call
// retries. ExpireSuppressDates itself stays exported for cron /
// manual callers that want to force a sweep.
func maybeExpireSuppressDates() {
	lastExpireDateMu.Lock()
	defer lastExpireDateMu.Unlock()

	todayUTC := time.Now().UTC().Truncate(24 * time.Hour)
	if !lastExpireDate.Before(todayUTC) {
		return
	}

	n, err := ExpireSuppressDates()
	if err != nil {
		log.Logger.Warn(fmt.Sprintf("exceptionsRepository: ExpireSuppressDates failed, continuing: %v", err))
		return
	}
	lastExpireDate = todayUTC
	if n > 0 {
		log.Logger.Info(fmt.Sprintf("exceptionsRepository: ExpireSuppressDates - reverted %d row(s) to New", n))
	}
}

// GetExceptionCountsByGroup returns one row per RULE_GROUP with the
// count of matching EXCEPTION rows. Collapses the count panel's old
// N-call fanout (fetchExceptions per group) into a single call.
// Empty-string filter args map to the SP's "no filter" branch.
//
// exceptionDate is NOT one of those — the SP equality-matches it, so an
// empty value yields zero rows rather than every date. The handler
// rejects an empty exception_date before reaching here, matching
// GetExceptions / GetExceptionsHist.
func GetExceptionCountsByGroup(exceptionType, severity, priority, exceptionState, assignTo, exceptionDate string) ([]models.GroupCount, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetExceptionCountsByGroup - using SNOWFLAKE database environment")
		rows, err = snowflake.Query(
			"CALL SP_GET_EXCEPTION_COUNTS_BY_GROUP(?, ?, ?, ?, ?, ?)",
			exceptionType, severity, priority, exceptionState, assignTo, exceptionDate,
		)
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptionCountsByGroup - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(
			`SELECT * FROM public."SP_GET_EXCEPTION_COUNTS_BY_GROUP"($1, $2, $3, $4, $5, $6::date)`,
			exceptionType, severity, priority, exceptionState, assignTo, exceptionDate,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.GroupCount{}
	for rows.Next() {
		var group sql.NullString
		var count sql.NullInt64
		if err := rows.Scan(&group, &count); err != nil {
			return nil, err
		}
		out = append(out, models.GroupCount{
			RuleGroup: sqlutil.NullStr(group),
			Count:     int(count.Int64),
		})
	}
	return out, nil
}

func GetSeverityTypes() ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetSeverityTypes - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL SP_GET_SEVERITY_TYPE()")
	} else {
		log.Logger.Info("exceptionsRepository: GetSeverityTypes - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_SEVERITY_TYPE"()`)
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
		rows, err = snowflake.Query("CALL SP_GET_PRIORITY_TYPE()")
	} else {
		log.Logger.Info("exceptionsRepository: GetPriorityTypes - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_PRIORITY_TYPE"()`)
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

// UpdateExceptionStatus flips STATUS_ID on a single EXCEPTION row keyed
// by EXCEPTION_ID, resolving the status name against EXCEPTION_STATUS.
// Optional comments + suppressDate let the caller bundle a pending
// COMMENTS / SUPPRESS_DATE value the operator just typed but hasn't
// committed via the per-cell endpoints yet — the SP applies them
// atomically inside the same UPDATE so the "blank" guards check the
// effective (passed) value instead of the stale DB value.
//
// Empty string on either param → treated as "leave alone" (bound as
// SQL NULL); the SP's COALESCE preserves the existing DB value. Only
// pass through what the frontend actually collected.
//
// Returns the number of rows updated (0 if the exception_id doesn't
// exist, the status name doesn't resolve, or a guard fired).
func UpdateExceptionStatus(exceptionID int64, statusName, comments, suppressDate string) (int, error) {
	var commentsArg any
	if comments == "" {
		commentsArg = nil
	} else {
		commentsArg = comments
	}
	var suppressArg any
	if suppressDate == "" {
		suppressArg = nil
	} else {
		suppressArg = suppressDate
	}
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateExceptionStatus - using SNOWFLAKE database environment")
		rows, err := snowflake.Query(
			"CALL SP_UPDATE_EXCEPTION_STATUS(?, ?, ?, ?)",
			exceptionID, statusName, commentsArg, suppressArg,
		)
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
		`SELECT public."SP_UPDATE_EXCEPTION_STATUS"($1, $2, $3, $4)`,
		exceptionID, statusName, commentsArg, suppressArg,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ExpireSuppressDates reverts every EXCEPTION whose SUPPRESS_DATE has
// already passed back to STATUS_ID=1 ("New") and clears SUPPRESS_DATE.
// Returns the number of rows expired. Intended to be called at the top of
// GetExceptions as a best-effort cleanup — the caller should log-and-
// continue on error so a stale-row sweep failure doesn't blank the grid.
func ExpireSuppressDates() (int, error) {
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		rows, err := snowflake.Query("CALL SP_EXPIRE_SUPPRESS_DATES()")
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	if err := postgres.DB.QueryRow(
		`SELECT public."SP_EXPIRE_SUPPRESS_DATES"()`,
	).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// UpdateExceptionAssignTo sets EXCEPTION.ASSIGN_TO_ID on a single row keyed
// by EXCEPTION_ID, resolving the assign_to name against DM_USER. Empty
// assignTo clears the assignment. Returns the number of rows updated.
// Distinct from UpdateAssignTo which mutates every row for an asset via
// the Assets grid path.
func UpdateExceptionAssignTo(exceptionID int64, assignTo string) (int, error) {
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateExceptionAssignTo - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_UPDATE_EXCEPTION_ASSIGN_TO(?, ?)", exceptionID, assignTo)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("exceptionsRepository: UpdateExceptionAssignTo - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_UPDATE_EXCEPTION_ASSIGN_TO"($1, $2)`,
		exceptionID, assignTo,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// UpdateExceptionSuppressDate sets EXCEPTION.SUPPRESS_DATE on a single row
// keyed by EXCEPTION_ID. Empty suppressDate ("") is passed as SQL NULL so
// the cell is cleared; otherwise the parsed YYYY-MM-DD value is stored.
// Returns the number of rows updated.
func UpdateExceptionSuppressDate(exceptionID int64, suppressDate string) (int, error) {
	var arg any
	if suppressDate == "" {
		arg = nil
	} else {
		arg = suppressDate
	}
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateExceptionSuppressDate - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_UPDATE_EXCEPTION_SUPPRESS_DATE(?, ?)", exceptionID, arg)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("exceptionsRepository: UpdateExceptionSuppressDate - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_UPDATE_EXCEPTION_SUPPRESS_DATE"($1, $2)`,
		exceptionID, arg,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// UpdateExceptionComments sets EXCEPTION.COMMENTS on a single row keyed by
// EXCEPTION_ID. Empty p_comments is stored as-is (blank string clears the
// cell). Returns the number of rows updated.
func UpdateExceptionComments(exceptionID int64, comments string) (int, error) {
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateExceptionComments - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_UPDATE_EXCEPTION_COMMENTS(?, ?)", exceptionID, comments)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("exceptionsRepository: UpdateExceptionComments - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_UPDATE_EXCEPTION_COMMENTS"($1, $2)`,
		exceptionID, comments,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func GetExceptionStatus() ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetExceptionStatus - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL SP_GET_EXCEPTION_STATUS()")
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptionStatus - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_EXCEPTION_STATUS"()`)
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

func GetExceptionState() ([]string, error) {
	var rows *sql.Rows
	var err error

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetExceptionState - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL SP_GET_EXCEPTION_STATE()")
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptionState - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_EXCEPTION_STATE"()`)
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
		rows, err = snowflake.Query("CALL SP_GET_EXCEPTION_TYPE()")
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptionTypes - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_EXCEPTION_TYPE"()`)
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
// model (23-column shape â€” no dummy NULLs to fit the legacy struct).
func GetExceptions(assetID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern, exceptionDate string) ([]models.Exception, error) {
	// Once-per-day sweep: any Suppress row whose SUPPRESS_DATE has
	// passed reverts to STATUS_ID=1 (New) with a null SUPPRESS_DATE.
	// Guarded by lastExpireDate so this only fires the first
	// GetExceptions call of each UTC day per process instead of on
	// every LHS tree click. SUPPRESS_DATE is DATE-granular, so
	// re-running mid-day would just re-scan-then-no-op.
	maybeExpireSuppressDates()

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
	exceptionStateArg := nilIfEmpty(exceptionState)
	assignToArg := nilIfEmpty(assignTo)
	ruleNamePatternArg := nilIfEmpty(ruleNamePattern)

	// SP_GET_EXCEPTIONS no longer defaults P_EXCEPTION_DATE to today
	// (the WHERE clause is a plain equality, not COALESCE-with-fallback),
	// so the repository always resolves the target date up front and
	// passes it explicitly.
	//
	// Priority:
	//   1. explicit exceptionDate argument (frontend passes histDates[0],
	//      the max EXCEPTION_DATE the server actually has data for). This
	//      keeps the live grid correct on days when today's ETL hasn't
	//      run yet (holidays, delayed runs) — the LHS dropdown already
	//      surfaces the true latest date, so aligning the query with it
	//      is the natural fix.
	//   2. today (UTC) as a fallback for first-render before the LHS
	//      dropdown has resolved, and for legacy callers that don't
	//      pass an explicit date.
	targetDate := strings.TrimSpace(exceptionDate)
	if targetDate == "" {
		targetDate = time.Now().UTC().Format("2006-01-02")
	}

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetExceptions - using SNOWFLAKE database environment")
		// SELECT * FROM TABLE(UDF_GET_EXCEPTIONS(...)) invokes the
		// table-valued SQL UDF that replaces SP_GET_EXCEPTIONS. UDFs
		// inline into the query plan (no per-call SP compilation, so
		// predicate push-down + partition pruning work across the
		// boundary). If it ever misbehaves, swap this line back to
		// `CALL SP_GET_EXCEPTIONS(...)` — the SP is kept in place
		// for exactly this rollback.
		//
		// TO_DATE(?) around the last param: Snowflake UDF argument
		// typing is stricter than SP CALL. The string "YYYY-MM-DD"
		// coerces to DATE inside a SP CALL context but not inside a
		// SELECT-invoked UDF, which reports "invalid argument types
		// for function UDF_GET_EXCEPTIONS" without the explicit cast.
		rows, err = snowflake.Query(
			"SELECT * FROM TABLE(UDF_GET_EXCEPTIONS(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TO_DATE(?)))",
			assetArg, typeArg, severityArg, priorityArg, ruleCatalogArg, ruleNameArg, ruleGroupArg, exceptionStateArg, assignToArg, ruleNamePatternArg, targetDate,
		)
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptions - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_EXCEPTIONS"($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, assetArg, typeArg, severityArg, priorityArg, ruleCatalogArg, ruleNameArg, ruleGroupArg, exceptionStateArg, assignToArg, ruleNamePatternArg, targetDate)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanExceptionRows(rows)
}

// scanExceptionRows walks the sql.Rows returned by SP_GET_EXCEPTIONS or
// SP_GET_EXCEPTIONS_HIST (same 25-column shape) into models.Exception
// values. Extracted so both the live and history paths share one scan.
func scanExceptionRows(rows *sql.Rows) ([]models.Exception, error) {
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
			stateID          sql.NullInt64
			exceptionState   sql.NullString
			statusID         sql.NullInt64
			exceptionStatus  sql.NullString
			commentsCol      sql.NullString
			issueDescription sql.NullString
			resultData       sql.NullString
			suppressDate     sql.NullTime
			openDate         sql.NullTime
			closeDate        sql.NullTime
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
			&stateID, &exceptionState,
			&statusID, &exceptionStatus,
			&commentsCol,
			&issueDescription, &resultData, &suppressDate,
			&openDate, &closeDate,
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
			StateID:          sqlutil.NullInt(stateID),
			ExceptionState:   sqlutil.NullStr(exceptionState),
			StatusID:         sqlutil.NullInt(statusID),
			ExceptionStatus:  sqlutil.NullStr(exceptionStatus),
			Comments:         sqlutil.NullStr(commentsCol),
			IssueDescription: sqlutil.NullStr(issueDescription),
			ResultData:       sqlutil.NullStr(resultData),
			SuppressDate:     sqlutil.NullTime(suppressDate),
			OpenDate:         sqlutil.NullTime(openDate),
			CloseDate:        sqlutil.NullTime(closeDate),
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

// GetExceptionsHist calls SP_GET_EXCEPTIONS_HIST for a specific
// EXCEPTION_DATE and returns the rows from that day's LATEST BATCH_ID
// within the caller's rule/catalog/group scope. Column shape mirrors
// SP_GET_EXCEPTIONS so scanExceptionRows handles both.
func GetExceptionsHist(exceptionDate, assetID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern string) ([]models.Exception, error) {
	if exceptionDate == "" {
		return nil, sql.ErrNoRows
	}
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	dateArg := exceptionDate
	assetArg := nilIfEmpty(assetID)
	typeArg := nilIfEmpty(exceptionType)
	severityArg := nilIfEmpty(severity)
	priorityArg := nilIfEmpty(priority)
	ruleCatalogArg := nilIfEmpty(ruleCatalog)
	ruleNameArg := nilIfEmpty(ruleName)
	ruleGroupArg := nilIfEmpty(ruleGroup)
	exceptionStateArg := nilIfEmpty(exceptionState)
	assignToArg := nilIfEmpty(assignTo)
	ruleNamePatternArg := nilIfEmpty(ruleNamePattern)

	var rows *sql.Rows
	var err error
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetExceptionsHist - using SNOWFLAKE database environment")
		rows, err = snowflake.Query(
			"CALL SP_GET_EXCEPTIONS_HIST(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			dateArg, assetArg, typeArg, severityArg, priorityArg,
			ruleCatalogArg, ruleNameArg, ruleGroupArg,
			exceptionStateArg, assignToArg, ruleNamePatternArg,
		)
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptionsHist - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(
			`SELECT * FROM public."SP_GET_EXCEPTIONS_HIST"($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			dateArg, assetArg, typeArg, severityArg, priorityArg,
			ruleCatalogArg, ruleNameArg, ruleGroupArg,
			exceptionStateArg, assignToArg, ruleNamePatternArg,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanExceptionRows(rows)
}

// GetExceptionHistDates returns the distinct EXCEPTION_DATEs present in
// EXCEPTION_HIST within the last 60 days (UTC), most recent first, as
// ISO YYYY-MM-DD strings. Powers the "DQM Date" dropdown.
func GetExceptionHistDates() ([]string, error) {
	var rows *sql.Rows
	var err error
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: GetExceptionHistDates - using SNOWFLAKE database environment")
		rows, err = snowflake.Query("CALL SP_GET_EXCEPTION_HIST_DATES()")
	} else {
		log.Logger.Info("exceptionsRepository: GetExceptionHistDates - using POSTGRES database environment")
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		rows, err = postgres.DB.Query(`SELECT * FROM public."SP_GET_EXCEPTION_HIST_DATES"()`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dates := []string{}
	for rows.Next() {
		var t sql.NullTime
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		if t.Valid {
			dates = append(dates, t.Time.Format("2006-01-02"))
		}
	}
	return dates, nil
}

// UpdateAssignTo sets ASSIGN_TO_ID for every EXCEPTION row of the given
// asset, resolving the user name against DM_USER. An empty assignTo
// clears the assignment (sets ASSIGN_TO_ID to NULL). Targets the slim
// EXCEPTION table via the new UPDATE_ASSIGN_TO SP.
func UpdateAssignTo(assetID, assignTo string) (int, error) {
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateAssignTo - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_UPDATE_ASSIGN_TO(?, ?)", assetID, assignTo)
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
		`SELECT public."SP_UPDATE_ASSIGN_TO"($1, $2)`,
		assetID, assignTo,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// joinExceptionIDs renders a selection of EXCEPTION_IDs as the plain
// comma-separated string both bulk SPs split on. Digits only, so there
// is no delimiter conflict and no quoting to get wrong. An empty or nil
// slice yields "", which both SPs treat as "nothing selected" and
// answer with a zero-row no-op — the callers reject that case earlier
// so it never reaches the database in practice.
func joinExceptionIDs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

// UpdateBulkAssign hands (exception-ids, rule-names, assign-to,
// is-permanent) to SP_UPDATE_BULK_ASSIGN.
//
// exceptionIDs is the target set: EXCEPTION.ASSIGN_TO_ID is updated for
// exactly those rows — the ones ticked in the grid's bulk-selection
// column — and for nothing else. It replaced rule-name targeting, which
// swept in every exception of a rule rather than the picked ones.
//
// ruleNames is NOT a target set. It is the distinct set of rules the
// selected rows belong to, derived client-side, and it drives only the
// PERMANENT rule-level write:
//   false → nothing. Only the selected EXCEPTION rows change.
//   true  → UPDATE RULE.ASSIGN_TO_ID for every named rule so future
//           exceptions inherit the assignee, and purge stale override
//           rows for them.
// The false branch used to INSERT a RULE_ASSIGN_OVERRIDE row per rule.
// That reassigned every UNTICKED exception of the rule that had no
// assignee of its own, because SP_GET_EXCEPTIONS displays
// COALESCE(EXCEPTION.ASSIGN_TO_ID, rao.ASSIGN_TO_ID, RULE.ASSIGN_TO_ID)
// — the grid reported "2 assigned" and showed 3.
// An empty ruleNames slice skips the permanent write entirely and still
// reassigns the selected exceptions.
//
// Both lists travel as plain comma-separated strings — the SP splits on
// ',' — matching the delimiter contract already used here: rule names
// are all-caps underscored (see dqm_seed_data.sql) and ids are digits,
// so neither can contain a comma. An empty exceptionIDs slice or an
// empty assignTo resolves to a zero-row no-op inside the SP. Returns
// the number of EXCEPTION rows updated.
func UpdateBulkAssign(exceptionIDs []int64, ruleNames []string, assignTo string, isPermanent bool) (int, error) {
	// Trim and drop blanks so a stray "" from the client doesn't become
	// an empty rule-name lookup inside the SP.
	cleaned := make([]string, 0, len(ruleNames))
	for _, r := range ruleNames {
		if t := strings.TrimSpace(r); t != "" {
			cleaned = append(cleaned, t)
		}
	}
	joined := strings.Join(cleaned, ",")
	joinedIDs := joinExceptionIDs(exceptionIDs)

	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateBulkAssign - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_UPDATE_BULK_ASSIGN(?, ?, ?, ?)", joinedIDs, joined, assignTo, isPermanent)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("exceptionsRepository: UpdateBulkAssign - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_UPDATE_BULK_ASSIGN"($1, $2, $3, $4)`,
		joinedIDs, joined, assignTo, isPermanent,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// UpdateBulkStatus hands (exception-ids, status-name, comments,
// suppress-date) to SP_UPDATE_BULK_STATUS. exceptionIDs is the target
// set — the rows ticked in the grid's bulk-selection column — replacing
// the rule-name targeting this used to do. The SP resolves status →
// EXCEPTION_STATUS_ID and updates EXCEPTION.STATUS_ID (plus
// EXCEPTION.COMMENTS when comments is non-null, plus
// EXCEPTION.SUPPRESS_DATE when suppressDate is non-empty) for exactly
// those rows.
//   - comments is *string: nil → leave existing COMMENTS untouched;
//     "" clears them. SP mirrors via COALESCE(:P_COMMENTS, "COMMENTS").
//   - suppressDate is a plain string because the Bulk Status panel has
//     no bulk-clear affordance: "" → leave existing SUPPRESS_DATE
//     untouched; "YYYY-MM-DD" → set. Empty string round-trips through
//     NULLIF('','') → NULL on both DB backends, then TRY_TO_DATE /
//     ::date, then COALESCE(NULL, existing) preserves the original.
// Id delimiter contract matches UpdateBulkAssign (plain comma join).
// An empty exceptionIDs slice is a zero-row no-op inside the SP.
// Returns the number of EXCEPTION rows updated.
func UpdateBulkStatus(exceptionIDs []int64, status string, comments *string, suppressDate string) (int, error) {
	joinedIDs := joinExceptionIDs(exceptionIDs)

	// database/sql translates nil interface → SQL NULL, and a *string
	// that dereferences to "" → the empty-string literal. Passing the
	// pointer directly preserves that distinction end-to-end.
	var commentsArg interface{}
	if comments != nil {
		commentsArg = *comments
	} else {
		commentsArg = nil
	}

	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateBulkStatus - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_UPDATE_BULK_STATUS(?, ?, ?, ?)", joinedIDs, status, commentsArg, suppressDate)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("exceptionsRepository: UpdateBulkStatus - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_UPDATE_BULK_STATUS"($1, $2, $3, $4)`,
		joinedIDs, status, commentsArg, suppressDate,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// UpdateExceptionState stamps MODIFIED_DATE / MODIFIED_BY on every EXCEPTION
// row matching (ASSET_ID, RULE_ID). When complete is true, also flips
// STATE_ID to 4 (Complete). When false, status is left untouched â€” the
// "touch" case for ExecuteRules where a rule re-fires for an existing
// (RuleID, AssetID).
func UpdateExceptionState(assetID string, ruleID int, complete bool) (int, error) {
	var n int
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("exceptionsRepository: UpdateExceptionState - using SNOWFLAKE database environment")
		rows, err := snowflake.Query("CALL SP_UPDATE_EXCEPTION_STATE(?, ?, ?)", assetID, ruleID, complete)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		if rows.Next() {
			_ = rows.Scan(&n)
		}
		return n, nil
	}
	log.Logger.Info("exceptionsRepository: UpdateExceptionState - using POSTGRES database environment")
	if postgres.DB == nil {
		return 0, sql.ErrConnDone
	}
	err := postgres.DB.QueryRow(
		`SELECT public."SP_UPDATE_EXCEPTION_STATE"($1, $2, $3)`,
		assetID, ruleID, complete,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// InsertExceptions bulk-writes rows into the slim EXCEPTION table with
// one multi-row INSERT per batch (batchSize below), replacing the old
// per-row SP_INSERT_EXCEPTION loop that cost one Snowflake round-trip
// per exception (300 rows × ~200-400ms each = a minute+ of wall clock).
// A single 300-row INSERT sends one compile+execute to the DB.
//
// The SP's COALESCE(NULLIF(x,0),1) default-to-1 behavior on STATE_ID
// and STATUS_ID is applied in Go up front so the SQL can stay a plain
// VALUES tuple that both Snowflake and Postgres accept without inline
// function-call gymnastics in the VALUES list. ExceptionDate fills
// EXCEPTION_DATE; when blank, ExceptionTime is used and the DB casts
// to DATE. RESULT_DATA is a JSON string (PG casts $N::json below).
//
// SP_INSERT_EXCEPTION stays in the repo for direct SQL callers; the
// Go path no longer routes through it.
func InsertExceptions(exceptions []models.Exception) error {
	if len(exceptions) == 0 {
		return nil
	}
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
	defaultOne := func(n int) any {
		if n == 0 {
			return 1
		}
		return n
	}
	// openDate: OPEN_DATE follows the row's initial status. Rows always
	// start as "New" (StatusID = 1 after defaultOne), so stamp today
	// (UTC) unless the caller explicitly seeded a non-New status — that
	// path leaves OPEN_DATE NULL and lets a later transition to New
	// set it via SP_UPDATE_EXCEPTION_STATUS / SP_UPDATE_BULK_STATUS.
	// Computed once per call so every row in the batch shares the same
	// stamp (matches the CURRENT_DATE semantics inside the SPs).
	openToday := time.Now().UTC().Format("2006-01-02")
	openDate := func(e models.Exception) any {
		if defaultOne(e.StatusID) == 1 {
			return openToday
		}
		return nil
	}
	// Bind values for one row in the shared column order. Ordering must
	// stay in sync with the column list and placeholder builders below.
	rowValues := func(e models.Exception) []any {
		return []any{
			e.RuleID,
			e.AssetID,
			dateOrTime(e),
			nilIfEmpty(e.IdBbGlobal),
			defaultOne(e.StateID),
			nilIfEmpty(e.ExceptionTime),
			nilIfEmpty(e.IssueDescription),
			nilIfEmpty(e.ResultData),
			nilIfZero(e.AssignToID),
			e.ResultTypeID,
			nilIfEmpty(e.CreatedDate),
			e.CreatedBy,
			defaultOne(e.StatusID),
			openDate(e),
		}
	}
	const columnList = `"RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL", ` +
		`"STATE_ID", "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA", ` +
		`"ASSIGN_TO_ID", "RESULT_TYPE_ID", "CREATED_DATE", "CREATED_BY", "STATUS_ID", ` +
		`"OPEN_DATE"`
	const colsPerRow = 14
	// batchSize caps the parameter count per statement well below Postgres's
	// 65535-parameter limit (500 * 13 = 6500) while still cutting round-trips
	// dramatically vs. per-row.
	const batchSize = 500

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info(fmt.Sprintf(
			"exceptionsRepository: InsertExceptions - SNOWFLAKE bulk insert of %d rows",
			len(exceptions),
		))
		// Snowflake uses `?` placeholders. Each row is a `(?,?,...)` tuple.
		rowPlaceholder := "(" + strings.Repeat("?,", colsPerRow-1) + "?)"
		for start := 0; start < len(exceptions); start += batchSize {
			end := start + batchSize
			if end > len(exceptions) {
				end = len(exceptions)
			}
			n := end - start
			placeholders := strings.Repeat(rowPlaceholder+",", n-1) + rowPlaceholder
			params := make([]any, 0, n*colsPerRow)
			for i := start; i < end; i++ {
				params = append(params, rowValues(exceptions[i])...)
			}
			stmt := `INSERT INTO "EXCEPTION" (` + columnList + `) VALUES ` + placeholders
			// snowflake.Query keeps the auth-token retry semantics that
			// snowflake.DB.Exec doesn't get; the INSERT still runs — we just
			// close the (empty) result set immediately.
			rows, err := snowflake.Query(stmt, params...)
			if err != nil {
				return err
			}
			rows.Close()
		}
		return nil
	}

	log.Logger.Info(fmt.Sprintf(
		"exceptionsRepository: InsertExceptions - POSTGRES bulk insert of %d rows",
		len(exceptions),
	))
	if postgres.DB == nil {
		return sql.ErrConnDone
	}
	// Postgres uses numbered `$1..$N` placeholders. The 8th slot per row is
	// RESULT_DATA and needs a `::json` cast (PG's json type isn't inferred
	// from a text bind).
	for start := 0; start < len(exceptions); start += batchSize {
		end := start + batchSize
		if end > len(exceptions) {
			end = len(exceptions)
		}
		n := end - start
		rowPlaceholders := make([]string, 0, n)
		params := make([]any, 0, n*colsPerRow)
		for i := 0; i < n; i++ {
			base := i * colsPerRow
			ph := make([]string, colsPerRow)
			for j := 0; j < colsPerRow; j++ {
				ph[j] = fmt.Sprintf("$%d", base+j+1)
			}
			// RESULT_DATA is slot 8 (index 7).
			ph[7] = ph[7] + "::json"
			rowPlaceholders = append(rowPlaceholders, "("+strings.Join(ph, ",")+")")
			params = append(params, rowValues(exceptions[start+i])...)
		}
		stmt := `INSERT INTO public."EXCEPTION" (` + columnList + `) VALUES ` +
			strings.Join(rowPlaceholders, ",")
		if _, err := postgres.DB.Exec(stmt, params...); err != nil {
			return err
		}
	}
	return nil
}

// UpdateExceptions updates each EXCEPTION row identified by (ASSET_ID, RULE_ID)
// via UPDATE_EXCEPTION. STATE_ID is force-reset to 1 (Pending) inside the SP
// regardless of what the caller passes. A NULL ResultData preserves the
// existing column via COALESCE inside the SP â€” same pattern as ID_BB_GLOBAL
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
				"CALL SP_UPDATE_EXCEPTION(?,?,?,?,?,?,?,?,?,?,?,?,?)",
				e.RuleID,
				e.AssetID,
				dateOrTime(e),
				nilIfEmpty(e.IdBbGlobal),
				e.StateID,
				nilIfEmpty(e.ExceptionTime),
				nilIfEmpty(e.IssueDescription),
				nilIfEmpty(e.ResultData),
				nilIfZero(e.AssignToID),
				e.ResultTypeID,
				nilIfEmpty(e.CreatedDate),
				e.CreatedBy,
				nilIfZero(e.StatusID),
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
			`SELECT public."SP_UPDATE_EXCEPTION"($1,$2,$3,$4,$5,$6,$7,$8::json,$9,$10,$11,$12,$13)`,
			e.RuleID,
			e.AssetID,
			dateOrTime(e),
			nilIfEmpty(e.IdBbGlobal),
			e.StateID,
			nilIfEmpty(e.ExceptionTime),
			nilIfEmpty(e.IssueDescription),
			nilIfEmpty(e.ResultData),
			nilIfZero(e.AssignToID),
			e.ResultTypeID,
			nilIfEmpty(e.CreatedDate),
			e.CreatedBy,
			nilIfZero(e.StatusID),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// ExecuteSnowflakeSQL is a TEMPORARY QA helper backing the /executeSN
// endpoint. Runs whatever SQL the caller supplies — DDL, CALL, SELECT,
// anything — on the live Snowflake connection and returns the result
// set (if any) as a slice of column→value maps. Rows are read as
// NullString so numerics / timestamps / booleans all coerce to their
// text representation; this keeps the wire format human-readable at
// the cost of losing native types. Capped at ExecuteSNMaxRows to
// prevent an unbounded SELECT from streaming the whole warehouse
// through the API. Postgres path is intentionally not implemented so
// nobody accidentally nukes local dev by hitting the same endpoint.
const ExecuteSNMaxRows = 1000

func ExecuteSnowflakeSQL(sqlText string) ([]map[string]any, error) {
	if !strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		return nil, fmt.Errorf("ExecuteSnowflakeSQL: not implemented for %q — Snowflake only",
			configs.EnvConfigs.Database)
	}
	log.Logger.Warn(fmt.Sprintf(
		"exceptionsRepository: ExecuteSnowflakeSQL - running ad-hoc SF SQL (%d chars)",
		len(sqlText),
	))
	rows, err := snowflake.Query(sqlText)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	results := make([]map[string]any, 0, 8)
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			if vals[i].Valid {
				row[c] = vals[i].String
			} else {
				row[c] = nil
			}
		}
		results = append(results, row)
		if len(results) >= ExecuteSNMaxRows {
			log.Logger.Warn(fmt.Sprintf(
				"exceptionsRepository: ExecuteSnowflakeSQL - result capped at %d rows",
				ExecuteSNMaxRows,
			))
			break
		}
	}
	return results, nil
}

// TruncateExceptionsAndHist is a TEMPORARY QA helper used by the /junk
// endpoint to wipe both EXCEPTION and EXCEPTION_HIST between test
// runs. Snowflake only; Postgres is intentionally not implemented and
// returns an error so it can't be accidentally used in dev to nuke
// local data. Remove alongside handlers.Junk / route /junk once the
// QA reset workflow no longer needs it.
func TruncateExceptionsAndHist() error {
	if !strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		return fmt.Errorf("TruncateExceptionsAndHist: not implemented for %q — Snowflake only",
			configs.EnvConfigs.Database)
	}
	log.Logger.Warn("exceptionsRepository: TruncateExceptionsAndHist - wiping EXCEPTION and EXCEPTION_HIST on SNOWFLAKE")
	// Two separate statements — Snowflake driver may not allow a single
	// multi-statement request without extra config. TRUNCATE returns no
	// row set; snowflake.Query is used to keep the auth-token retry
	// semantics and the empty result is closed immediately.
	for _, table := range []string{"EXCEPTION", "EXCEPTION_HIST"} {
		rows, err := snowflake.Query(fmt.Sprintf(`TRUNCATE TABLE "%s"`, table))
		if err != nil {
			return fmt.Errorf("TruncateExceptionsAndHist: truncating %q failed: %w", table, err)
		}
		rows.Close()
	}
	return nil
}
