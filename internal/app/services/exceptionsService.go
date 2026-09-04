package services

import (
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/repositories"
)

func GetExceptionTypes() ([]string, error) {
	return repositories.GetExceptionTypes()
}

func GetExceptionState() ([]string, error) {
	return repositories.GetExceptionState()
}

func GetExceptionStatus() ([]string, error) {
	return repositories.GetExceptionStatus()
}

func UpdateExceptionStatus(exceptionID int64, statusName, comments, suppressDate string) (int, error) {
	return repositories.UpdateExceptionStatus(exceptionID, statusName, comments, suppressDate)
}

func UpdateExceptionComments(exceptionID int64, comments string) (int, error) {
	return repositories.UpdateExceptionComments(exceptionID, comments)
}

func UpdateExceptionSuppressDate(exceptionID int64, suppressDate string) (int, error) {
	return repositories.UpdateExceptionSuppressDate(exceptionID, suppressDate)
}

// TruncateExceptionsAndHist is a TEMPORARY QA helper — thin passthrough
// to the repository. Snowflake only; Postgres is intentionally not
// implemented and returns an error. Remove alongside handlers.Junk /
// route /junk once the QA reset workflow no longer needs it.
func TruncateExceptionsAndHist() error {
	return repositories.TruncateExceptionsAndHist()
}

// ExecuteSnowflakeSQL is a TEMPORARY QA helper — thin passthrough to
// the repository, backing the /executeSN endpoint. Runs arbitrary SQL
// on Snowflake and returns rows if any. Postgres path returns an
// error. Remove alongside handlers.ExecuteSN / route /executeSN once
// no longer needed.
func ExecuteSnowflakeSQL(sqlText string) ([]map[string]any, error) {
	return repositories.ExecuteSnowflakeSQL(sqlText)
}

func GetSeverityTypes() ([]string, error) {
	return repositories.GetSeverityTypes()
}

func GetPriorityTypes() ([]string, error) {
	return repositories.GetPriorityTypes()
}

func GetExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern, exceptionDate, securityGroup string) ([]models.Exception, error) {
	return repositories.GetExceptions(aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern, exceptionDate, securityGroup)
}

func GetExceptionsHist(exceptionDate, aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern string) ([]models.Exception, error) {
	return repositories.GetExceptionsHist(exceptionDate, aladdinID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern)
}

func GetExceptionHistDates() ([]string, error) {
	return repositories.GetExceptionHistDates()
}

func InsertExceptions(exceptions []models.Exception) error {
	return repositories.InsertExceptions(exceptions)
}

func UpdateExceptions(exceptions []models.Exception) error {
	return repositories.UpdateExceptions(exceptions)
}

func UpdateExceptionState(assetID string, ruleID int, complete bool) (int, error) {
	return repositories.UpdateExceptionState(assetID, ruleID, complete)
}

func UpdateAssignTo(assetID, assignTo string) (int, error) {
	return repositories.UpdateAssignTo(assetID, assignTo)
}

func UpdateExceptionAssignTo(exceptionID int64, assignTo string) (int, error) {
	return repositories.UpdateExceptionAssignTo(exceptionID, assignTo)
}

// exceptionIDs is the target set for both calls; ruleNames on the assign
// path is only the rule-level side effect (see the repository comments).
func UpdateBulkAssign(exceptionIDs []int64, ruleNames []string, assignTo string, isPermanent bool) (int, error) {
	return repositories.UpdateBulkAssign(exceptionIDs, ruleNames, assignTo, isPermanent)
}

func UpdateBulkStatus(exceptionIDs []int64, status string, comments *string, suppressDate string) (int, error) {
	return repositories.UpdateBulkStatus(exceptionIDs, status, comments, suppressDate)
}

func GetSecurityGroups() ([]string, error) {
	return repositories.GetSecurityGroups()
}

func GetExceptionCountsByGroup(exceptionType, severity, priority, exceptionState, assignTo, exceptionDate string, useHist bool) ([]models.GroupCount, error) {
	return repositories.GetExceptionCountsByGroup(exceptionType, severity, priority, exceptionState, assignTo, exceptionDate, useHist)
}
