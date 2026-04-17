package handlers

import (
	"database/sql"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"

	"github.com/gofiber/fiber/v2"
)

func GetInformation(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusOK).SendString("Welcome to Go microservices using Fiber")
}

func GetMukesh(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusOK).SendString("Mukesh work faster")
}

func GetSecurityExceptions(ctx *fiber.Ctx) error {
	aladdinID := ctx.Query("aladdin_id")
	if aladdinID == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "aladdin_id query parameter is required"})
	}

	var db *sql.DB
	var query string

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("GetSecurityExceptions - using SNOWFLAKE database environment")
		db = snowflake.DB
		query = "SELECT SECURITY_EXCEPTION_ID, RULE_ID, ALADDIN_ID, RUN_DATE, RUN_START, " +
			"RESULT_TYPE_ID, EXCEPTION_SOURCE_ID, EXCEPTION_STATUS_ID, SEVERITY_TYPE_ID, " +
			"PROCESS_TYPE_ID, CATEGORY_TYPE_ID, ASSIGN_TO, ASSIGNED_BY, " +
			"ISSUE_DESCRIPTION, CREATED_DATE, CREATED_BY, " +
			"MODIFIED_DATE, MODIFIED_BY FROM SECURITY_EXCEPTION WHERE ALADDIN_ID = $1"
	} else {
		log.Logger.Info("GetSecurityExceptions - using POSTGRES database environment")
		db = postgres.DB
		query = "SELECT \"SECURITY_EXCEPTION_ID\", \"RULE_ID\", \"ALADDIN_ID\", \"RUN_DATE\", \"RUN_START\", " +
			"\"RESULT_TYPE_ID\", \"EXCEPTION_SOURCE_ID\", \"EXCEPTION_STATUS_ID\", \"SEVERITY_TYPE_ID\", " +
			"\"PROCESS_TYPE_ID\", \"CATEGORY_TYPE_ID\", \"ASSIGN_TO\", \"ASSIGNED_BY\", " +
			"\"ISSUE_DESCRIPTION\", \"CREATED_DATE\", \"CREATED_BY\", " +
			"\"MODIFIED_DATE\", \"MODIFIED_BY\" FROM public.\"SECURITY_EXCEPTION\" WHERE \"ALADDIN_ID\" = $1"
	}

	if db == nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database connection is not available"})
	}

	rows, err := db.Query(query, aladdinID)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query security exceptions"})
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
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to scan security exception"})
		}
		exceptions = append(exceptions, e)
	}

	if exceptions == nil {
		exceptions = []models.SecurityException{}
	}
	return ctx.Status(fiber.StatusOK).JSON(exceptions)
}
