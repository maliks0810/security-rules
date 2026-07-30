package routes

import (
	"github.com/gofiber/fiber/v2"

	"securityrules/security-rules/internal/app/handlers"
)

func PublicRoutes(app *fiber.App) {
	route := app.Group(route_prefix + "v1/api")

	route.Get("/info", handlers.GetInformation)
	route.Get("/getExceptions", handlers.GetExceptions)
	route.Get("/getExceptionsHist", handlers.GetExceptionsHist)
	route.Get("/getExceptionHistDates", handlers.GetExceptionHistDates)
	route.Get("/getAssets", handlers.GetAssets)
	route.Get("/getExceptionTypes", handlers.GetExceptionTypes)
	route.Get("/getExceptionState", handlers.GetExceptionState)
	route.Get("/getExceptionStatus", handlers.GetExceptionStatus)
	route.Get("/updateExceptionStatus", handlers.UpdateExceptionStatus)
	route.Post("/updateExceptionComments", handlers.UpdateExceptionComments)
	route.Post("/updateExceptionSuppressDate", handlers.UpdateExceptionSuppressDate)
	route.Post("/updateExceptionAssignTo", handlers.UpdateExceptionAssignTo)
	route.Post("/updateBulkAssign", handlers.UpdateBulkAssign)
	route.Post("/updateBulkStatus", handlers.UpdateBulkStatus)
	route.Get("/getSeverityTypes", handlers.GetSeverityTypes)
	route.Get("/getPriorityTypes", handlers.GetPriorityTypes)
	route.Get("/getRules", handlers.GetRules)
	route.Get("/getRuleGroups", handlers.GetRuleGroups)
	route.Get("/getDMUsers", handlers.GetDMUsers)
	route.Get("/getRuleCatalogs", handlers.GetRuleCatalogs)
	route.Get("/getRuleNames", handlers.GetRuleNames)
	// Accept both POST and GET. POST is the preferred entry point —
	// this endpoint mutates state (archive-then-insert), and load
	// balancers / ingresses retry idempotent GETs on backend delays,
	// which caused doubled EXCEPTION inserts in QA when the first slow
	// request triggered an automatic retry mid-run. GET stays registered
	// so already-deployed clients that still fire a GET keep working
	// during the frontend rollout; new clients should POST.
	route.Post("/executeRules", handlers.ExecuteRules)
	route.Get("/executeRules", handlers.ExecuteRules)
	route.Get("/executeSecurityRules", handlers.ExecuteSecurityRules)
	route.Get("/updateAssignTo", handlers.UpdateAssignTo)
	route.Get("/events", handlers.StreamEvents)

	// TEMPORARY: /junk truncates EXCEPTION and EXCEPTION_HIST on
	// Snowflake so we can wipe test data between runs. Remove once
	// the QA workflow no longer needs it.
	route.Post("/junk", handlers.Junk)

	// TEMPORARY: /executeSN runs any SQL the caller sends against the
	// live Snowflake connection (DDL, CALL, SELECT, …) and returns
	// row output. Snowflake only — Postgres path 500s so local dev
	// can't be nuked by accident. Remove once no longer needed.
	route.Post("/executeSN", handlers.ExecuteSN)
}
