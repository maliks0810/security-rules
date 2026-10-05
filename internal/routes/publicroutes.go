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
	route.Get("/getExceptionRuns", handlers.GetExceptionRuns)
	route.Get("/getAssets", handlers.GetAssets)
	route.Get("/getExceptionTypes", handlers.GetExceptionTypes)
	route.Get("/getExceptionState", handlers.GetExceptionState)
	route.Get("/getExceptionStatus", handlers.GetExceptionStatus)
	route.Get("/getSecurityGroups", handlers.GetSecurityGroups)
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
	route.Get("/getRuleGroupsForUser", handlers.GetRuleGroupsForUser)
	route.Get("/getDMUsers", handlers.GetDMUsers)
	route.Get("/getDMRole", handlers.GetDMRole)
	route.Post("/updateUserPreferences", handlers.UpdateUserPreferences)
	route.Get("/getUserPreferences", handlers.GetUserPreferences)
	route.Get("/refreshUserPreferences", handlers.RefreshUserPreferences)
	route.Post("/clearUserPreferences", handlers.ClearUserPreferences)
	route.Get("/getRuleCatalogs", handlers.GetRuleCatalogs)
	route.Get("/getRuleNames", handlers.GetRuleNames)
	route.Get("/getRulesForGroup", handlers.GetRulesForGroup)
	route.Get("/refreshRulesByGroup", handlers.RefreshRulesByGroup)
	route.Get("/getExceptionCountsByGroup", handlers.GetExceptionCountsByGroup)
	// POST only. This endpoint mutates state (archive-then-insert), and
	// load balancers / ingresses retry idempotent GETs on backend
	// delays, which caused doubled EXCEPTION inserts in QA when the
	// first slow request triggered an automatic retry mid-run. The GET
	// variant existed only so already-deployed clients kept working
	// during the frontend rollout; that rollout is done - the frontend
	// sends POST - so the retry-prone entry point is gone.
	route.Post("/executeRules", handlers.ExecuteRules)
	route.Get("/executeSecurityRules", handlers.ExecuteSecurityRules)
	route.Get("/updateAssignTo", handlers.UpdateAssignTo)
	route.Get("/events", handlers.StreamEvents)

	// /junk (TRUNCATE EXCEPTION + EXCEPTION_HIST) and /executeSN (run
	// arbitrary caller-supplied SQL on the live Snowflake connection)
	// used to be registered here. Both were unauthenticated, like every
	// route in this group, which made /executeSN a remote shell on the
	// warehouse for anyone who could reach the service. Removed rather
	// than guarded: a QA convenience is not worth that exposure, and the
	// same work can be done through a Snowflake worksheet by someone
	// holding their own credentials.
}
