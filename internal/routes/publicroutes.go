package routes

import (
	"github.com/gofiber/fiber/v2"

	"securityrules/security-rules/internal/app/handlers"
)

func PublicRoutes(app *fiber.App) {
	route := app.Group(route_prefix + "v1/api")

	route.Get("/info", handlers.GetInformation)
	route.Get("/getExceptions", handlers.GetExceptions)
	route.Get("/getAssets", handlers.GetAssets)
	route.Get("/getExceptionTypes", handlers.GetExceptionTypes)
	route.Get("/getExceptionStatus", handlers.GetExceptionStatus)
	route.Get("/getSeverityTypes", handlers.GetSeverityTypes)
	route.Get("/getPriorityTypes", handlers.GetPriorityTypes)
	route.Get("/getRules", handlers.GetRules)
	route.Get("/getRuleGroups", handlers.GetRuleGroups)
	route.Get("/getDMUsers", handlers.GetDMUsers)
	route.Get("/getRuleCatalogs", handlers.GetRuleCatalogs)
	route.Get("/executeRules", handlers.ExecuteRules)
	route.Get("/updateAssignTo", handlers.UpdateAssignTo)
	route.Get("/events", handlers.StreamEvents)
}
