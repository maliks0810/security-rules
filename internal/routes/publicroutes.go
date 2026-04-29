package routes

import (
	"github.com/gofiber/fiber/v2"

	"securityrules/security-rules/internal/app/handlers"
)

func PublicRoutes(app *fiber.App) {
	route := app.Group(route_prefix + "v1/api")

	route.Get("/info", handlers.GetInformation)
	route.Get("/getSecurityExceptions", handlers.GetSecurityExceptions)
	route.Get("/getAssets", handlers.GetAssets)
	route.Post("/insertSecurityExceptions", handlers.InsertSecurityExceptions)
	route.Get("/events", handlers.StreamEvents)
}
