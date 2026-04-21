package handlers

import (
	"securityrules/security-rules/internal/app/services"

	"github.com/gofiber/fiber/v2"
)

func GetInformation(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusOK).SendString("Welcome to Go microservices using Fiber")
}

func GetSecurityExceptions(ctx *fiber.Ctx) error {
	aladdinID := ctx.Query("aladdin_id")
	if aladdinID == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "aladdin_id query parameter is required"})
	}

	exceptions, err := services.GetSecurityExceptions(aladdinID)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query security exceptions"})
	}

	return ctx.Status(fiber.StatusOK).JSON(exceptions)
}
