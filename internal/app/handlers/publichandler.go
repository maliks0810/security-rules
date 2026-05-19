package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"time"

	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/app/models"
	"securityrules/security-rules/internal/app/services"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// GetInformation godoc
// @Summary      Service welcome message
// @Description  Returns a static welcome string used as a basic liveness check.
// @Tags         info
// @Produce      plain
// @Success      200  {string}  string  "Welcome to Go microservices using Fiber"
// @Router       /v1/api/info [get]
func GetInformation(ctx *fiber.Ctx) error {
	return ctx.Status(fiber.StatusOK).SendString("Welcome to Go microservices using Fiber")
}

// GetSecurityExceptions godoc
// @Summary      List security exceptions for an asset
// @Description  Returns all SECURITY_EXCEPTION rows for the given asset ID.
// @Tags         security-exceptions
// @Produce      json
// @Param        asset_id    query     string  true  "Asset ID"
// @Success      200         {array}   models.SecurityException
// @Failure      400         {object}  map[string]string  "asset_id query parameter is required"
// @Failure      500         {object}  map[string]string  "failed to query security exceptions"
// @Router       /v1/api/getSecurityExceptions [get]
func GetSecurityExceptions(ctx *fiber.Ctx) error {
	assetID := ctx.Query("asset_id")
	if assetID == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "asset_id query parameter is required"})
	}

	exceptions, err := services.GetSecurityExceptions(assetID)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query security exceptions"})
	}

	return ctx.Status(fiber.StatusOK).JSON(exceptions)
}

// GetAssets godoc
// @Summary      List assets with exception summary
// @Description  Returns the deduplicated set of assets along with their latest exception metadata.
// @Tags         assets
// @Produce      json
// @Success      200  {array}   models.Asset
// @Failure      500  {object}  map[string]string  "failed to query assets"
// @Router       /v1/api/getAssets [get]
func GetAssets(ctx *fiber.Ctx) error {
	assets, err := services.GetAssets()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query assets"})
	}

	return ctx.Status(fiber.StatusOK).JSON(assets)
}

// GetRules godoc
// @Summary      List rules
// @Description  Returns rules from LIST_RULES, optionally filtered by process type.
// @Tags         rules
// @Produce      json
// @Param        process_type  query     string  false  "Process type filter"
// @Success      200           {array}   models.Rule
// @Failure      500           {object}  map[string]string  "failed to query rules"
// @Router       /v1/api/getRules [get]
func GetRules(ctx *fiber.Ctx) error {
	processType := ctx.Query("process_type")

	rules, err := services.GetRules(processType)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query rules"})
	}

	return ctx.Status(fiber.StatusOK).JSON(rules)
}

// ExecuteRules godoc
// @Summary      Execute rules for an asset
// @Description  Runs every rule for the given process_type against the asset and inserts any returned rows as security exceptions.
// @Tags         rules
// @Produce      json
// @Param        process_type  query     string  true   "Process type"
// @Param        asset_id      query     string  true   "Asset ID"
// @Param        id_bb_global  query     string  false  "Bloomberg global ID"
// @Success      200           {object}  map[string]string  "rules executed"
// @Failure      400           {object}  map[string]string  "process_type and asset_id are required"
// @Failure      500           {object}  map[string]string  "failed to execute rules"
// @Router       /v1/api/executeRules [post]
func ExecuteRules(ctx *fiber.Ctx) error {
	processType := ctx.Query("process_type")
	assetID := ctx.Query("asset_id")
	if processType == "" || assetID == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "process_type and asset_id are required"})
	}

	idBbGlobal := ctx.Query("id_bb_global")

	var err error
	if idBbGlobal == "" {
		err = services.ExecuteRules(processType, assetID)
	} else {
		err = services.ExecuteRules(processType, assetID, idBbGlobal)
	}
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to execute rules"})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
}

// InsertSecurityExceptions godoc
// @Summary      Insert security exceptions
// @Description  Inserts one or more SECURITY_EXCEPTION rows. Accepts an array of SecurityException objects.
// @Tags         security-exceptions
// @Accept       json
// @Produce      json
// @Param        exceptions  body      []models.SecurityException  true  "Security exceptions to insert"
// @Success      201
// @Failure      400  {object}  map[string]string  "invalid request body"
// @Failure      500  {object}  map[string]string  "failed to insert security exceptions"
// @Router       /v1/api/insertSecurityExceptions [post]
// StreamEvents godoc
// @Summary      Server-Sent Events stream of domain changes
// @Description  Long-lived text/event-stream that pushes events such as security_exception.inserted to subscribed clients.
// @Tags         events
// @Produce      text/event-stream
// @Success      200  {string}  string  "stream of SSE-formatted events"
// @Router       /v1/api/events [get]
func StreamEvents(ctx *fiber.Ctx) error {
	ctx.Set("Content-Type", "text/event-stream")
	ctx.Set("Cache-Control", "no-cache")
	ctx.Set("Connection", "keep-alive")
	ctx.Set("X-Accel-Buffering", "no")

	sub := events.Subscribe()

	ctx.Context().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		defer events.Unsubscribe(sub)

		// Prime the stream so the client sees response headers immediately
		// instead of waiting for the first event or keepalive tick.
		_, _ = w.WriteString(": connected\n\n")
		_ = w.Flush()

		ping := time.NewTicker(15 * time.Second)
		defer ping.Stop()

		for {
			select {
			case ev, ok := <-sub:
				if !ok {
					return
				}
				data, err := json.Marshal(ev)
				if err != nil {
					continue
				}
				if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data); err != nil {
					return
				}
				if err := w.Flush(); err != nil {
					return
				}
			case <-ping.C:
				if _, err := w.WriteString(": ping\n\n"); err != nil {
					return
				}
				if err := w.Flush(); err != nil {
					return
				}
			}
		}
	}))
	return nil
}

func InsertSecurityExceptions(ctx *fiber.Ctx) error {
	var exceptions []models.SecurityException
	if err := ctx.BodyParser(&exceptions); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if err := services.InsertSecurityExceptions(exceptions); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to insert security exceptions"})
	}

	return ctx.SendStatus(fiber.StatusCreated)
}
