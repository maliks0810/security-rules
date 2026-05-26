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
// @Summary      List security exceptions
// @Description  Returns SECURITY_EXCEPTION rows, optionally filtered by asset ID, exception type, severity (CATEGORY_TYPE.CODE), priority (SEVERITY_TYPE.CODE), rule type, rule name, and rule group.
// @Tags         security-exceptions
// @Produce      json
// @Param        asset_id        query     string  false  "Asset ID filter"
// @Param        exception_type  query     string  false  "EXCEPTION_TYPE.CODE filter"
// @Param        severity        query     string  false  "CATEGORY_TYPE.CODE filter"
// @Param        priority        query     string  false  "SEVERITY_TYPE.CODE filter"
// @Param        rule_type       query     string  false  "RULE_TYPE.NAME filter"
// @Param        rule_name       query     string  false  "RULE.RULE_NAME filter"
// @Param        rule_group      query     string  false  "RULE_GROUP.NAME filter"
// @Param        exception_status query    string  false  "EXCEPTION_STATUS.CODE filter"
// @Param        assign_to       query     string  false  "DM_USER.USER filter"
// @Success      200             {array}   models.SecurityException
// @Failure      500             {object}  map[string]string  "failed to query security exceptions"
// @Router       /v1/api/getSecurityExceptions [get]
func GetSecurityExceptions(ctx *fiber.Ctx) error {
	assetID := ctx.Query("asset_id")
	exceptionType := ctx.Query("exception_type")
	severity := ctx.Query("severity")
	priority := ctx.Query("priority")
	ruleType := ctx.Query("rule_type")
	ruleName := ctx.Query("rule_name")
	ruleGroup := ctx.Query("rule_group")
	exceptionStatus := ctx.Query("exception_status")
	assignTo := ctx.Query("assign_to")

	exceptions, err := services.GetSecurityExceptions(assetID, exceptionType, severity, priority, ruleType, ruleName, ruleGroup, exceptionStatus, assignTo)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query security exceptions"})
	}

	return ctx.Status(fiber.StatusOK).JSON(exceptions)
}

// GetAssets godoc
// @Summary      List assets with exception summary
// @Description  Returns the deduplicated set of assets, optionally filtered by exception type CODE and severity (CATEGORY_TYPE.CODE).
// @Tags         assets
// @Produce      json
// @Param        exception_type  query     string  false  "EXCEPTION_TYPE.CODE filter"
// @Param        severity        query     string  false  "CATEGORY_TYPE.CODE filter"
// @Param        priority        query     string  false  "SEVERITY_TYPE.CODE filter"
// @Param        rule_type       query     string  false  "RULE_TYPE.NAME filter"
// @Param        rule_name        query     string  false  "RULE.RULE_NAME filter"
// @Param        exception_status query     string  false  "EXCEPTION_STATUS.CODE filter"
// @Param        assign_to       query      string  false  "DM_USER.USER filter"
// @Success      200             {array}   models.Asset
// @Failure      500             {object}  map[string]string  "failed to query assets"
// @Router       /v1/api/getAssets [get]
func GetAssets(ctx *fiber.Ctx) error {
	exceptionType := ctx.Query("exception_type")
	severity := ctx.Query("severity")
	priority := ctx.Query("priority")
	ruleType := ctx.Query("rule_type")
	ruleName := ctx.Query("rule_name")
	exceptionStatus := ctx.Query("exception_status")
	assignTo := ctx.Query("assign_to")

	assets, err := services.GetAssets(exceptionType, severity, priority, ruleType, ruleName, exceptionStatus, assignTo)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query assets"})
	}

	return ctx.Status(fiber.StatusOK).JSON(assets)
}

// GetExceptionStatus godoc
// @Summary      List exception status codes
// @Description  Returns EXCEPTION_STATUS.CODE values ordered by SORT_ORDER.
// @Tags         exception-status
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query exception status"
// @Router       /v1/api/getExceptionStatus [get]
func GetExceptionStatus(ctx *fiber.Ctx) error {
	codes, err := services.GetExceptionStatus()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query exception status"})
	}

	return ctx.Status(fiber.StatusOK).JSON(codes)
}

// GetExceptionTypes godoc
// @Summary      List exception type codes
// @Description  Returns EXCEPTION_TYPE.CODE values ordered by EXCEPTIONTYPERANK.
// @Tags         exception-types
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query exception types"
// @Router       /v1/api/getExceptionTypes [get]
func GetExceptionTypes(ctx *fiber.Ctx) error {
	codes, err := services.GetExceptionTypes()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query exception types"})
	}

	return ctx.Status(fiber.StatusOK).JSON(codes)
}

// GetPriorityType godoc
// @Summary      List priority codes
// @Description  Returns SEVERITY_TYPE.CODE values ordered by SEVERITY_RANK.
// @Tags         priority-types
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query priority types"
// @Router       /v1/api/getPriorityType [get]
func GetPriorityType(ctx *fiber.Ctx) error {
	codes, err := services.GetPriorityType()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query priority types"})
	}

	return ctx.Status(fiber.StatusOK).JSON(codes)
}

// GetSeverityType godoc
// @Summary      List severity codes
// @Description  Returns CATEGORY_TYPE.CODE values ordered by CATEGORY_RANK.
// @Tags         severity-types
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query severity types"
// @Router       /v1/api/getSeverityType [get]
func GetSeverityType(ctx *fiber.Ctx) error {
	codes, err := services.GetSeverityType()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query severity types"})
	}

	return ctx.Status(fiber.StatusOK).JSON(codes)
}

// GetDMUsers godoc
// @Summary      List DM users
// @Description  Returns DM_USER.USER values ordered by ID.
// @Tags         users
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query users"
// @Router       /v1/api/getDMUsers [get]
func GetDMUsers(ctx *fiber.Ctx) error {
	users, err := services.GetDMUsers()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query users"})
	}

	return ctx.Status(fiber.StatusOK).JSON(users)
}

// GetRuleGroups godoc
// @Summary      List rule group names
// @Description  Returns RULE_GROUP.NAME values ordered by RULE_GROUP_ID.
// @Tags         rule-groups
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query rule groups"
// @Router       /v1/api/getRuleGroups [get]
func GetRuleGroups(ctx *fiber.Ctx) error {
	names, err := services.GetRuleGroups()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query rule groups"})
	}

	return ctx.Status(fiber.StatusOK).JSON(names)
}

// GetRuleTypes godoc
// @Summary      List rule type names for a rule group
// @Description  Returns RULE_TYPE.NAME values joined to RULE_GROUP by RULE_GROUP_ID and filtered by rule group name.
// @Tags         rule-types
// @Produce      json
// @Param        rule_group  query     string  true  "Rule group name"
// @Success      200         {array}   string
// @Failure      400         {object}  map[string]string  "rule_group query parameter is required"
// @Failure      500         {object}  map[string]string  "failed to query rule types"
// @Router       /v1/api/getRuleTypes [get]
func GetRuleTypes(ctx *fiber.Ctx) error {
	ruleGroup := ctx.Query("rule_group")
	if ruleGroup == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "rule_group query parameter is required"})
	}

	names, err := services.GetRuleTypes(ruleGroup)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query rule types"})
	}

	return ctx.Status(fiber.StatusOK).JSON(names)
}

// GetRules godoc
// @Summary      List rules
// @Description  Returns rules from GET_RULES, optionally filtered by rule type (RULE_TYPE.NAME).
// @Tags         rules
// @Produce      json
// @Param        process_type  query     string  false  "Process type filter"
// @Param        rule_type     query     string  false  "RULE_TYPE.NAME filter"
// @Success      200           {array}   models.Rule
// @Failure      500           {object}  map[string]string  "failed to query rules"
// @Router       /v1/api/getRules [get]
func GetRules(ctx *fiber.Ctx) error {
	processType := ctx.Query("process_type")
	ruleType := ctx.Query("rule_type")

	rules, err := services.GetRules(processType, ruleType)
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

// InsertSecurityExceptions is a private endpoint and intentionally omitted from Swagger.
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
