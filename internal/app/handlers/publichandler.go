package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
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

// GetExceptions godoc
// @Summary      List exceptions
// @Description  Returns rows from GET_EXCEPTIONS, which reads the slim EXCEPTION table joined with RULE and the EXCEPTION_*_TYPE lookups.
// @Tags         exceptions
// @Produce      json
// @Param        asset_id          query     string  false  "Asset ID filter"
// @Param        exception_type    query     string  false  "EXCEPTION_TYPE.NAME filter"
// @Param        severity          query     string  false  "EXCEPTION_SEVERITY_TYPE.NAME filter"
// @Param        priority          query     string  false  "EXCEPTION_PRIORITY_TYPE.NAME filter"
// @Param        rule_catalog      query     string  false  "RULE_CATALOG.NAME filter (reserved — RULE does not carry RULE_CATALOG_ID for filtering yet)"
// @Param        rule_name         query     string  false  "RULE.RULE_NAME filter"
// @Param        rule_group        query     string  false  "Reserved (RULE has no rule_group yet)"
// @Param        exception_state  query     string  false  "EXCEPTION_STATE.NAME filter"
// @Param        assign_to         query     string  false  "DM_USER.USER filter"
// @Param        rule_name_pattern query     string  false  "SQL ILIKE pattern against RULE.RULE_NAME"
// @Success      200             {array}   models.Exception
// @Failure      500             {object}  map[string]string  "failed to query exceptions"
// @Router       /v1/api/getExceptions [get]
func GetExceptions(ctx *fiber.Ctx) error {
	assetID := ctx.Query("asset_id")
	exceptionType := ctx.Query("exception_type")
	severity := ctx.Query("severity")
	priority := ctx.Query("priority")
	ruleCatalog := ctx.Query("rule_catalog")
	ruleName := ctx.Query("rule_name")
	ruleGroup := ctx.Query("rule_group")
	exceptionState := ctx.Query("exception_state")
	assignTo := ctx.Query("assign_to")
	ruleNamePattern := ctx.Query("rule_name_pattern")

	exceptions, err := services.GetExceptions(assetID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query exceptions"})
	}

	return ctx.Status(fiber.StatusOK).JSON(exceptions)
}

// GetExceptionsHist godoc
// @Summary      List history-table exceptions for a specific EXCEPTION_DATE
// @Description  Same shape as /getExceptions but reads from EXCEPTION_HIST
// @Description  and only returns rows belonging to that day's LATEST BATCH_ID
// @Description  within the caller's rule/catalog/group scope. Powers the "DQM
// @Description  Date" back-in-time selector on the sidebar.
// @Tags         exceptions
// @Produce      json
// @Param        exception_date    query     string  true   "ISO YYYY-MM-DD"
// @Param        asset_id          query     string  false  "Asset ID filter"
// @Param        exception_type    query     string  false  "EXCEPTION_TYPE.NAME filter"
// @Param        severity          query     string  false  "EXCEPTION_SEVERITY_TYPE.NAME filter"
// @Param        priority          query     string  false  "EXCEPTION_PRIORITY_TYPE.NAME filter"
// @Param        rule_catalog      query     string  false  "RULE_CATALOG.NAME filter"
// @Param        rule_name         query     string  false  "RULE.RULE_NAME filter"
// @Param        rule_group        query     string  false  "RULE_GROUP.NAME filter"
// @Param        exception_state   query     string  false  "EXCEPTION_STATE.NAME filter"
// @Param        assign_to         query     string  false  "DM_USER.USER filter"
// @Param        rule_name_pattern query     string  false  "SQL ILIKE pattern against RULE.RULE_NAME"
// @Success      200               {array}   models.Exception
// @Failure      400               {object}  map[string]string  "exception_date is required"
// @Failure      500               {object}  map[string]string  "failed to query exception history"
// @Router       /v1/api/getExceptionsHist [get]
func GetExceptionsHist(ctx *fiber.Ctx) error {
	exceptionDate := ctx.Query("exception_date")
	if exceptionDate == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "exception_date is required"})
	}
	assetID := ctx.Query("asset_id")
	exceptionType := ctx.Query("exception_type")
	severity := ctx.Query("severity")
	priority := ctx.Query("priority")
	ruleCatalog := ctx.Query("rule_catalog")
	ruleName := ctx.Query("rule_name")
	ruleGroup := ctx.Query("rule_group")
	exceptionState := ctx.Query("exception_state")
	assignTo := ctx.Query("assign_to")
	ruleNamePattern := ctx.Query("rule_name_pattern")

	exceptions, err := services.GetExceptionsHist(exceptionDate, assetID, exceptionType, severity, priority, ruleCatalog, ruleName, ruleGroup, exceptionState, assignTo, ruleNamePattern)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query exception history"})
	}
	return ctx.Status(fiber.StatusOK).JSON(exceptions)
}

// GetExceptionHistDates godoc
// @Summary      Distinct EXCEPTION_DATEs available in EXCEPTION_HIST
// @Description  Returns ISO date strings for the last 60 days that have any
// @Description  EXCEPTION_HIST activity, most recent first. Powers the
// @Description  "DQM Date" dropdown options.
// @Tags         exceptions
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query exception history dates"
// @Router       /v1/api/getExceptionHistDates [get]
func GetExceptionHistDates(ctx *fiber.Ctx) error {
	dates, err := services.GetExceptionHistDates()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query exception history dates"})
	}
	return ctx.Status(fiber.StatusOK).JSON(dates)
}

// GetAssets godoc
// @Summary      List assets with exception summary
// @Description  Returns the deduplicated set of assets, optionally filtered by exception type CODE and severity (CATEGORY_TYPE.CODE).
// @Tags         assets
// @Produce      json
// @Param        exception_type  query     string  false  "EXCEPTION_TYPE.CODE filter"
// @Param        severity        query     string  false  "CATEGORY_TYPE.CODE filter"
// @Param        priority        query     string  false  "SEVERITY_TYPE.CODE filter"
// @Param        rule_catalog       query     string  false  "RULE_CATALOG.NAME filter"
// @Param        rule_name        query     string  false  "RULE.RULE_NAME filter"
// @Param        exception_state query     string  false  "EXCEPTION_STATE.CODE filter"
// @Param        assign_to       query      string  false  "DM_USER.USER filter"
// @Success      200             {array}   models.Asset
// @Failure      500             {object}  map[string]string  "failed to query assets"
// @Router       /v1/api/getAssets [get]
func GetAssets(ctx *fiber.Ctx) error {
	exceptionType := ctx.Query("exception_type")
	severity := ctx.Query("severity")
	priority := ctx.Query("priority")
	ruleCatalog := ctx.Query("rule_catalog")
	ruleName := ctx.Query("rule_name")
	exceptionState := ctx.Query("exception_state")
	assignTo := ctx.Query("assign_to")
	ruleGroup := ctx.Query("rule_group")

	assets, err := services.GetAssets(exceptionType, severity, priority, ruleCatalog, ruleName, exceptionState, assignTo, ruleGroup)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query assets"})
	}

	return ctx.Status(fiber.StatusOK).JSON(assets)
}

// GetExceptionState godoc
// @Summary      List exception state codes
// @Description  Returns EXCEPTION_STATE.CODE values ordered by SORT_ORDER.
// @Tags         exception-state
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query exception state"
// @Router       /v1/api/getExceptionState [get]
func GetExceptionState(ctx *fiber.Ctx) error {
	codes, err := services.GetExceptionState()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query exception state"})
	}

	return ctx.Status(fiber.StatusOK).JSON(codes)
}

// UpdateExceptionStatus godoc
// @Summary      Update EXCEPTION.STATUS_ID for a single row
// @Description  Resolves the status name against EXCEPTION_STATUS and updates
// @Description  the STATUS_ID for the row identified by exception_id.
// @Tags         exceptions
// @Produce      json
// @Param        exception_id  query     int     true   "EXCEPTION_ID"
// @Param        status        query     string  true   "EXCEPTION_STATUS.NAME"
// @Success      200           {object}  map[string]int   "rows updated"
// @Failure      400           {object}  map[string]string "invalid params"
// @Failure      500           {object}  map[string]string "failed to update exception status"
// @Router       /v1/api/updateExceptionStatus [get]
func UpdateExceptionStatus(ctx *fiber.Ctx) error {
	exceptionID, err := ctx.ParamsInt("exception_id")
	if err != nil || exceptionID == 0 {
		if v := ctx.Query("exception_id"); v != "" {
			var parsed int64
			_, perr := fmt.Sscanf(v, "%d", &parsed)
			if perr != nil || parsed == 0 {
				return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "exception_id is required"})
			}
			status := ctx.Query("status")
			if status == "" {
				return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "status is required"})
			}
			n, err := services.UpdateExceptionStatus(parsed, status)
			if err != nil {
				return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update exception status"})
			}
			return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"updated": n})
		}
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "exception_id is required"})
	}
	status := ctx.Query("status")
	if status == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "status is required"})
	}
	n, err := services.UpdateExceptionStatus(int64(exceptionID), status)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update exception status"})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"updated": n})
}

// UpdateExceptionComments godoc
// @Summary      Update EXCEPTION.COMMENTS for a single row
// @Description  Sets the free-text COMMENTS on the row identified by exception_id.
// @Tags         exceptions
// @Accept       json
// @Produce      json
// @Param        payload  body      handlers.updateExceptionCommentsBody  true  "exception_id + comments"
// @Success      200  {object}  map[string]int   "rows updated"
// @Failure      400  {object}  map[string]string "invalid params"
// @Failure      500  {object}  map[string]string "failed to update exception comments"
// @Router       /v1/api/updateExceptionComments [post]
func UpdateExceptionComments(ctx *fiber.Ctx) error {
	var body updateExceptionCommentsBody
	if err := ctx.BodyParser(&body); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}
	if body.ExceptionID == 0 {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "exception_id is required"})
	}
	n, err := services.UpdateExceptionComments(body.ExceptionID, body.Comments)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update exception comments"})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"updated": n})
}

type updateExceptionCommentsBody struct {
	ExceptionID int64  `json:"exception_id"`
	Comments    string `json:"comments"`
}

// UpdateExceptionSuppressDate godoc
// @Summary      Update EXCEPTION.SUPPRESS_DATE for a single row
// @Description  Sets the SUPPRESS_DATE (YYYY-MM-DD) on the row identified by
// @Description  exception_id. Empty suppress_date clears the cell.
// @Tags         exceptions
// @Accept       json
// @Produce      json
// @Param        payload  body      handlers.updateExceptionSuppressDateBody  true  "exception_id + suppress_date"
// @Success      200  {object}  map[string]int   "rows updated"
// @Failure      400  {object}  map[string]string "invalid params"
// @Failure      500  {object}  map[string]string "failed to update exception suppress_date"
// @Router       /v1/api/updateExceptionSuppressDate [post]
func UpdateExceptionSuppressDate(ctx *fiber.Ctx) error {
	var body updateExceptionSuppressDateBody
	if err := ctx.BodyParser(&body); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}
	if body.ExceptionID == 0 {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "exception_id is required"})
	}
	n, err := services.UpdateExceptionSuppressDate(body.ExceptionID, body.SuppressDate)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update exception suppress_date"})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"updated": n})
}

type updateExceptionSuppressDateBody struct {
	ExceptionID  int64  `json:"exception_id"`
	SuppressDate string `json:"suppress_date"`
}

// UpdateExceptionAssignTo godoc
// @Summary      Update EXCEPTION.ASSIGN_TO_ID for a single row
// @Description  Resolves assign_to against DM_USER and updates the single
// @Description  EXCEPTION row keyed by exception_id. Empty assign_to clears
// @Description  the assignment.
// @Tags         exceptions
// @Accept       json
// @Produce      json
// @Param        payload  body      handlers.updateExceptionAssignToBody  true  "exception_id + assign_to"
// @Success      200  {object}  map[string]int   "rows updated"
// @Failure      400  {object}  map[string]string "invalid params"
// @Failure      500  {object}  map[string]string "failed to update exception assign_to"
// @Router       /v1/api/updateExceptionAssignTo [post]
func UpdateExceptionAssignTo(ctx *fiber.Ctx) error {
	var body updateExceptionAssignToBody
	if err := ctx.BodyParser(&body); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}
	if body.ExceptionID == 0 {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "exception_id is required"})
	}
	n, err := services.UpdateExceptionAssignTo(body.ExceptionID, body.AssignTo)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update exception assign_to"})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"updated": n})
}

type updateExceptionAssignToBody struct {
	ExceptionID int64  `json:"exception_id"`
	AssignTo    string `json:"assign_to"`
}

// GetExceptionStatus godoc
// @Summary      List exception status names
// @Description  Returns EXCEPTION_STATUS.NAME values ordered by SORT_ORDER.
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
// @Summary      List exception type names
// @Description  Returns EXCEPTION_TYPE.NAME values ordered by SORT_ORDER.
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

// GetPriorityTypes godoc
// @Summary      List priority names
// @Description  Returns EXCEPTION_PRIORITY_TYPE.NAME values ordered by SORT_ORDER.
// @Tags         priority-types
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query priority types"
// @Router       /v1/api/getPriorityTypes [get]
func GetPriorityTypes(ctx *fiber.Ctx) error {
	codes, err := services.GetPriorityTypes()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query priority types"})
	}

	return ctx.Status(fiber.StatusOK).JSON(codes)
}

// GetSeverityTypes godoc
// @Summary      List severity codes
// @Description  Returns CATEGORY_TYPE.CODE values ordered by CATEGORY_RANK.
// @Tags         severity-types
// @Produce      json
// @Success      200  {array}   string
// @Failure      500  {object}  map[string]string  "failed to query severity types"
// @Router       /v1/api/getSeverityTypes [get]
func GetSeverityTypes(ctx *fiber.Ctx) error {
	codes, err := services.GetSeverityTypes()
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
// @Summary      List rule groups
// @Description  Returns RULE_GROUP rows (name + flag_status_visible) ordered by RULE_GROUP_ID.
// @Tags         rule-groups
// @Produce      json
// @Success      200  {array}   models.RuleGroup
// @Failure      500  {object}  map[string]string  "failed to query rule groups"
// @Router       /v1/api/getRuleGroups [get]
func GetRuleGroups(ctx *fiber.Ctx) error {
	groups, err := services.GetRuleGroups()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query rule groups"})
	}

	return ctx.Status(fiber.StatusOK).JSON(groups)
}

// GetRuleCatalogs godoc
// @Summary      List rule type names for a rule group
// @Description  Returns RULE_CATALOG.NAME values joined to RULE_GROUP by RULE_GROUP_ID and filtered by rule group name.
// @Tags         rule-catalogs
// @Produce      json
// @Param        rule_group  query     string  true  "Rule group name"
// @Success      200         {array}   string
// @Failure      400         {object}  map[string]string  "rule_group query parameter is required"
// @Failure      500         {object}  map[string]string  "failed to query rule types"
// @Router       /v1/api/getRuleCatalogs [get]
func GetRuleCatalogs(ctx *fiber.Ctx) error {
	ruleGroup := ctx.Query("rule_group")
	if ruleGroup == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "rule_group query parameter is required"})
	}

	names, err := services.GetRuleCatalogs(ruleGroup)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query rule types"})
	}

	return ctx.Status(fiber.StatusOK).JSON(names)
}

// GetRuleNames godoc
// @Summary      List rule names + descriptions for a catalog
// @Description  Returns one {rule_name, rule_description} per RULE row in the given catalog. Used by the rule tree view to render the friendlier description on each leaf (falling back to rule_name when null/empty) and to label the Exceptions header when a specific rule is selected.
// @Tags         rule-names
// @Produce      json
// @Param        rule_catalog  query     string  true  "Rule catalog name"
// @Success      200           {array}   models.RuleName
// @Failure      400           {object}  map[string]string  "rule_catalog query parameter is required"
// @Failure      500           {object}  map[string]string  "failed to query rule names"
// @Router       /v1/api/getRuleNames [get]
func GetRuleNames(ctx *fiber.Ctx) error {
	ruleCatalog := ctx.Query("rule_catalog")
	if ruleCatalog == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "rule_catalog query parameter is required"})
	}

	names, err := services.GetRuleNames(ruleCatalog)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query rule names"})
	}

	return ctx.Status(fiber.StatusOK).JSON(names)
}

// GetRules godoc
// @Summary      List rule catalogs
// @Description  Returns one row per RULE_CATALOG, optionally filtered. rule_type controls how rule_name is interpreted: "CATALOG" or "RULE" -> rule_name matches RULE_CATALOG.NAME; "GROUP" -> rule_name matches RULE_GROUP.NAME. Omit / empty / "All" means no filter.
// @Tags         rules
// @Produce      json
// @Param        rule_name     query     string  false  "Filter value (catalog name or group name depending on rule_type)"
// @Param        rule_type     query     string  false  "CATALOG | GROUP | RULE"
// @Success      200           {array}   models.Rule
// @Failure      500           {object}  map[string]string  "failed to query rules"
// @Router       /v1/api/getRules [get]
func GetRules(ctx *fiber.Ctx) error {
	ruleName := ctx.Query("rule_name")
	ruleType := ctx.Query("rule_type")

	rules, err := services.GetRules(ruleName, ruleType)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to query rules"})
	}

	return ctx.Status(fiber.StatusOK).JSON(rules)
}

// ExecuteRules godoc
// @Summary      Execute rules (archive-then-insert)
// @Description  Moves today's EXCEPTION rows for the catalogs implied by (rule_name, rule_type) into EXCEPTION_HIST via SP_ARCHIVE_EXCEPTIONS (each row stamped with a per-EXCEPTION_DATE BATCH_ID that starts at 1 for a new day and increments for subsequent same-day runs), then runs every matching catalog and inserts whatever rows the catalog sources return. Per-asset scoping (asset_id / id_bb_global) is intentionally not accepted — use /executeSecurityRules for that. rule_name + rule_type semantics match /getRules ("CATALOG" / "RULE" match RULE_CATALOG.NAME, "GROUP" matches RULE_GROUP.NAME, omit / empty / "All" runs every catalog). Additional query params prefixed with "param_" flow into every RULE_CATALOG_SOURCE as ${NAME} placeholder substitutions — e.g. ?param_RATINGS_MISSING=Aa substitutes ${RATINGS_MISSING} → 'Aa'. Empty values (?param_X=) become SQL NULL.
// @Tags         rules
// @Produce      json
// @Param        rule_name     query     string  false  "Filter value (catalog name or group name depending on rule_type)"
// @Param        rule_type     query     string  false  "CATALOG | GROUP | RULE"
// @Success      200           {object}  map[string]string  "rules executed"
// @Failure      500           {object}  map[string]string  "failed to execute rules"
// @Router       /v1/api/executeRules [get]
func ExecuteRules(ctx *fiber.Ctx) error {
	ruleName := ctx.Query("rule_name")
	ruleType := ctx.Query("rule_type")

	// Any ?param_NAME=VALUE query args become ${NAME} placeholder
	// substitutions inside the RULE_CATALOG_SOURCE. The prefix is
	// stripped and the key is passed uppercase so the placeholder in
	// the source stays canonical regardless of URL casing.
	params := map[string]string{}
	ctx.Request().URI().QueryArgs().VisitAll(func(key, value []byte) {
		k := string(key)
		if !strings.HasPrefix(k, "param_") {
			return
		}
		params[strings.ToUpper(strings.TrimPrefix(k, "param_"))] = string(value)
	})

	if err := services.ExecuteRules(ruleName, ruleType, params); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to execute rules"})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
}

// ExecuteSecurityRules godoc
// @Summary      Execute security rules
// @Description  Same orchestration as /executeRules but routed through services.ExecuteSecurityRules so the security-rule flow can diverge later. Query params are identical: asset_id is optional (required when id_bb_global is supplied); rule_name + rule_type scope which catalogs run ("CATALOG" / "RULE" match RULE_CATALOG.NAME, "GROUP" matches RULE_GROUP.NAME, omit / empty / "All" runs every catalog).
// @Tags         rules
// @Produce      json
// @Param        asset_id      query     string  false  "Asset ID (omit to run across all assets; required when id_bb_global is supplied)"
// @Param        id_bb_global  query     string  false  "Bloomberg global ID"
// @Param        rule_name     query     string  false  "Filter value (catalog name or group name depending on rule_type)"
// @Param        rule_type     query     string  false  "CATALOG | GROUP | RULE"
// @Success      200           {object}  map[string]string  "security rules executed"
// @Failure      400           {object}  map[string]string  "asset_id is required when id_bb_global is supplied"
// @Failure      500           {object}  map[string]string  "failed to execute security rules"
// @Router       /v1/api/executeSecurityRules [get]
func ExecuteSecurityRules(ctx *fiber.Ctx) error {
	assetID := ctx.Query("asset_id")
	idBbGlobal := ctx.Query("id_bb_global")
	ruleName := ctx.Query("rule_name")
	ruleType := ctx.Query("rule_type")

	if idBbGlobal != "" && assetID == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "asset_id is required when id_bb_global is supplied"})
	}

	var err error
	if idBbGlobal == "" {
		err = services.ExecuteSecurityRules(ruleName, ruleType, assetID)
	} else {
		err = services.ExecuteSecurityRules(ruleName, ruleType, assetID, idBbGlobal)
	}
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to execute security rules"})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
}


// UpdateAssignTo godoc
// @Summary      Update EXCEPTION.ASSIGN_TO_ID for an asset
// @Description  Resolves assign_to against DM_USER and updates every
//               EXCEPTION row for the given asset. An empty assign_to
//               clears the assignment.
// @Tags         exceptions
// @Produce      json
// @Param        asset_id   query     string  true   "Asset ID"
// @Param        assign_to  query     string  false  "DM_USER.USER name (empty to unassign)"
// @Success      200        {object}  map[string]int  "rows updated"
// @Failure      400        {object}  map[string]string  "asset_id query parameter is required"
// @Failure      500        {object}  map[string]string  "failed to update assign to"
// @Router       /v1/api/updateAssignTo [get]
func UpdateAssignTo(ctx *fiber.Ctx) error {
	assetID := ctx.Query("asset_id")
	if assetID == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "asset_id query parameter is required"})
	}
	assignTo := ctx.Query("assign_to")

	n, err := services.UpdateAssignTo(assetID, assignTo)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update assign to"})
	}
	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"updated": n})
}


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

// InsertExceptions is a private endpoint and intentionally omitted from Swagger.
func InsertExceptions(ctx *fiber.Ctx) error {
	var exceptions []models.Exception
	if err := ctx.BodyParser(&exceptions); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if err := services.InsertExceptions(exceptions); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to insert exceptions"})
	}

	return ctx.SendStatus(fiber.StatusCreated)
}
