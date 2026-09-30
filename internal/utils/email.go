package utils

import (
	"context"
	"fmt"
	"html"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/app/repositories"
	httputil "securityrules/security-rules/internal/utils/http"
	"securityrules/security-rules/internal/utils/log"
)

// emailRequest is the Velocity notification service's payload.
//
// The nullable fields are pointers so an unset one marshals to JSON
// null rather than "" or [] — the service's contract asks for null
// specifically, and an empty string is not the same value.
type emailRequest struct {
	Topic              string   `json:"topic"`
	Title              string   `json:"title"`
	Name               string   `json:"name"`
	From               string   `json:"from"`
	To                 []string `json:"to"`
	Cc                 *string  `json:"cc"`
	Bcc                *string  `json:"bcc"`
	Content            string   `json:"content"`
	ContentProperties  *string  `json:"contentProperties"`
	IncludeSubscribers bool     `json:"includesubscribers"`
	Subject            string   `json:"subject"`
	Attachments        *string  `json:"attachments"`
}

// SendExceptionsEmail notifies the operators authorized on a rule
// group that its rules have run.
//
// Recipients come from GetRuleFailureEmailRecipients: the rule groups
// owning the given catalogs, their RULE_GROUP_AUTHORIZATION access
// lists, and of those only the DM_USER rows with
// FLAG_EMAIL_ON_RULE_FAILURE = 'Y'. Callers pass the catalog IDs their
// scope already resolved to, so GROUP, CATALOG and RULE scopes all
// arrive here the same way.
//
// Returns nil for every "nothing to do" case — no EMAIL_URL configured,
// no catalogs, nobody opted in. None of those is a failure, and the
// caller treats this as best-effort anyway: a rule run that produced
// exceptions must not be reported as failed because a notification
// could not be delivered.
func SendExceptionsEmail(ctx context.Context, ruleName string, ruleType string, ruleCatalogIDs []int) error {
	// Unset EMAIL_URL disables sending. Deliberately not an error:
	// local and test environments run without a notification service,
	// and they should not have to stub one out to execute rules.
	url := strings.TrimSpace(configs.EnvConfigs.EmailUrl)
	if url == "" {
		log.Logger.Info("utils: SendExceptionsEmail - EMAIL_URL is not configured, skipping notification")
		return nil
	}
	if len(ruleCatalogIDs) == 0 {
		return nil
	}

	recipients, err := repositories.GetRuleFailureEmailRecipients(ruleCatalogIDs)
	if err != nil {
		return fmt.Errorf("unable to resolve email recipients: %w", err)
	}
	if len(recipients) == 0 {
		log.Logger.Info(fmt.Sprintf(
			"utils: SendExceptionsEmail - rule_name=%q rule_type=%q: no recipients opted in, skipping notification",
			ruleName, ruleType,
		))
		return nil
	}

	// One row per catalog in the resolved scope, LEFT JOINed against
	// EXCEPTION so a catalog with zero live rows still lists at 0.
	// Ordered by (group name, catalog name) so successive sends read
	// predictably.
	counts, err := repositories.GetExceptionCountsByCatalog(ruleCatalogIDs)
	if err != nil {
		return fmt.Errorf("unable to load per-catalog exception counts: %w", err)
	}

	// Subject reads "DQM: <Rule Group>" where the group name comes from
	// RULE_GROUP (the same row RULE_GROUP_AUTHORIZATION's ACCESS_LIST
	// resolved the recipients through). Distinct + comma-joined so a
	// scope that happened to span multiple groups still produces a
	// single legible line — in practice a CATALOG or RULE scope always
	// resolves to one group, and GROUP scope is one by definition.
	// Fallback to the caller's rule_name when counts came back empty
	// so the operator still sees what triggered the mail.
	subjectGroup := distinctGroupNames(counts)
	if subjectGroup == "" {
		subjectGroup = ruleName
	}
	subject := "DQM: " + subjectGroup

	body := emailRequest{
		Topic:              subject,
		Title:              "",
		Name:               "",
		From:               "donnotreply@tcw.com",
		To:                 recipients,
		Cc:                 nil,
		Bcc:                nil,
		Content:            buildExceptionsEmailContent(counts),
		ContentProperties:  nil,
		IncludeSubscribers: false,
		Subject:            subject,
		Attachments:        nil,
	}

	// EMAIL_URL is the complete endpoint, so it goes in as the base
	// with an empty path — build() just concatenates the two.
	//
	// The response body is not modelled: nothing downstream consumes
	// it, and decoding into a concrete type would make an unexpected
	// shape look like a delivery failure. A non-2xx still surfaces via
	// httpErr below.
	_, httpErr, err := httputil.Post[emailRequest, map[string]any](
		url, "", &body, nil,
		map[string]string{"Content-Type": "application/json"},
		ctx,
	)
	// httpErr is checked FIRST. On a non-2xx the http helper returns
	// both a populated httpErr and a generic "received an invalid
	// status code: N" error, so testing err first would discard the
	// response body — which is normally the only thing that says why
	// the notification was rejected.
	if httpErr != nil {
		return fmt.Errorf("email notification returned %d: %s", httpErr.Code, httpErr.Body)
	}
	if err != nil {
		return fmt.Errorf("email notification request failed: %w", err)
	}

	log.Logger.Info(fmt.Sprintf(
		"utils: SendExceptionsEmail - rule_name=%q rule_type=%q: notified %d recipient(s)",
		ruleName, ruleType, len(recipients),
	))
	return nil
}

// buildExceptionsEmailContent renders the per-catalog summary as an
// HTML fragment: one <table> with three columns — Project Name,
// Catalog Name, Number of Exceptions. Header cells reuse the
// Exceptions grid header palette (#003e7e navy on white text,
// 13px / weight 450, 6px 10px padding, 1px #9ca3af borders) so the
// email reads as an extension of the app the operator already knows.
// Styles are inline for maximum email-client compatibility — nothing
// out there reliably honors <style> blocks.
//
// Group / catalog names are html.EscapeString'd; they come from
// operator-managed rows (RULE_GROUP.NAME, RULE_CATALOG.NAME) and
// could carry &, <, > that would otherwise break the layout or
// injection-vector into the recipient's mail client.
func buildExceptionsEmailContent(rows []repositories.CatalogExceptionCount) string {
	const (
		thStyle = `background:#003e7e;color:#ffffff;font-weight:450;` +
			`padding:6px 10px;border:1px solid #9ca3af;text-align:left;`
		tdStyle      = `padding:6px 10px;border:1px solid #9ca3af;`
		tdCountStyle = `padding:6px 10px;border:1px solid #9ca3af;text-align:right;`
	)
	// Preamble names the RULE_GROUP the summary is for — same value the
	// table's "Project Name" column shows. Distinct + comma-joined so a
	// scope spanning multiple groups (rare) still reads cleanly. When
	// the summary came back empty there is no group to name, so the
	// preamble is dropped and the table alone carries the "No catalogs
	// in scope." row.
	projectName := distinctGroupNames(rows)

	var b strings.Builder
	b.WriteString(`<div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#111827;">`)
	if projectName != "" {
		b.WriteString(`<p>Data Quality exceptions were generated for the project `)
		b.WriteString(html.EscapeString(projectName))
		b.WriteString(` in the HTML grid</p>`)
	}
	b.WriteString(`<table style="border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;font-size:13px;">`)
	b.WriteString(`<thead><tr>`)
	b.WriteString(`<th style="` + thStyle + `">Project Name</th>`)
	b.WriteString(`<th style="` + thStyle + `">Catalog Name</th>`)
	b.WriteString(`<th style="` + thStyle + `">Number of Exceptions</th>`)
	b.WriteString(`</tr></thead>`)
	b.WriteString(`<tbody>`)
	if len(rows) == 0 {
		b.WriteString(`<tr><td colspan="3" style="` + tdStyle + `">No catalogs in scope.</td></tr>`)
	} else {
		for _, r := range rows {
			b.WriteString(`<tr>`)
			b.WriteString(`<td style="` + tdStyle + `">` + html.EscapeString(r.GroupName) + `</td>`)
			b.WriteString(`<td style="` + tdStyle + `">` + html.EscapeString(r.CatalogName) + `</td>`)
			b.WriteString(`<td style="` + tdCountStyle + `">` + strconvItoa(r.ExceptionCount) + `</td>`)
			b.WriteString(`</tr>`)
		}
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// strconvItoa is a local alias so this file doesn't need to add a
// strconv import just for one Itoa — keeps the import block tight.
func strconvItoa(n int) string {
	return fmt.Sprintf("%d", n)
}

// distinctGroupNames pulls the unique RULE_GROUP names out of the
// per-catalog summary (in first-seen order — the query already sorts
// by group name, so that's alphabetical) and joins them with ", ".
// Blank names are dropped. Empty input returns "". Used by the email
// subject / topic so the recipient sees which project the run was
// for.
func distinctGroupNames(rows []repositories.CatalogExceptionCount) string {
	seen := make(map[string]struct{}, len(rows))
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		g := strings.TrimSpace(r.GroupName)
		if g == "" {
			continue
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		names = append(names, g)
	}
	return strings.Join(names, ", ")
}
