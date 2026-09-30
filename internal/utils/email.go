package utils

import (
	"context"
	"fmt"
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

	body := emailRequest{
		Topic:              "DQM : Security Master ",
		Title:              "",
		Name:               "",
		From:               "airflow3-prod3@tcw.com",
		To:                 recipients,
		Cc:                 nil,
		Bcc:                nil,
		Content:            "Testing ?",
		ContentProperties:  nil,
		IncludeSubscribers: false,
		Subject:            "DQM : Security Master ",
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
