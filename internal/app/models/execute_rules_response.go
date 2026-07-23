package models

// ExecuteRulesResponse is the JSON body returned by /executeRules on
// every outcome — success, not-found, and internal failure. The HTTP
// status code on the response and ExceptionStatus in the body always
// match, so callers can inspect either.
//
// Rationale for duplicating the status inside the body: some frontend
// wrappers care about the payload shape more than the HTTP layer, and
// this lets a single .then() handler read the result without also
// checking res.status.
type ExecuteRulesResponse struct {
	// Total number of exceptions inserted by this run (i.e. len(produced)
	// after every catalog in scope ran and the archive-then-insert
	// pipeline finished). Zero when the scope resolves to no catalogs
	// or when a catalog failed before insert.
	ExceptionCount int `json:"exception_count" example:"280"`
	// Human-readable failure detail. Always present in the JSON — an
	// empty string on success, populated with the wrapped error
	// message on 404 (bad scope) and 500 (Snowflake / SP failure).
	// Kept unconditionally (no omitempty) so callers can rely on
	// `exception_message` existing in every response.
	ExceptionMessage string `json:"exception_message" example:""`
	// Mirrors the HTTP status the endpoint returned: 200 on success,
	// 404 when the requested scope resolved to zero catalogs, 500 on
	// any downstream failure.
	ExceptionStatus int `json:"exception_status" example:"200"`
}
