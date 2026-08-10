package models

// DMUser represents one row from the DM_USER lookup table as returned
// by SP_GET_DM_USERS. Role + Email were added alongside the original
// User column; both are nullable in the DB (the "Unassigned"
// placeholder row keeps both null) and use `omitempty` so their JSON
// wire representation stays clean for callers that only need the
// user name.
type DMUser struct {
	User  string `json:"user"`
	Role  string `json:"role,omitempty"`
	Email string `json:"email,omitempty"`
}
