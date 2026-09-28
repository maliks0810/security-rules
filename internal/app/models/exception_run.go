package models

// ExceptionRun is one rule run the "Exceptions Date" dropdown can offer
// for a rule group / catalog / rule scope. BatchID is nil for the live
// EXCEPTION run and the EXCEPTION_HIST BATCH_ID otherwise.
// ExceptionTime is the latest EXCEPTION_TIME among the run's rows.
type ExceptionRun struct {
	ExceptionDate string `json:"exception_date"`
	BatchID       *int64 `json:"batch_id"`
	ExceptionTime string `json:"exception_time,omitempty"`
}
