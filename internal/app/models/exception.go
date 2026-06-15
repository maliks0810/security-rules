package models

// Exception represents a row from the slim EXCEPTION table, optionally
// augmented with joined display strings (rule name, status name, priority
// name, etc.) when returned by GET_EXCEPTIONS_2. The display fields use
// omitempty so insert/update bodies don't need to set them.
type Exception struct {
	ExceptionID      int64  `json:"exception_id,omitempty"`
	RuleID           int    `json:"rule_id"`
	RuleName         string `json:"rule_name,omitempty"`
	AssetID          string `json:"asset_id"`
	ExceptionDate    string `json:"exception_date,omitempty"`
	ExceptionTime    string `json:"exception_time,omitempty"`
	IdBbGlobal       string `json:"id_bb_global,omitempty"`
	StatusID         int    `json:"status_id"`
	ExceptionStatus  string `json:"exception_status,omitempty"`
	CommentID        int    `json:"comment_id,omitempty"`
	IssueDescription string `json:"issue_description,omitempty"`
	ResultData       string `json:"result_data,omitempty"`
	SuppressDate     string `json:"suppress_date,omitempty"`
	AssignToID       int    `json:"assign_to_id,omitempty"`
	AssignTo         string `json:"assign_to,omitempty"`
	ResultTypeID     int    `json:"result_type_id"`
	Priority         string `json:"priority,omitempty"`
	Severity         string `json:"severity,omitempty"`
	ExceptionType    string `json:"exception_type,omitempty"`
	CreatedDate      string `json:"created_date,omitempty"`
	CreatedBy        string `json:"created_by,omitempty"`
	ModifiedDate     string `json:"modified_date,omitempty"`
	ModifiedBy       string `json:"modified_by,omitempty"`
}
