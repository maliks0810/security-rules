package models

type SecurityException struct {
	SecurityExceptionID int    `json:"security_exception_id"`
	RuleID                int       `json:"rule_id"`
	RuleName              string    `json:"rule_name"`
	AssetID             string `json:"asset_id"`
	RunDate             string `json:"run_date"`
	RunStart            string `json:"run_start"`
	ResultTypeID        int    `json:"result_type_id"`
	ExceptionSourceID   int    `json:"exception_source_id"`
	ExceptionStatusID   int    `json:"exception_status_id"`
	SeverityTypeID      int    `json:"severity_type_id"`
	ProcessTypeID       int    `json:"process_type_id"`
	CategoryTypeID      int    `json:"category_type_id"`
	AssignTo            string `json:"assign_to"`
	AssignToDate        string `json:"assign_to_date"`
	AssignedBy          string `json:"assigned_by"`
	ResolveDate         string `json:"resolve_date"`
	IssueDescription    string `json:"issue_description"`
	CreatedDate         string `json:"created_date"`
	CreatedBy           string `json:"created_by"`
	ModifiedDate        string `json:"modified_date"`
	ModifiedBy          string `json:"modified_by"`
}
