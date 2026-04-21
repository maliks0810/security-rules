package models

type Asset struct {
	ExceptionDate       string `json:"exception_date"`
	Priority            string `json:"priority"`
	Type                string `json:"type"`
	AssignTo            string `json:"assign_to"`
	AssetID             string `json:"asset_id"`
	Figi                string `json:"figi"`
	SecurityDescription string `json:"security_description"`
	Trader              string `json:"trader"`
	TradingTeam         string `json:"trading_team"`
	ExceptionCount      int    `json:"exception_count"`
	BbgLastRefresh      string `json:"bbg_last_refresh"`
}
