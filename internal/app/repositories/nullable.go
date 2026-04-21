package repositories

import (
	"database/sql"
	"time"
)

func nullStr(v sql.NullString) string {
	if v.Valid {
		return v.String
	}
	return ""
}

func nullInt(v sql.NullInt64) int {
	if v.Valid {
		return int(v.Int64)
	}
	return 0
}

func nullTime(v sql.NullTime) string {
	if v.Valid {
		return v.Time.Format(time.RFC3339Nano)
	}
	return ""
}
