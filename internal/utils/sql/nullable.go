// Package sqlutil provides helpers for working with database/sql values,
// including conversion of nullable columns to plain Go types.
package sqlutil

import (
	"database/sql"
	"time"
)

// NullStr returns v.String when Valid, else an empty string.
func NullStr(v sql.NullString) string {
	if v.Valid {
		return v.String
	}
	return ""
}

// NullInt returns v.Int64 as int when Valid, else 0.
func NullInt(v sql.NullInt64) int {
	if v.Valid {
		return int(v.Int64)
	}
	return 0
}

// NullTime returns v.Time formatted as RFC3339Nano when Valid, else an empty string.
func NullTime(v sql.NullTime) string {
	if v.Valid {
		return v.Time.Format(time.RFC3339Nano)
	}
	return ""
}
