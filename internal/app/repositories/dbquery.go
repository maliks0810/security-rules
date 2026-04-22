package repositories

import (
	"database/sql"
	"errors"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/postgres"
	"securityrules/security-rules/internal/utils/snowflake"
)

// runQuery dispatches to Snowflake or Postgres based on config and, for
// Snowflake, retries once after reopening if the auth token has expired.
func runQuery(query string, args ...any) (*sql.Rows, error) {
	if !strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		if postgres.DB == nil {
			return nil, sql.ErrConnDone
		}
		return postgres.DB.Query(query, args...)
	}

	if snowflake.DB == nil {
		if snowflake.Reopen == nil {
			return nil, sql.ErrConnDone
		}
		if err := snowflake.Reopen(); err != nil {
			return nil, err
		}
	}

	rows, err := snowflake.DB.Query(query, args...)
	if err == nil {
		return rows, nil
	}

	if !snowflake.IsAuthTokenExpired(err) || snowflake.Reopen == nil {
		return nil, err
	}

	log.Logger.Warn("snowflake: auth token expired, reopening connection and retrying query")
	if rerr := snowflake.Reopen(); rerr != nil {
		return nil, errors.Join(err, rerr)
	}
	if snowflake.DB == nil {
		return nil, errors.Join(err, sql.ErrConnDone)
	}
	return snowflake.DB.Query(query, args...)
}

// snowflakeSelected returns true when the current DATABASE config is Snowflake.
func snowflakeSelected() bool {
	return strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE")
}
