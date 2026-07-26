package snowflake

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/utils/log"

	"github.com/snowflakedb/gosnowflake"
	"github.com/youmark/pkcs8"
)

// DB is the package-level Snowflake database connection, initialized by main.go
// at startup and consumed by handlers.
var DB *sql.DB

// Reopen is a hook registered by main.go that force-closes DB and opens a fresh
// connection. Callers invoke it after detecting an expired auth token.
var Reopen func() error

// IsAuthTokenExpired reports whether err looks like Snowflake's expired-token
// signal. Snowflake returns error code 390114 with a message containing
// "Authentication token has expired".
func IsAuthTokenExpired(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "authentication token has expired") ||
		strings.Contains(msg, "390114")
}

// Query runs a query against DB and, if the auth token has expired, calls
// Reopen and retries once. Callers that need Snowflake-specific reauth should
// use this instead of DB.Query directly. Logs the SQL at INFO when
// LOG_LEVEL=INFO; stays silent when LOG_LEVEL=DEBUG (which is reserved
// for the RULE_CATALOG_SOURCE entry point below).
func Query(query string, args ...any) (*sql.Rows, error) {
	logIfInfo(query, args)
	return dispatch(context.Background(), query, args...)
}

// QueryRuleCatalog is the entry point for RULE_CATALOG_SOURCE calls
// (used by rulesRepository.runRuleCommandAndBuild). It always logs
// the SQL at INFO regardless of LOG_LEVEL — those runs are the
// primary debug signal in both modes, so they're never suppressed.
// Kept as a distinct function so LOG_LEVEL=DEBUG can silence every
// other snowflake.Query call without any of them dodging the log.
func QueryRuleCatalog(query string) (*sql.Rows, error) {
	log.Logger.Info(fmt.Sprintf("snowflake: RULE_CATALOG_SOURCE SQL=%s", query))
	return dispatch(context.Background(), query)
}

// QueryContext is the context-aware twin of Query: cancellation/timeouts on
// ctx propagate to the in-flight Snowflake call so a stuck request can be
// bounded by the caller. Reauth retry behavior is unchanged.
func QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	logIfInfo(query, args)
	return dispatch(ctx, query, args...)
}

// logIfInfo emits the driver-bound SQL + args at INFO level when
// LOG_LEVEL=INFO (or is unset / EnvConfigs isn't loaded yet — safer
// to log than silently drop early-boot queries). Under LOG_LEVEL=
// DEBUG this is a no-op, deliberately, so only RULE_CATALOG_SOURCE
// runs (which take the QueryRuleCatalog entry point) get logged.
func logIfInfo(query string, args []any) {
	if configs.EnvConfigs != nil &&
		!strings.EqualFold(configs.EnvConfigs.LogLevel, "INFO") &&
		strings.TrimSpace(configs.EnvConfigs.LogLevel) != "" {
		return
	}
	if len(args) > 0 {
		log.Logger.Info(fmt.Sprintf("snowflake: Query SQL=%s ARGS=%v", query, args))
	} else {
		log.Logger.Info(fmt.Sprintf("snowflake: Query SQL=%s", query))
	}
}

// dispatch is the shared driver call + auth-token retry body. Every
// public entry point above funnels through here so the reauth logic
// stays in one place and each entry point owns its own logging.
func dispatch(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if DB == nil {
		if Reopen == nil {
			return nil, sql.ErrConnDone
		}
		if err := Reopen(); err != nil {
			return nil, err
		}
	}

	rows, err := DB.QueryContext(ctx, query, args...)
	if err == nil {
		return rows, nil
	}

	if !IsAuthTokenExpired(err) || Reopen == nil {
		return nil, err
	}

	log.Logger.Warn("snowflake: auth token expired, reopening connection and retrying query")
	if rerr := Reopen(); rerr != nil {
		return nil, errors.Join(err, rerr)
	}
	if DB == nil {
		return nil, errors.Join(err, sql.ErrConnDone)
	}
	return DB.QueryContext(ctx, query, args...)
}

/*
Representation of properties required to connect/communicate with TCW Data Cloud
via the Snowflake driver (https://github.com/snowflakedb/gosnowflake)
*/
type Snowflake struct {
	Account          string
	User             string
	Role             string
	Warehouse        string
	Database         string
	Schema           string
	Authenticator    gosnowflake.AuthType
	KeepSessionAlive bool
}

func ParseAuthType(authType string) (gosnowflake.AuthType, error) {
	switch strings.ToUpper(authType) {
	case "SNOWFLAKE_JWT":
		return gosnowflake.AuthTypeJwt, nil
	case "EXTERNALBROWSER":
		return gosnowflake.AuthTypeExternalBrowser, nil
	default:
		return -1, errors.New("not supported value, just [snowflake_jwt | externalbrowser]")
	}

}

/*
Interface containing functions required to communicate with the TCW Data Cloud
via the Snowflake driver (https://github.com/snowflakedb/gosnowflake)
*/
type Snowflaker interface {
	GetSnowflakeConfiguration(*rsa.PrivateKey) gosnowflake.Config
	Open([]byte, string) (*sql.DB, error)
}

/*
Function to build the connection string required to open a DB connection to TCW Data cloud
via the driver (https://github.com/snowflakedb/gosnowflake)

Returns:

	string					fully realized connection string based on the Snowflake configurations
*/
func (s Snowflake) GetSnowflakeConfiguration(pk *rsa.PrivateKey) gosnowflake.Config {
	return gosnowflake.Config{
		Account:          s.Account,
		User:             s.User,
		Database:         s.Database,
		Schema:           s.Schema,
		Role:             s.Role,
		Authenticator:    s.Authenticator,
		PrivateKey:       pk,
		KeepSessionAlive: s.KeepSessionAlive,
	}
}

/*
Function to return a DB connection to the TCW Data Cloud using the Snowflake driver (https://github.com/snowflakedb/gosnowflake)

Returns:

	sql.DB					DB connection based on the Snowflake driver
*/
func (s Snowflake) Open(der []byte, password string) (*sql.DB, error) {
	pk, err := pkcs8.ParsePKCS8PrivateKeyRSA(der, []byte(password))
	if err != nil {
		msg := fmt.Sprintf("snowflake.go: Open - unable to acquire a RSA private key with error: %v", err)
		log.Logger.Error(msg)
		return nil, errors.Join(err, errors.New(msg))
	}
	config := s.GetSnowflakeConfiguration(pk)
	dsn, err := gosnowflake.DSN(&config)
	if err != nil {
		msg := fmt.Sprintf("snowflake.go: Open - unable to acquire a DSN with error: %v", err)
		log.Logger.Error(msg)
		return nil, errors.Join(err, errors.New(msg))
	}

	return sql.Open("snowflake", dsn)
}
