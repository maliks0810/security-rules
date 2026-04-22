package snowflake

import (
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"strings"

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
// use this instead of DB.Query directly.
func Query(query string, args ...any) (*sql.Rows, error) {
	if DB == nil {
		if Reopen == nil {
			return nil, sql.ErrConnDone
		}
		if err := Reopen(); err != nil {
			return nil, err
		}
	}

	rows, err := DB.Query(query, args...)
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
	return DB.Query(query, args...)
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
