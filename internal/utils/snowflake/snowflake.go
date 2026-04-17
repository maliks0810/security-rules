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
