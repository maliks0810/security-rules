package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
	"go.opentelemetry.io/otel"
	stdout "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/app/handlers"
	"securityrules/security-rules/internal/middleware"
	"securityrules/security-rules/internal/routes"
	"securityrules/security-rules/internal/utils/azure"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/net"
	pg "securityrules/security-rules/internal/utils/postgres"
	sf "securityrules/security-rules/internal/utils/snowflake"
	"securityrules/security-rules/internal/utils/types"
)

// Facade aggregates the shared resources used across the service (vault,
// snowflake connection, etc.).  Mirrors security-refresher's RefreshFacade
// but scoped to what a REST-only service needs.
type Facade struct {
	Vault                 azure.Vault
	Snowflake             sf.Snowflake
	DBConnection          *sql.DB
	DBConnectionExpiresOn *time.Time
	PostgresDBConnection  *sql.DB
}

func main() {
	log.Logger.Info("main.go: main - initialize the environment configurations - reading from environment files and environment values...")
	configs.Load()

	log.Logger.Info(fmt.Sprintf("main.go: main - environment configuration set to: %s", configs.EnvConfigs.GolangEnvironment))

	log.Logger.Info("main.go: main - setting up the graceful shutdown channels")
	shutdownChannel := make(chan os.Signal, 1)
	signal.Notify(shutdownChannel, syscall.SIGTERM, syscall.SIGINT)

	tp := newTracerProvider()
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Logger.Error(fmt.Sprintf("unable to shutdown the trace provider: %v", err))
		}
	}()

	log.Logger.Info("main.go: main - initializing the interface facade...")
	facade := initializeFacade()

	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("main.go: main - DATABASE is set to SNOWFLAKE, opening Snowflake connection...")
		if err := openSnowflakeConnection(&facade); err != nil {
			log.Logger.Error(fmt.Sprintf("main.go: main - unable to open snowflake connection at startup: %v", err))
		} else {
			sf.DB = facade.DBConnection
		}
	} else {
		log.Logger.Info("main.go: main - DATABASE is set to POSTGRES, opening Postgres connection...")
		if err := openPostgresConnection(&facade); err != nil {
			log.Logger.Error(fmt.Sprintf("main.go: main - unable to open postgres connection at startup: %v", err))
		} else {
			pg.DB = facade.PostgresDBConnection
		}
	}

	prepare()

	app := fiber.New()
	middleware.FiberMiddleware(app)

	routes.PublicRoutes(app)
	routes.PrivateRoutes(app, privateRouteHandlers())
	routes.UtilityRoutes(app)

	go func() {
		sig := <-shutdownChannel
		releaseResources(&facade, sig)
		_ = app.Shutdown()
	}()

	net.StartServer(app)
}

func initializeFacade() Facade {
	return Facade{
		Vault:     initializeVault(),
		Snowflake: initializeSnowflake(),
	}
}

func newTracerProvider() *sdktrace.TracerProvider {
	exporter, err := stdout.New(stdout.WithPrettyPrint())
	if err != nil {
		log.Logger.Fatal(fmt.Sprintf("unable to create a new OTEL tracer provider: %v", err))
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(
			resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceNameKey.String("security-rules"),
			)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	return tp
}

func prepare() {
}

func privateRouteHandlers() routes.Handlers {
	return routes.Handlers{
		GetIdentity: handlers.GetIdentity,
	}
}

func initializeSnowflake() sf.Snowflake {
	authenticator, err := sf.ParseAuthType(configs.EnvConfigs.SnowflakeAuthenticator)
	if err != nil {
		msg := fmt.Sprintf("main.go: get Snowflake Authenticator - unable to parse with error: %v", err)
		log.Logger.Error(msg)
	}

	return sf.Snowflake{
		Account:       configs.EnvConfigs.SnowflakeAccount,
		User:          configs.EnvConfigs.SnowflakeUser,
		Role:          configs.EnvConfigs.SnowflakeRole,
		Warehouse:     configs.EnvConfigs.SnowflakeWarehouse,
		Database:      configs.EnvConfigs.SnowflakeDatabase,
		Schema:        configs.EnvConfigs.SnowflakeSchema,
		Authenticator: authenticator,
	}
}

func getSnowflakeSecrets() ([]byte, string, error) {
	keys := []string{configs.EnvConfigs.KeyVaultDerKey, configs.EnvConfigs.KeyVaultPwdKey}
	v := azure.NewVault(configs.EnvConfigs.KeyVaultUrl, !types.Environment.IsLocal(configs.EnvConfigs.GolangEnvironment))
	log.Logger.Info("main.go: getSnowflakeSecrets - retrieving values from Azure KeyVault for snowflake authentication...")
	m, err := v.GetMany(keys)
	if err != nil {
		msg := fmt.Sprintf("main.go: getSnowflakeSecrets - unable to get secrets from Azure KeyVault with error: %v", err)
		log.Logger.Error(msg)
		return nil, "", errors.Join(err, errors.New(msg))
	}
	decoded, err := base64.StdEncoding.DecodeString(m[configs.EnvConfigs.KeyVaultDerKey])
	if err != nil {
		msg := fmt.Sprintf("main.go: getSnowflakeSecrets - unable to decode DER value with error: %v", err)
		log.Logger.Error(msg)
		return nil, "", errors.Join(err, errors.New(msg))
	}

	log.Logger.Info("main.go: getSnowflakeSecrets - returning values from Azure KeyVault for snowflake authentication")
	return decoded, m[configs.EnvConfigs.KeyVaultPwdKey], nil
}

func initializeVault() azure.Vault {
	return azure.NewVault(
		configs.EnvConfigs.KeyVaultUrl,
		!types.Environment.IsLocal(configs.EnvConfigs.GolangEnvironment),
	)
}

func openSnowflakeConnection(facade *Facade) error {
	now := time.Now()

	log.Logger.Debug("main.go: openSnowflakeConnection - checking to see if the DB connection needs to be opened/re-opened...")
	if facade.DBConnection != nil {
		if facade.DBConnectionExpiresOn != nil &&
			!facade.DBConnectionExpiresOn.IsZero() &&
			now.After(*facade.DBConnectionExpiresOn) {
			log.Logger.Info(fmt.Sprintf("Connection expired: Closing it now: %v, expired on: %v", now, facade.DBConnectionExpiresOn))
			facade.DBConnection.Close()
			facade.DBConnection = nil
		} else {
			log.Logger.Debug("Connection reference is available")
			return nil
		}
	}

	der, pwd, err := getSnowflakeSecrets()
	if err != nil {
		msg := fmt.Sprintf("main.go openSnowflakeConnection - unable to retrieve secrets from Azure KeyVault with error: %v", err)
		log.Logger.Error(msg)
		return errors.Join(err, errors.New(msg))
	}
	log.Logger.Info("main.go: openSnowflakeConnection - connection is not open.  opening a new connection...")

	maxRetries := 2
	retries := 0

	var db *sql.DB
	for retries < maxRetries {
		db, err = facade.Snowflake.Open(der, pwd)
		if err != nil {
			msg := fmt.Sprintf("openSnowflakeConnection - unable to open snowflake connection with error: %v", err)
			log.Logger.Error(msg)
			return errors.Join(err, errors.New(msg))
		}

		err = db.Ping()
		if err == nil {
			facade.DBConnection = db
			connectionExpiresOn := now.Add(
				time.Duration(configs.EnvConfigs.SnowflakeConnectionTtlInMin * int(time.Minute)))

			facade.DBConnectionExpiresOn = &connectionExpiresOn

			log.Logger.Info(fmt.Sprintf("try [%d]: openSnowflakeConnection - DB connection successfully opened. Expires on: %v", retries, connectionExpiresOn))
			return nil
		}

		log.Logger.Warn(fmt.Sprintf("try [%d]: %s", retries, err.Error()))
		retries++
	}

	return err
}

func closeSnowflakeConnection(facade *Facade) error {
	log.Logger.Debug("main.go: closeSnowflakeConnection - checking to see if a connection exists and should be closed...")
	if facade.DBConnection == nil {
		log.Logger.Debug("main.go: closeSnowflakeConnection - connection does not exist.  do not need to close the connection.")
		return nil
	}

	log.Logger.Debug("main.go: closeSnowflakeConnection - connection exists, attempting to close the DB connection...")
	if err := facade.DBConnection.Close(); err != nil {
		msg := fmt.Sprintf("main.go: closeSnowflakeConnection - unable to close snowflake connection with error: %v", err)
		log.Logger.Error(msg)
		return errors.Join(err, errors.New(msg))
	}

	log.Logger.Info("main.go: closeSnowflakeConnection - DB connection has been successfully closed.")
	facade.DBConnection = nil
	sf.DB = nil
	return nil
}

func openPostgresConnection(facade *Facade) error {
	log.Logger.Debug("main.go: openPostgresConnection - checking to see if the DB connection needs to be opened...")
	if facade.PostgresDBConnection != nil {
		if err := facade.PostgresDBConnection.Ping(); err == nil {
			log.Logger.Debug("main.go: openPostgresConnection - connection reference is available")
			return nil
		}
		facade.PostgresDBConnection.Close()
		facade.PostgresDBConnection = nil
	}

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		configs.EnvConfigs.PostgresHost,
		configs.EnvConfigs.PostgresPort,
		configs.EnvConfigs.PostgresUser,
		configs.EnvConfigs.PostgresPassword,
		configs.EnvConfigs.PostgresDatabase,
	)

	log.Logger.Info("main.go: openPostgresConnection - opening a new connection...")

	maxRetries := 2
	retries := 0
	var db *sql.DB
	var err error

	for retries < maxRetries {
		db, err = sql.Open("postgres", connStr)
		if err != nil {
			msg := fmt.Sprintf("main.go: openPostgresConnection - unable to open postgres connection with error: %v", err)
			log.Logger.Error(msg)
			return errors.Join(err, errors.New(msg))
		}

		err = db.Ping()
		if err == nil {
			facade.PostgresDBConnection = db
			log.Logger.Info(fmt.Sprintf("try [%d]: openPostgresConnection - DB connection successfully opened.", retries))
			return nil
		}

		log.Logger.Warn(fmt.Sprintf("try [%d]: %s", retries, err.Error()))
		retries++
	}

	return err
}

func closePostgresConnection(facade *Facade) error {
	log.Logger.Debug("main.go: closePostgresConnection - checking to see if a connection exists and should be closed...")
	if facade.PostgresDBConnection == nil {
		log.Logger.Debug("main.go: closePostgresConnection - connection does not exist.  do not need to close the connection.")
		return nil
	}

	if err := facade.PostgresDBConnection.Close(); err != nil {
		msg := fmt.Sprintf("main.go: closePostgresConnection - unable to close postgres connection with error: %v", err)
		log.Logger.Error(msg)
		return errors.Join(err, errors.New(msg))
	}

	log.Logger.Info("main.go: closePostgresConnection - DB connection has been successfully closed.")
	facade.PostgresDBConnection = nil
	return nil
}

func releaseResources(facade *Facade, sig os.Signal) {
	log.Logger.Info(fmt.Sprintf("main.go: releaseResources - received shutdown signal: %v", sig))
	_ = closeSnowflakeConnection(facade)
	_ = closePostgresConnection(facade)
}
