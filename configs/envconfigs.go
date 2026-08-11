package configs

import (
	"github.com/spf13/viper"

	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/types"
)

type envConfigs struct {
	GolangEnvironment           types.Environment
	HostEnvironment             string `mapstructure:"HOST_ENVIRONMENT"`
	AuthAudience                string `mapstructure:"TCW_OKTA_AUDIENCE"`
	AuthIssuer                  string `mapstructure:"TCW_OKTA_ISSUER"`
	AuthorizationUrl            string `mapstructure:"PERMITIO_AUTH_URL"`
	AuthorizationKey            string `mapstructure:"PERMITIO_AUTH_KEY"`
	AmqpConnection              string `mapstructure:"AMQP_CONNECTION_STRING"`
	SnowflakeAccount            string `mapstructure:"SNOWFLAKE_ACCOUNT"`
	SnowflakeUser               string `mapstructure:"SNOWFLAKE_USER"`
	SnowflakeRole               string `mapstructure:"SNOWFLAKE_ROLE"`
	SnowflakeWarehouse          string `mapstructure:"SNOWFLAKE_WAREHOUSE"`
	SnowflakeDatabase           string `mapstructure:"SNOWFLAKE_DATABASE"`
	SnowflakeSchema             string `mapstructure:"SNOWFLAKE_SCHEMA"`
	SnowflakeAuthenticator      string `mapstructure:"SNOWFLAKE_AUTHENTICATOR"`
	KeyVaultUrl                 string `mapstructure:"AZ_KEY_VAULT_VELOCITY_URL"`
	KeyVaultDerKey              string `mapstructure:"AZ_SF_DEF_KEY"`
	KeyVaultPwdKey              string `mapstructure:"AZ_SF_PWD_KEY"`
	SnowflakeConnectionTtlInMin int    `mapstructure:"SNOWFLAKE_CONNECTION_TTL_IN_MINUTES"`
	Database                    string `mapstructure:"DATABASE"`
	PostgresHost                string `mapstructure:"POSTGRES_HOST"`
	PostgresPort                int    `mapstructure:"POSTGRES_PORT"`
	PostgresUser                string `mapstructure:"POSTGRES_USER"`
	PostgresPassword            string `mapstructure:"POSTGRES_PASSWORD"`
	PostgresDatabase            string `mapstructure:"POSTGRES_DATABASE"`
	EnableSwagger               bool   `mapstructure:"ENABLE_SWAGGER"`
	// LogLevel gates how noisy the Snowflake query logs are:
	//   INFO  → every snowflake.Query call is logged with its SQL
	//   DEBUG → only RULE_CATALOG_SOURCE calls (via
	//           runRuleCommandAndBuild) are logged; other queries stay
	//           silent
	// Deliberately inverted from the usual level ranking so that DEBUG
	// zooms in on rule-catalog runs and INFO gives the full firehose.
	// Defaults to INFO across all envs.
	LogLevel string `mapstructure:"LOG_LEVEL"`
	// LogHttpSuccess gates Fiber's per-request access-log middleware
	// entirely. Default false — every "[time] status - Xms method
	// path" line is suppressed (2xx, 3xx, 4xx, 5xx alike) so the
	// console keeps only the zap-level app messages. Flip to true to
	// log every request (useful when tracing a specific call
	// end-to-end); failures remain visible via zap.Error at the
	// handler layer.
	LogHttpSuccess bool `mapstructure:"LOG_HTTP_SUCCESS"`
}

var EnvConfigs *envConfigs

func Load() {
	EnvConfigs = loadEnvironmentVariables()
}

func loadEnvironmentVariables() (configs *envConfigs) {
	viper.AddConfigPath(".")
	viper.AddConfigPath("/env")
	viper.AddConfigPath("../../env")
	viper.AddConfigPath("/go/bin/env")
	viper.SetConfigType("env")

	viper.SetDefault("GOLANG_ENVIRONMENT", "local")
	viper.SetDefault("TCW_OKTA_AUDIENCE", "api://default")
	viper.SetDefault("TCW_OKTA_ISSUER", "https://tcw.okta.com/oauth2/default")

	// General Configurations
	viper.BindEnv("GOLANG_ENVIRONMENT")

	// Authentication Configurations
	viper.BindEnv("TCW_OKTA_AUDIENCE")
	viper.BindEnv("TCW_OKTA_ISSUER")

	// Permit.IO Configurations
	viper.BindEnv("PERMITIO_AUTH_URL")
	viper.BindEnv("PERMITIO_AUTH_KEY")

	// AMQP Configurations (Injected by ES-PlatformEngineering)
	viper.BindEnv("AMQP_CONNECTION_STRING")

	// Snowflake Configurations
	viper.BindEnv("SNOWFLAKE_ACCOUNT")
	viper.BindEnv("SNOWFLAKE_USER")
	viper.BindEnv("SNOWFLAKE_ROLE")
	viper.BindEnv("SNOWFLAKE_WAREHOUSE")
	viper.BindEnv("SNOWFLAKE_DATABASE")
	viper.BindEnv("SNOWFLAKE_SCHEMA")
	viper.BindEnv("SNOWFLAKE_AUTHENTICATOR")
	viper.BindEnv("SNOWFLAKE_CONNECTION_TTL_IN_MINUTES")
	viper.BindEnv("AZ_KEY_VAULT_VELOCITY_URL")
	viper.BindEnv("AZ_SF_DEF_KEY")
	viper.BindEnv("AZ_SF_PWD_KEY")

	// Database Selection
	viper.SetDefault("DATABASE", "SNOWFLAKE")
	viper.BindEnv("DATABASE")

	// Postgres Configurations
	viper.SetDefault("POSTGRES_HOST", "localhost")
	viper.SetDefault("POSTGRES_PORT", 5432)
	viper.SetDefault("POSTGRES_USER", "postgres")
	viper.SetDefault("POSTGRES_PASSWORD", "1010data")
	viper.SetDefault("POSTGRES_DATABASE", "DATA_QUALITY")
	viper.BindEnv("POSTGRES_HOST")
	viper.BindEnv("POSTGRES_PORT")
	viper.BindEnv("POSTGRES_USER")
	viper.BindEnv("POSTGRES_PASSWORD")
	viper.BindEnv("POSTGRES_DATABASE")

	// Swagger UI exposure. Defaults to true so dev/local always get docs;
	// set ENABLE_SWAGGER=false in an env file (typically prod) to make
	// the /swagger route stop serving and return 404.
	viper.SetDefault("ENABLE_SWAGGER", true)
	viper.BindEnv("ENABLE_SWAGGER")

	// Snowflake query log verbosity. INFO logs every snowflake.Query
	// call; DEBUG limits logging to RULE_CATALOG_SOURCE calls only.
	// Default INFO in every environment.
	viper.SetDefault("LOG_LEVEL", "INFO")
	viper.BindEnv("LOG_LEVEL")

	// HTTP access-log toggle for Fiber's per-request line
	// ("[time] status - Xms method path"). Default false — every
	// access-log line is suppressed (any status) so the console
	// keeps only the zap-level app messages. Set LOG_HTTP_SUCCESS=
	// true in an env file to log every request end-to-end.
	viper.SetDefault("LOG_HTTP_SUCCESS", false)
	viper.BindEnv("LOG_HTTP_SUCCESS")

	golangEnv := viper.GetString("GOLANG_ENVIRONMENT")

	envFile := ".env." + golangEnv
	viper.SetConfigName(envFile)

	if err := viper.ReadInConfig(); err != nil {
		log.Logger.Fatal("Unable to load environment configuration file" + err.Error())
	}

	if err := viper.Unmarshal(&configs); err != nil {
		log.Logger.Fatal(err.Error())
	}

	configs.GolangEnvironment = types.Environment(golangEnv)

	return
}
