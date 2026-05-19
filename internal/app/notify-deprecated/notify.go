// Package notify watches the underlying database for new SECURITY_EXCEPTION
// rows and publishes a security_exception.inserted event on the in-process
// broker. It branches on the DATABASE env var so a Postgres listener or a
// Snowflake poller is started, but never both.
package notifydeprecated

import (
	"context"
	"strings"

	"securityrules/security-rules/configs"
	"securityrules/security-rules/internal/utils/log"
)

// Start launches the appropriate watcher in a goroutine. It returns
// immediately. The watcher stops when ctx is cancelled.
func Start(ctx context.Context, postgresConnStr string) {
	if strings.EqualFold(configs.EnvConfigs.Database, "SNOWFLAKE") {
		log.Logger.Info("notify: starting Snowflake poller")
		go pollSnowflake(ctx)
		return
	}

	log.Logger.Info("notify: starting Postgres LISTEN")
	go listenPostgres(ctx, postgresConnStr)
}
