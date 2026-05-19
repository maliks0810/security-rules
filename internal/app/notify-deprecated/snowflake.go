package notifydeprecated

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/utils/log"
	"securityrules/security-rules/internal/utils/snowflake"
)

// pollInterval is how often we ask Snowflake whether new rows have arrived.
// Snowflake charges per warehouse-second, so this is intentionally
// conservative; tighten it if real-time freshness matters more than cost.
const pollInterval = 30 * time.Second

func pollSnowflake(ctx context.Context) {
	if snowflake.DB == nil {
		log.Logger.Error("notify: snowflake.DB is nil; poller will not start")
		return
	}

	var watermark sql.NullInt64
	if err := snowflake.DB.QueryRow(`SELECT COALESCE(MAX("SECURITY_EXCEPTION_ID"), 0) FROM SECURITY_EXCEPTION`).Scan(&watermark); err != nil {
		log.Logger.Error(fmt.Sprintf("notify: snowflake watermark init failed: %v", err))
		return
	}
	log.Logger.Info(fmt.Sprintf("notify: snowflake watermark initialized at %d", watermark.Int64))

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rows, err := snowflake.Query(
				`SELECT "SECURITY_EXCEPTION_ID", "ASSET_ID" FROM SECURITY_EXCEPTION WHERE "SECURITY_EXCEPTION_ID" > ? ORDER BY "SECURITY_EXCEPTION_ID"`,
				watermark.Int64,
			)
			if err != nil {
				log.Logger.Error(fmt.Sprintf("notify: snowflake poll failed: %v", err))
				continue
			}

			for rows.Next() {
				var (
					id      sql.NullInt64
					assetID sql.NullString
				)
				if err := rows.Scan(&id, &assetID); err != nil {
					log.Logger.Error(fmt.Sprintf("notify: snowflake scan failed: %v", err))
					continue
				}
				events.Publish(events.Event{
					Type: "security_exception.inserted",
					Payload: map[string]any{
						"security_exception_id": id.Int64,
						"asset_id":              assetID.String,
					},
				})
				if id.Int64 > watermark.Int64 {
					watermark.Int64 = id.Int64
				}
			}
			rows.Close()
		}
	}
}
