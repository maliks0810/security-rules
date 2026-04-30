package notify

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"securityrules/security-rules/internal/app/events"
	"securityrules/security-rules/internal/utils/log"

	"github.com/lib/pq"
)

const pgChannel = "security_exception_inserted"

func listenPostgres(ctx context.Context, connStr string) {
	listener := pq.NewListener(connStr, 10*time.Second, time.Minute, func(ev pq.ListenerEventType, err error) {
		if err != nil {
			log.Logger.Error(fmt.Sprintf("notify: pg listener event=%d err=%v", ev, err))
		}
	})
	defer listener.Close()

	if err := listener.Listen(pgChannel); err != nil {
		log.Logger.Error(fmt.Sprintf("notify: LISTEN %s failed: %v", pgChannel, err))
		return
	}
	log.Logger.Info("notify: subscribed to Postgres channel " + pgChannel)

	for {
		select {
		case <-ctx.Done():
			return
		case n := <-listener.Notify:
			if n == nil {
				continue
			}
			parts := strings.SplitN(n.Extra, "|", 3)
			payload := map[string]any{}
			if len(parts) >= 1 {
				if id, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
					payload["security_exception_id"] = id
				}
			}
			if len(parts) >= 2 {
				payload["aladdin_id"] = parts[1]
			}
			if len(parts) >= 3 {
				payload["rule_id"] = parts[2]
			}
			events.Publish(events.Event{
				Type:    "security_exception.inserted",
				Payload: payload,
			})
		}
	}
}
