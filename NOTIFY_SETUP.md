# LISTEN/NOTIFY-driven SSE refresh

End-to-end works: a direct SQL `INSERT` (no Go code touched) produces an SSE event:

```
event: security_exception.inserted
data: {"type":"security_exception.inserted","payload":{"aladdin_id":"BDL36EUA0","security_exception_id":900243}}
```

Calling `INSERT_SECURITY_EXCEPTION` from psql refreshes the React UI without going
through the Go POST path.

## Components

- `INSERT_NOTIFY_TRIGGER_pg.sql` — AFTER INSERT trigger on `SECURITY_EXCEPTION` calling
  `pg_notify` with a `<id>|<aladdin_id>` payload (pipe format because some lib/pq +
  JSON-payload + trigger combinations had inconsistent delivery).
- `internal/app/notify/notify.go` — dispatcher: `Start(ctx, connStr)` chooses Postgres
  LISTEN or Snowflake polling based on `DATABASE` env var.
- `internal/app/notify/postgres.go` — `pq.NewListener` subscriber, parses
  `id|aladdin_id` and publishes the SSE event.
- `internal/app/notify/snowflake.go` — watermark poller (default 30s) on
  `SELECT MAX(SECURITY_EXCEPTION_ID)`, publishes new rows.
- `cmd/security-rules/main.go` — calls `notify.Start` after DB connections open,
  cancels on shutdown.
- `internal/app/services/exceptionsService.go` — removed the in-service
  `events.Publish` call; the DB-driven path now covers all sources.

## Caveat

A flaky pattern was observed where the Postgres listener stopped delivering
notifications after some service restarts on Windows — a fresh start always
recovered. If this recurs reliably, switching to a `pgx`-based listener or polling
would be more robust.
