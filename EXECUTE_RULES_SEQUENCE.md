# ExecuteRules — stored procedure sequence

Entry point: `POST /executeRules` → `publichandler.ExecuteRules` →
`services.ExecuteRules` ([internal/app/services/rulesService.go](internal/app/services/rulesService.go)).

## Short version

```
resolve catalogs
  → run each catalog SP
  → drop inactive-rule rows
  → archive → insert → inherit → revert → drop stale closed
  → notify
```

Steps 1, 2, 4, 5 are hard-fatal (any error returns 500). Everything after
is best-effort — errors are logged and the response stays 200 once the DB
work is committed.

## Sequence

| # | Repo function | Snowflake SP / query | Postgres function | What it does | Fatal? |
|---|---|---|---|---|---|
| 1 | `repositories.GetRules` | `SP_GET_RULES(P_RULE_NAME, P_RULE_TYPE)` | `SP_GET_RULES` | Resolves scope → one row per `RULE_CATALOG`. Under RULE scope also requires `RULE.IS_ACTIVE = 1`. | **yes** |
| 2 (loop) | `repositories.ExecuteRule` | Each catalog's `RULE_CATALOG_SOURCE` (whatever SP that column names — differs per catalog) | same | Produces exception rows for that catalog. `${IS_REFRESH}` / `${RULE_NAME}` / caller params are string-substituted first. One call per catalog from #1. Any catalog failure aborts the run with no DB mutation (archive hasn't run yet). | **yes** |
| 3 | `repositories.GetInactiveRuleIDs` | plain `SELECT "RULE_ID" FROM "RULE" WHERE COALESCE("IS_ACTIVE",0)=0` | same | Returns the `RULE_ID` set to drop from the in-memory `produced` slice before insert. Not an SP. | log + continue |
| 4 | `repositories.ArchiveExceptions` | `SP_ARCHIVE_EXCEPTIONS(P_RULE_NAME, P_RULE_TYPE)` | `SP_ARCHIVE_EXCEPTIONS` | Moves today's in-scope `EXCEPTION` rows into `EXCEPTION_HIST` under a fresh per-date `BATCH_ID`, then deletes them from the live table. | **yes** |
| 5 | `services.InsertExceptions` → `repositories.InsertExceptions` | hand-written bulk `INSERT INTO "EXCEPTION" (...) VALUES (...),(...)...` | same (`$N` placeholders + `::json` cast) | Writes the freshly-produced rows in batches of 500. **Not** an SP — the per-row `SP_INSERT_EXCEPTION` is bypassed for throughput. Skipped entirely when `len(produced) == 0`. | **yes** |
| 6 | `repositories.InheritExceptionStatuses` | `SP_INHERIT_EXCEPTION_STATUSES(P_RULE_NAME, P_RULE_TYPE)` | `SP_INHERIT_EXCEPTION_STATUSES` | For each freshly-inserted row, carries `STATUS_ID` / `COMMENTS` / `CLOSE_DATE` / `SUPPRESS_DATE` forward from the latest `EXCEPTION_HIST` row for the same `(RULE_ID, ASSET_ID)`. Also deletes any rows for inactive rules — safety net on top of #3. | log + continue |
| 7 (loop, dedup by SP name) | `repositories.ExecuteRevertToNewCriteria` | Whatever each catalog has set in `RULE_CATALOG.REVERT_TO_NEW_CRITERIA`. Known today: `SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES()`, `SP_REVERT_TO_NEW_COUNTRY_OF_RISK_NULL_FOR_BENCHMARK()`, `SP_REVERT_TO_NEW_FIGI_NULL_CHECK_FOR_BENCHMARK()`, `SP_REVERT_TO_NEW_IDBBCOMPANY_NULL_FOR_BENCHMARK()` | same (postgres `public."SP_…"()`) | One call per distinct SP name across all in-scope catalogs. Each flips rows back to New when the condition that fired them is still true, defer has expired, or an Override's reason no longer holds. | log + continue |
| 8 | `repositories.DropClosedExceptions` | `SP_DROP_CLOSED_EXCEPTIONS(P_RULE_NAME, P_RULE_TYPE)` | `SP_DROP_CLOSED_EXCEPTIONS` | Removes Accept / Override rows whose `CLOSE_DATE` is more than one business day old — closed work shouldn't clutter the grid. | log + continue |
| 9 | `utils.SendExceptionsEmail` → `repositories.GetRuleFailureEmailRecipients` + `repositories.GetExceptionCountsByCatalog` | `SP_GET_RULE_GROUP_EMAIL_LIST(P_RULE_CATALOG_IDS, P_ROLE_FILTER)` + plain count query | same | Only for GROUP / CATALOG / RULE scope. Resolves recipients, computes per-catalog counts, builds the HTML body, POSTs to `EMAIL_URL`. Guarded by 30 s timeout + panic recover; errors never fail the response. | log + continue |

## Notes

- **"All" / unscoped runs** (`rule_name` empty or `All`):
  - Steps 1–8 still fire scope-wide (`SP_GET_RULES` returns every catalog;
    archive / inherit / drop all accept `NULL` scope).
  - Step 9 (email) is skipped on purpose — unscoped would mail every
    recipient on every group's access list at once.
- **Stale-date housekeeping** (`SP_ARCHIVE_STALE_DATES`,
  `SP_EXPIRE_SUPPRESS_DATES`, `SP_UPDATE_CLOSE_DATE`) is **not** invoked
  from `ExecuteRules`. External crons run those SPs directly against
  Snowflake on their own schedule.
- **Per-scope serialization**: a `sync.Map` of mutexes keyed by
  `upper(rule_type) || '|' || rule_name` prevents two concurrent calls
  for the same scope from racing on archive-then-insert. Distinct scopes
  still run in parallel.
- **Response shape**: the handler returns `ExecuteRulesResponse` with
  `ExceptionCount = len(produced) - dropped`, where `dropped` is the
  count from step 8. Step 9's state (sent / skipped / failed) is in the
  logs only, not in the response.
