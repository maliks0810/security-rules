DROP FUNCTION IF EXISTS public."SP_EXPIRE_SUPPRESS_DATES"();

-- Any EXCEPTION row whose SUPPRESS_DATE has already passed (< today UTC)
-- reverts to STATUS_ID=1 ("New") and its SUPPRESS_DATE is cleared. Also
-- bumps MODIFIED_DATE / MODIFIED_BY. Returns the number of rows expired.
-- Called at the top of GetExceptions in the Go layer as a best-effort
-- cleanup so the grid never displays a stale Suppress row.
CREATE OR REPLACE FUNCTION public."SP_EXPIRE_SUPPRESS_DATES"()
RETURNS integer
LANGUAGE sql
AS $$
    WITH expired AS (
        UPDATE public."EXCEPTION"
           SET "STATUS_ID"     = 1,
               "SUPPRESS_DATE" = NULL,
               -- Every row this touches transitions back to STATUS_ID=1
               -- (New), so OPEN_DATE ratchets to today.
               "OPEN_DATE"     = (NOW() AT TIME ZONE 'UTC')::date,
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
         WHERE "SUPPRESS_DATE" IS NOT NULL
           AND "SUPPRESS_DATE" < (NOW() AT TIME ZONE 'UTC')::date
        RETURNING 1
    ),
    -- Hold release. A Hold stamps OPEN_DATE = the day it was applied and
    -- SUPPRESS_DATE = 2 business days on from it, so this counts the
    -- same 2 business days forward from OPEN_DATE and releases the row
    -- once that day has passed: a Friday hold runs through Tuesday and
    -- returns to New on Wednesday.
    --
    -- Weekends only, no holiday calendar (none exists in this schema).
    -- Offsets by ISO weekday: Mon/Tue/Wed +2, Thu/Fri +4 (skipping the
    -- weekend), Sat +3, Sun +2.
    --
    -- Agrees with the branch above by construction - that one would
    -- already catch these rows. Kept explicit so Hold's lifecycle is
    -- readable on its own. Rows released above are already STATUS_ID=1
    -- with a NULL SUPPRESS_DATE, so the two CTEs cannot double-count.
    held AS (
        UPDATE public."EXCEPTION"
           SET "STATUS_ID"     = 1,
               "SUPPRESS_DATE" = NULL,
               "OPEN_DATE"     = (NOW() AT TIME ZONE 'UTC')::date,
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
         WHERE "STATUS_ID" = 7
           AND "OPEN_DATE" IS NOT NULL
           AND (NOW() AT TIME ZONE 'UTC')::date >
               "OPEN_DATE" + (CASE EXTRACT(ISODOW FROM "OPEN_DATE")
                                  WHEN 4 THEN 4
                                  WHEN 5 THEN 4
                                  WHEN 6 THEN 3
                                  ELSE 2
                              END)::int
        RETURNING 1
    )
    SELECT (SELECT COUNT(*) FROM expired)::int
         + (SELECT COUNT(*) FROM held)::int;
$$;
