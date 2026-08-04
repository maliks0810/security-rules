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
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM expired;
$$;
