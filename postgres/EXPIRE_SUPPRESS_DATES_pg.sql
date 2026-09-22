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
               -- OPEN_DATE is write-once. A row coming back from
               -- Suppress or Hold was surfaced long before this sweep,
               -- so releasing it must NOT reset its age. COALESCE only
               -- fills a gap.
               "OPEN_DATE"     = COALESCE("OPEN_DATE", (NOW() AT TIME ZONE 'UTC')::date),
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
         WHERE "SUPPRESS_DATE" IS NOT NULL
           AND "SUPPRESS_DATE" < (NOW() AT TIME ZONE 'UTC')::date
        RETURNING 1
    )
    -- The separate Hold-release CTE that used to sit here counted 2
    -- business days forward from OPEN_DATE. OPEN_DATE is now write-once
    -- ("the day this exception was first surfaced"), so that pass would
    -- have released every held row on the very next sweep.
    --
    -- Nothing is lost: applying a Hold also sets SUPPRESS_DATE to the
    -- same 2 business days out, so the branch above releases the same
    -- rows on the same day - a Friday hold runs through Tuesday and
    -- returns to New on Wednesday.
    SELECT (SELECT COUNT(*) FROM expired)::int;
$$;
