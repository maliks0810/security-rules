DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION_SUPPRESS_DATE"(bigint, date);

-- Sets EXCEPTION.SUPPRESS_DATE for the row identified by p_exception_id.
-- NULL p_suppress_date clears the cell. Also bumps MODIFIED_DATE /
-- MODIFIED_BY. Returns 1 on success, 0 if the row did not match.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_EXCEPTION_SUPPRESS_DATE"(
    p_exception_id  bigint,
    p_suppress_date date
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH updated AS (
        UPDATE public."EXCEPTION"
           SET "SUPPRESS_DATE" = p_suppress_date,
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
         WHERE "EXCEPTION_ID" = p_exception_id
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
