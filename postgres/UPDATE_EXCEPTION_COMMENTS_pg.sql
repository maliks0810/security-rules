DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION_COMMENTS"(bigint, text);

-- Sets EXCEPTION.COMMENTS for the row identified by p_exception_id.
-- Also bumps MODIFIED_DATE / MODIFIED_BY. Returns 1 on success,
-- 0 if the row did not match.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_EXCEPTION_COMMENTS"(
    p_exception_id bigint,
    p_comments     text
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH updated AS (
        UPDATE public."EXCEPTION"
           SET "COMMENTS"      = p_comments,
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
         WHERE "EXCEPTION_ID" = p_exception_id
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
