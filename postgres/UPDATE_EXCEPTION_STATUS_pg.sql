DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION_STATUS"(bigint, text);

-- Sets EXCEPTION.STATUS_ID for the row identified by p_exception_id,
-- resolving p_status_name against EXCEPTION_STATUS.NAME. Also bumps
-- MODIFIED_DATE / MODIFIED_BY. Returns 1 on success, 0 if the row or
-- the status name did not match.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_EXCEPTION_STATUS"(
    p_exception_id bigint,
    p_status_name  text
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH updated AS (
        UPDATE public."EXCEPTION"
           SET "STATUS_ID"     = (
                   SELECT "EXCEPTION_STATUS_ID"
                   FROM public."EXCEPTION_STATUS"
                   WHERE "NAME" = p_status_name
                   LIMIT 1
               ),
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
         WHERE "EXCEPTION_ID" = p_exception_id
           AND EXISTS (
               SELECT 1 FROM public."EXCEPTION_STATUS"
                WHERE "NAME" = p_status_name
           )
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
