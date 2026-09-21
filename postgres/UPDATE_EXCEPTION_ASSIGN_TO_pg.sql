DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION_ASSIGN_TO"(bigint, text);

-- Sets EXCEPTION.ASSIGN_TO_ID for a single row keyed by EXCEPTION_ID,
-- resolving p_assign_to against DM_USER.USER. Empty or NULL p_assign_to
-- resolves to the 'Unassigned' user, so ASSIGN_TO_ID is never NULL.
-- Also bumps MODIFIED_DATE
-- / MODIFIED_BY. Returns 1 on success, 0 if the exception_id did not
-- match. Distinct from SP_UPDATE_ASSIGN_TO (which touches every row for
-- an ASSET_ID from the Assets grid path).
CREATE OR REPLACE FUNCTION public."SP_UPDATE_EXCEPTION_ASSIGN_TO"(
    p_exception_id bigint,
    p_assign_to    text
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH updated AS (
        UPDATE public."EXCEPTION"
           SET "ASSIGN_TO_ID" = (
                                   -- Empty resolves to the 'Unassigned'
                                   -- user rather than to NULL.
                                   SELECT "ID"
                                   FROM public."DM_USER"
                                   WHERE "USER" = CASE
                                                     WHEN p_assign_to IS NULL OR p_assign_to = ''
                                                         THEN 'Unassigned'
                                                     ELSE p_assign_to
                                                 END
                                   LIMIT 1
                               ),
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
         WHERE "EXCEPTION_ID" = p_exception_id
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
