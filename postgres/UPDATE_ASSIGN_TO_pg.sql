DROP FUNCTION IF EXISTS public."SP_UPDATE_ASSIGN_TO"(character varying, text);

-- Updates ASSIGN_TO_ID on every EXCEPTION row for the given asset, resolving
-- the user name against DM_USER. Passing an empty/NULL p_assign_to clears
-- the assignment (sets ASSIGN_TO_ID to NULL).
CREATE OR REPLACE FUNCTION public."SP_UPDATE_ASSIGN_TO"(
    p_asset_id  character varying,
    p_assign_to text
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH updated AS (
        UPDATE public."EXCEPTION"
           SET "ASSIGN_TO_ID" = (
               -- Empty resolves to the 'Unassigned' user rather than to
               -- NULL, so ASSIGN_TO_ID always points at a real user.
               SELECT "ID"::int
               FROM public."DM_USER"
               WHERE "USER" = CASE
                                 WHEN p_assign_to IS NULL OR p_assign_to = ''
                                     THEN 'Unassigned'
                                 ELSE p_assign_to
                             END
               LIMIT 1
           ),
           "MODIFIED_DATE" = CURRENT_TIMESTAMP,
           "MODIFIED_BY"   = 'system'
         WHERE "ASSET_ID" = p_asset_id
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
