DROP FUNCTION IF EXISTS public."UPDATE_ASSIGN_TO"(character varying, text);

-- Updates ASSIGN_TO_ID on every SECURITY_EXCEPTION row for the given asset,
-- resolving the user name against DM_USER. Passing an empty/NULL p_assign_to
-- clears the assignment (sets ASSIGN_TO_ID to NULL).
CREATE OR REPLACE FUNCTION public."UPDATE_ASSIGN_TO"(
    p_asset_id  character varying,
    p_assign_to text
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH updated AS (
        UPDATE public."SECURITY_EXCEPTION"
           SET "ASSIGN_TO_ID" = CASE
               WHEN p_assign_to IS NULL OR p_assign_to = '' THEN NULL
               ELSE (
                   SELECT "ID"
                   FROM public."DM_USER"
                   WHERE "USER" = p_assign_to
                   LIMIT 1
               )
           END,
           "MODIFIED_DATE" = CURRENT_TIMESTAMP,
           "MODIFIED_BY"   = 'system'
         WHERE "ASSET_ID" = p_asset_id
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
