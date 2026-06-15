DROP FUNCTION IF EXISTS public."COMPLETE_SECURITY_EXCEPTION"(character varying, numeric);
DROP FUNCTION IF EXISTS public."UPDATE_EXCEPTION_STATUS"(character varying, numeric);
DROP FUNCTION IF EXISTS public."UPDATE_SECURITY_EXCEPTION_STATUS"(character varying, numeric);

-- Marks the SECURITY_EXCEPTION row identified by (ASSET_ID, RULE_ID) as
-- Complete, but only if it is currently Pending. Other statuses are
-- left untouched. Used by ExecuteRules for previously-existing exceptions
-- that the rule no longer flags.
CREATE OR REPLACE FUNCTION public."UPDATE_SECURITY_EXCEPTION_STATUS"(
    p_asset_id character varying,
    p_rule_id  numeric
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH updated AS (
        UPDATE public."SECURITY_EXCEPTION"
           SET "EXCEPTION_STATUS_ID" = 4,
               "MODIFIED_DATE"       = CURRENT_TIMESTAMP,
               "MODIFIED_BY"         = 'system'
         WHERE "ASSET_ID"            = p_asset_id
           AND "RULE_ID"             = p_rule_id
           AND "EXCEPTION_STATUS_ID" = 1
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
