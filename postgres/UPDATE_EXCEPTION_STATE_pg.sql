DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION_STATE"(character varying, numeric);
DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION_STATE"(character varying, numeric, boolean);

-- Stamps MODIFIED_DATE / MODIFIED_BY on every EXCEPTION row matching
-- (ASSET_ID, RULE_ID). When p_complete is true, also flips STATE_ID to 4
-- (Complete). When p_complete is false, state is left untouched â€” used
-- by ExecuteRules to record that the rule re-fired for an existing
-- (RuleID, AssetID) without changing its state.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_EXCEPTION_STATE"(
    p_asset_id character varying,
    p_rule_id  numeric,
    p_complete boolean DEFAULT false
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH updated AS (
        UPDATE public."EXCEPTION"
           SET "STATE_ID"      = CASE WHEN p_complete THEN 4 ELSE "STATE_ID" END,
               "MODIFIED_DATE" = CURRENT_TIMESTAMP,
               "MODIFIED_BY"   = 'system'
         WHERE "ASSET_ID"      = p_asset_id
           AND "RULE_ID"       = p_rule_id::int
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
