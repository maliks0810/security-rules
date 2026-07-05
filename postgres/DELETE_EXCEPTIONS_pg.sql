DROP FUNCTION IF EXISTS public."SP_DELETE_EXCEPTIONS"(text, text);

-- Deletes EXCEPTION rows whose EXCEPTION_DATE = today and whose RULE
-- falls inside the catalog scope implied by (p_rule_name, p_rule_type).
-- Scope rules match GET_RULES:
--   p_rule_type = 'CATALOG' or 'RULE' â†’ p_rule_name = RULE_CATALOG.NAME
--   p_rule_type = 'GROUP'             â†’ p_rule_name = RULE_GROUP.NAME
--   p_rule_name NULL / empty / 'All'  â†’ every catalog (full wipe of today)
-- Returns the number of rows deleted.
CREATE OR REPLACE FUNCTION public."SP_DELETE_EXCEPTIONS"(
    p_rule_name text DEFAULT NULL,
    p_rule_type text DEFAULT NULL
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH deleted AS (
        DELETE FROM public."EXCEPTION"
        WHERE "EXCEPTION_DATE" = (NOW() AT TIME ZONE 'UTC')::date
          AND "RULE_ID" IN (
              SELECT r."RULE_ID"
              FROM public."RULE" r
              JOIN public."RULE_CATALOG" rc      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
              LEFT JOIN public."RULE_GROUP" rg   ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
              WHERE p_rule_name IS NULL
                 OR p_rule_name = ''
                 OR p_rule_name = 'All'
                 OR (UPPER(COALESCE(p_rule_type, 'CATALOG')) IN ('CATALOG','RULE')
                       AND rc."NAME" = p_rule_name)
                 OR (UPPER(p_rule_type) = 'GROUP'
                       AND rg."NAME"  = p_rule_name)
          )
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM deleted;
$$;
