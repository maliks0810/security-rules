CREATE OR REPLACE PROCEDURE SP_DELETE_EXCEPTIONS(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    -- Deletes EXCEPTION rows whose EXCEPTION_DATE = today and whose RULE
    -- falls inside the catalog scope implied by (P_RULE_NAME, P_RULE_TYPE).
    -- Scope rules match GET_RULES:
    --   P_RULE_TYPE = 'CATALOG' or 'RULE' â†’ P_RULE_NAME = RULE_CATALOG.NAME
    --   P_RULE_TYPE = 'GROUP'             â†’ P_RULE_NAME = RULE_GROUP.NAME
    --   P_RULE_NAME NULL / empty / 'All'  â†’ every catalog (full wipe of today)
    DELETE FROM "EXCEPTION"
    WHERE "EXCEPTION_DATE" = TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP))
      AND "RULE_ID" IN (
          SELECT r."RULE_ID"
          FROM "RULE" r
          JOIN "RULE_CATALOG" rc      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
          LEFT JOIN "RULE_GROUP" rg   ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
          WHERE :P_RULE_NAME IS NULL
             OR :P_RULE_NAME = ''
             OR :P_RULE_NAME = 'All'
             OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) IN ('CATALOG','RULE')
                   AND rc."NAME" = :P_RULE_NAME)
             OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                   AND rg."NAME"  = :P_RULE_NAME)
      );
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
