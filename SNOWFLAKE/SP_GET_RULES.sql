CREATE OR REPLACE PROCEDURE SP_GET_RULES(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS TABLE(
    "RULE_CATALOG_ID"   NUMBER,
    "RULE_CATALOG_NAME" VARCHAR,
    "RULE_COMMAND"      VARCHAR,
    "ENVIRONMENT"       VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    -- Returns one row per RULE_CATALOG. RULE_COMMAND is RULE_CATALOG_SOURCE
    -- (the SQL the Go ExecuteRule layer runs; the result set must include
    -- a RULE_ID column per row). ENVIRONMENT is RULE_CATALOG_CONNECTION.
    --
    -- Filtering:
    --   P_RULE_TYPE = 'CATALOG'
    --     â†’ P_RULE_NAME matched against RULE_CATALOG.NAME.
    --   P_RULE_TYPE = 'GROUP'
    --     â†’ P_RULE_NAME matched against RULE_GROUP.NAME; returns every
    --       catalog whose RULE_GROUP_ID resolves to that group.
    --   P_RULE_TYPE = 'RULE'
    --     â†’ P_RULE_NAME matched against RULE.RULE_NAME; returns the
    --       catalog(s) that own that rule (EXISTS-join to RULE so the
    --       catalog row still appears at most once).
    --   P_RULE_TYPE NULL / unset OR P_RULE_NAME NULL / empty / 'All'
    --     â†’ no filter, return every catalog.
    res := (
        SELECT rc."RULE_CATALOG_ID"         AS "RULE_CATALOG_ID",
               rc."NAME"                    AS "RULE_CATALOG_NAME",
               rc."RULE_CATALOG_SOURCE"     AS "RULE_COMMAND",
               rc."RULE_CATALOG_CONNECTION" AS "ENVIRONMENT"
        FROM "RULE_CATALOG" rc
        LEFT JOIN "RULE_GROUP" rg
          ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
        WHERE :P_RULE_NAME IS NULL
           OR :P_RULE_NAME = ''
           OR :P_RULE_NAME = 'All'
           OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) = 'CATALOG'
                 AND rc."NAME" = :P_RULE_NAME)
           OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                 AND rg."NAME"  = :P_RULE_NAME)
           OR (UPPER(:P_RULE_TYPE) = 'RULE'
                 AND EXISTS (
                     SELECT 1 FROM "RULE" r
                      WHERE r."RULE_CATALOG_ID" = rc."RULE_CATALOG_ID"
                        AND r."RULE_NAME"       = :P_RULE_NAME
                 ))
    );
    RETURN TABLE(res);
END;
$$;
