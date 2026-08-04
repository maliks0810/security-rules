CREATE OR REPLACE PROCEDURE SP_GET_RULES(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS TABLE(
    "RULE_CATALOG_ID"        NUMBER,
    "RULE_CATALOG_NAME"      VARCHAR,
    "RULE_COMMAND"           VARCHAR,
    "ENVIRONMENT"            VARCHAR,
    "REVERT_TO_NEW_CRITERIA" VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT rc."RULE_CATALOG_ID"         AS "RULE_CATALOG_ID",
               rc."NAME"                    AS "RULE_CATALOG_NAME",
               rc."RULE_CATALOG_SOURCE"     AS "RULE_COMMAND",
               rc."RULE_CATALOG_CONNECTION" AS "ENVIRONMENT",
               rc."REVERT_TO_NEW_CRITERIA"  AS "REVERT_TO_NEW_CRITERIA"
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
