CREATE OR REPLACE PROCEDURE GET_RULES(
    P_PROCESS_TYPE VARCHAR,
    P_RULE_CATALOG VARCHAR DEFAULT NULL
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
    -- Now returns one row per RULE_CATALOG. The RULE_CATALOG_SOURCE query
    -- (returned as RULE_COMMAND) is expected to emit a RULE_ID column per
    -- row when executed; the Go ExecuteRule layer scans that and uses it
    -- as each EXCEPTION's RULE_ID. P_PROCESS_TYPE is accepted for caller
    -- compatibility but ignored — RULE_CATALOG has no process-type column.
    res := (
        SELECT rc."RULE_CATALOG_ID"         AS "RULE_CATALOG_ID",
               rc."NAME"                    AS "RULE_CATALOG_NAME",
               rc."RULE_CATALOG_SOURCE"     AS "RULE_COMMAND",
               rc."RULE_CATALOG_CONNECTION" AS "ENVIRONMENT"
        FROM "RULE_CATALOG" rc
        WHERE (:P_RULE_CATALOG IS NULL OR :P_RULE_CATALOG = 'All' OR rc."NAME" = :P_RULE_CATALOG)
    );
    RETURN TABLE(res);
END;
$$;
