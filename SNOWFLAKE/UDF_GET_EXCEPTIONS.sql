-- Table-valued SQL UDF that replaces the SP_GET_EXCEPTIONS wrapper.
-- Semantics are identical (same columns, same filters, same rao
-- override precedence) but the body is a pure SELECT rather than a
-- LANGUAGE SQL procedure's RESULTSET-then-RETURN scaffold. Snowflake
-- inlines table UDFs into the caller's query plan the same way it
-- treats parameterized views, so:
--   - no per-call SP compilation (100–300 ms saved when warm)
--   - the optimizer can push predicates + prune micro-partitions
--     across the UDF boundary (SPs are opaque scopes)
--   - each call still appears in QUERY_HISTORY as its own SELECT so
--     latency is observable
--
-- Call site (Go repository): SELECT * FROM TABLE(UDF_GET_EXCEPTIONS(...))
--
-- All 11 parameters are required — Snowflake table UDFs do not
-- support DEFAULT values for parameters like SPs do. The repository
-- always passes today's UTC date as P_EXCEPTION_DATE; empty-string
-- filter args map to NULL client-side (nilIfEmpty in Go).
--
-- SP_GET_EXCEPTIONS.sql is left in place for rollback safety —
-- switching Go back to CALL SP_GET_EXCEPTIONS(...) is a one-line
-- change if the UDF ever misbehaves.

CREATE OR REPLACE FUNCTION UDF_GET_EXCEPTIONS(
    P_ASSET_ID          VARCHAR,
    P_EXCEPTION_TYPE    VARCHAR,
    P_SEVERITY          VARCHAR,
    P_PRIORITY          VARCHAR,
    P_RULE_CATALOG      VARCHAR,
    P_RULE_NAME         VARCHAR,
    P_RULE_GROUP        VARCHAR,
    P_EXCEPTION_STATE   VARCHAR,
    P_ASSIGN_TO         VARCHAR,
    P_RULE_NAME_PATTERN VARCHAR,
    P_EXCEPTION_DATE    DATE
)
RETURNS TABLE (
    "EXCEPTION_ID"      NUMBER,
    "RULE_ID"           NUMBER,
    "RULE_NAME"         VARCHAR,
    "ASSET_ID"          VARCHAR,
    "EXCEPTION_DATE"    DATE,
    "EXCEPTION_TIME"    TIMESTAMP_NTZ,
    "ID_BB_GLOBAL"      VARCHAR,
    "STATE_ID"          NUMBER,
    "EXCEPTION_STATE"   VARCHAR,
    "STATUS_ID"         NUMBER,
    "EXCEPTION_STATUS"  VARCHAR,
    "COMMENTS"          VARCHAR,
    "ISSUE_DESCRIPTION" VARCHAR,
    "RESULT_DATA"       VARCHAR,
    "SUPPRESS_DATE"     DATE,
    "OPEN_DATE"         DATE,
    "CLOSE_DATE"        DATE,
    "ASSIGN_TO_ID"      NUMBER,
    "ASSIGN_TO"         VARCHAR,
    "RESULT_TYPE_ID"    NUMBER,
    "PRIORITY"          VARCHAR,
    "SEVERITY"          VARCHAR,
    "EXCEPTION_TYPE"    VARCHAR,
    "CREATED_DATE"      TIMESTAMP_NTZ,
    "CREATED_BY"        VARCHAR,
    "MODIFIED_DATE"     TIMESTAMP_NTZ,
    "MODIFIED_BY"       VARCHAR
)
AS
$$
    SELECT e."EXCEPTION_ID"            AS "EXCEPTION_ID",
           e."RULE_ID"                 AS "RULE_ID",
           r."RULE_NAME"               AS "RULE_NAME",
           e."ASSET_ID"                AS "ASSET_ID",
           e."EXCEPTION_DATE"          AS "EXCEPTION_DATE",
           e."EXCEPTION_TIME"          AS "EXCEPTION_TIME",
           e."ID_BB_GLOBAL"            AS "ID_BB_GLOBAL",
           e."STATE_ID"                AS "STATE_ID",
           es."NAME"                   AS "EXCEPTION_STATE",
           e."STATUS_ID"               AS "STATUS_ID",
           est_s."NAME"                AS "EXCEPTION_STATUS",
           e."COMMENTS"                AS "COMMENTS",
           e."ISSUE_DESCRIPTION"       AS "ISSUE_DESCRIPTION",
           TO_VARCHAR(e."RESULT_DATA") AS "RESULT_DATA",
           e."SUPPRESS_DATE"           AS "SUPPRESS_DATE",
           e."OPEN_DATE"               AS "OPEN_DATE",
           e."CLOSE_DATE"              AS "CLOSE_DATE",
           COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID") AS "ASSIGN_TO_ID",
           du."USER"                   AS "ASSIGN_TO",
           e."RESULT_TYPE_ID"          AS "RESULT_TYPE_ID",
           ept."NAME"                  AS "PRIORITY",
           est."NAME"                  AS "SEVERITY",
           et."NAME"                   AS "EXCEPTION_TYPE",
           e."CREATED_DATE"            AS "CREATED_DATE",
           e."CREATED_BY"              AS "CREATED_BY",
           e."MODIFIED_DATE"           AS "MODIFIED_DATE",
           e."MODIFIED_BY"             AS "MODIFIED_BY"
    FROM "EXCEPTION" e
    LEFT JOIN "RULE"                    r     ON r."RULE_ID"                     = e."RULE_ID"
    LEFT JOIN "EXCEPTION_TYPE"          et    ON et."EXCEPTION_TYPE_ID"          = r."EXCEPTION_TYPE_ID"
    LEFT JOIN "EXCEPTION_PRIORITY_TYPE" ept   ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
    LEFT JOIN "EXCEPTION_SEVERITY_TYPE" est   ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
    LEFT JOIN "RULE_CATALOG"            rc    ON rc."RULE_CATALOG_ID"            = r."RULE_CATALOG_ID"
    LEFT JOIN "RULE_GROUP"              rg    ON rg."RULE_GROUP_ID"              = rc."RULE_GROUP_ID"
    LEFT JOIN "EXCEPTION_STATE"         es    ON es."EXCEPTION_STATE_ID"         = e."STATE_ID"
    LEFT JOIN "EXCEPTION_STATUS"        est_s ON est_s."EXCEPTION_STATUS_ID"     = e."STATUS_ID"
    -- Latest RULE_ASSIGN_OVERRIDE row per RULE_ID (written by Bulk
    -- Assign). Precedence: per-row EXCEPTION.ASSIGN_TO_ID wins over
    -- the bulk override, which wins over the RULE default.
    LEFT JOIN (
        SELECT "RULE_ID", "ASSIGN_TO_ID"
        FROM (
            SELECT "RULE_ID", "ASSIGN_TO_ID",
                   ROW_NUMBER() OVER (
                       PARTITION BY "RULE_ID"
                       ORDER BY "CREATED_DATE" DESC,
                                "RULE_ASSIGN_OVERRIDE_ID" DESC
                   ) AS rn
            FROM "RULE_ASSIGN_OVERRIDE"
        )
        WHERE rn = 1
    ) rao ON rao."RULE_ID" = r."RULE_ID"
    LEFT JOIN "DM_USER"                 du    ON du."ID" = COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
    WHERE e."EXCEPTION_DATE" = P_EXCEPTION_DATE
      AND (P_ASSET_ID          IS NULL OR e."ASSET_ID" = P_ASSET_ID)
      AND (P_EXCEPTION_TYPE    IS NULL OR et."NAME"    = P_EXCEPTION_TYPE)
      AND (P_SEVERITY          IS NULL OR est."NAME"   = P_SEVERITY)
      AND (P_PRIORITY          IS NULL OR ept."NAME"   = P_PRIORITY)
      AND (P_RULE_CATALOG      IS NULL OR P_RULE_CATALOG = 'All' OR rc."NAME" = P_RULE_CATALOG)
      AND (P_RULE_NAME         IS NULL OR P_RULE_NAME    = 'All' OR r."RULE_NAME" = P_RULE_NAME)
      AND (P_RULE_GROUP        IS NULL OR P_RULE_GROUP   = 'All' OR rg."NAME"     = P_RULE_GROUP)
      AND (P_EXCEPTION_STATE   IS NULL OR P_EXCEPTION_STATE = 'All' OR es."NAME" = P_EXCEPTION_STATE)
      AND (P_ASSIGN_TO         IS NULL OR P_ASSIGN_TO = 'All' OR du."USER" = P_ASSIGN_TO)
      AND (P_RULE_NAME_PATTERN IS NULL OR r."RULE_NAME" ILIKE P_RULE_NAME_PATTERN)
$$;
