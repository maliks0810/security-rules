-- ID-BB-Company-Null-For-Benchmark catalog-scoped revert workflow.
-- Copied verbatim from SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES
-- (same three passes: drift / suppress-expiry / override-mismatch),
-- with only the procedure name and the hard-coded catalog name
-- changed. RESULT_DATA field references (ALADDIN_VALUE / BBG_VALUE)
-- are kept as-is -- adjust them to the keys this catalog's SQL
-- actually emits if different.
--
-- Returns the total number of EXCEPTION rows reverted
-- (drift + suppress + override-mismatch combined).

CREATE OR REPLACE PROCEDURE SP_REVERT_TO_NEW_IDBBCOMPANY_NULL_FOR_BENCHMARK()
RETURNS NUMBER
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    today             DATE          := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    now_ts            TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
    suppress_id       NUMBER        := NULL;
    override_id       NUMBER        := NULL;
    drift_affected    NUMBER        := 0;
    suppress_affected NUMBER        := 0;
    override_affected NUMBER        := 0;
BEGIN
    SELECT "EXCEPTION_STATUS_ID" INTO :suppress_id
    FROM "EXCEPTION_STATUS"
    WHERE "NAME" = 'Suppress'
    LIMIT 1;

    SELECT "EXCEPTION_STATUS_ID" INTO :override_id
    FROM "EXCEPTION_STATUS"
    WHERE "NAME" = 'Override'
    LIMIT 1;

    UPDATE "EXCEPTION" e
       SET "STATUS_ID"     = 1,
           "OPEN_DATE"     = COALESCE(e."OPEN_DATE", :today),
           "SUPPRESS_DATE" = NULL,
           "CLOSE_DATE"    = NULL,
           "MODIFIED_DATE" = :now_ts,
           "MODIFIED_BY"   = 'system'
      FROM (
          SELECT h."RULE_ID",
                 h."ASSET_ID",
                 TRY_PARSE_JSON(h."RESULT_DATA"):"ALADDIN_VALUE"::VARCHAR AS hist_aladdin,
                 TRY_PARSE_JSON(h."RESULT_DATA"):"BBG_VALUE"::VARCHAR     AS hist_bbg
            FROM (
                SELECT "RULE_ID", "ASSET_ID", "RESULT_DATA",
                       ROW_NUMBER() OVER (
                           PARTITION BY "RULE_ID", "ASSET_ID"
                           ORDER BY "EXCEPTION_DATE" DESC NULLS LAST,
                                    "BATCH_ID"       DESC NULLS LAST
                       ) AS rn
                  FROM "EXCEPTION_HIST"
            ) h
           WHERE h.rn = 1
      ) prev
     WHERE e."RULE_ID"  = prev."RULE_ID"
       AND e."ASSET_ID" = prev."ASSET_ID"
       AND e."STATUS_ID" <> 1
       AND e."RULE_ID" IN (
           SELECT r."RULE_ID"
             FROM "RULE" r
             JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
            WHERE rc."NAME" = 'ID BB Company Null For Benchmark'
       )
       AND (
           NOT EQUAL_NULL(
               TRY_PARSE_JSON(e."RESULT_DATA"):"ALADDIN_VALUE"::VARCHAR,
               prev.hist_aladdin
           )
           OR NOT EQUAL_NULL(
               TRY_PARSE_JSON(e."RESULT_DATA"):"BBG_VALUE"::VARCHAR,
               prev.hist_bbg
           )
       );
    drift_affected := SQLROWCOUNT;

    IF (:suppress_id IS NOT NULL) THEN
        UPDATE "EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "SUPPRESS_DATE" = NULL,
               "CLOSE_DATE"    = NULL,
               "MODIFIED_DATE" = :now_ts,
               "MODIFIED_BY"   = 'system'
         WHERE e."STATUS_ID"    = :suppress_id
           AND e."SUPPRESS_DATE" IS NOT NULL
           AND e."SUPPRESS_DATE" < :today
           AND e."RULE_ID" IN (
               SELECT r."RULE_ID"
                 FROM "RULE" r
                 JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
                WHERE rc."NAME" = 'ID BB Company Null For Benchmark'
           );
        suppress_affected := SQLROWCOUNT;
    END IF;

    IF (:override_id IS NOT NULL) THEN
        UPDATE "EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "CLOSE_DATE"    = NULL,
               "SUPPRESS_DATE" = NULL,
               "OPEN_DATE"     = COALESCE(e."OPEN_DATE", :today),
               "MODIFIED_DATE" = :now_ts,
               "MODIFIED_BY"   = 'system'
         WHERE e."STATUS_ID" = :override_id
           AND NOT EQUAL_NULL(
                   TRY_PARSE_JSON(e."RESULT_DATA"):"ALADDIN_VALUE"::VARCHAR,
                   TRY_PARSE_JSON(e."RESULT_DATA"):"BBG_VALUE"::VARCHAR
               )
           AND e."RULE_ID" IN (
               SELECT r."RULE_ID"
                 FROM "RULE" r
                 JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
                WHERE rc."NAME" = 'ID BB Company Null For Benchmark'
           );
        override_affected := SQLROWCOUNT;
    END IF;

    RETURN drift_affected + suppress_affected + override_affected;
END;
$$;
