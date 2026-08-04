-- Bloomberg-catalog-scoped revert workflow. For every EXCEPTION row in
-- the 'Bloomberg Compare Differences' catalog that is not currently
-- 'New', flip it back to New (with OPEN_DATE = today) when EITHER of
-- the two RESULT_DATA JSON values has drifted since the previous run:
--   * ALADDIN_VALUE differs from the last archived hist row's value, OR
--   * BBG_VALUE     differs from the last archived hist row's value.
-- "Previous run" = the EXCEPTION_HIST row with the max
-- (EXCEPTION_DATE, BATCH_ID) per (RULE_ID, ASSET_ID). Same day's later
-- batches win when today has archives; falls through to yesterday's
-- final batch on the first run of a fresh day.
--
-- Additionally, any Suppress row whose SUPPRESS_DATE has passed
-- (< today UTC) reverts to New regardless of value drift and its
-- SUPPRESS_DATE is cleared. This duplicates SP_EXPIRE_SUPPRESS_DATES's
-- global sweep but keeps the Bloomberg revert workflow self-contained
-- for callers that invoke this SP directly (Rule Catalog's
-- REVERT_TO_NEW_CRITERIA).
--
-- Returns the total number of EXCEPTION rows reverted (drift + suppress
-- combined).

CREATE OR REPLACE PROCEDURE SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES()
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    today             DATE          := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    now_ts            TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
    suppress_id       NUMBER        := NULL;
    drift_affected    NUMBER        := 0;
    suppress_affected NUMBER        := 0;
BEGIN
    SELECT "EXCEPTION_STATUS_ID" INTO :suppress_id
    FROM "EXCEPTION_STATUS"
    WHERE "NAME" = 'Suppress'
    LIMIT 1;

    -- Pass 1: ALADDIN_VALUE / BBG_VALUE drift vs the latest hist row.
    UPDATE "EXCEPTION" e
       SET "STATUS_ID"     = 1,
           "OPEN_DATE"     = :today,
           "SUPPRESS_DATE" = NULL,
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
            WHERE rc."NAME" = 'Bloomberg Compare Differences'
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

    -- Pass 2: Suppress rows whose SUPPRESS_DATE has passed. Independent
    -- of hist so rows with no prior hist still get expired.
    -- OPEN_DATE is intentionally NOT ratcheted here — a suppression
    -- lapsing is not the same signal as a fresh discovery, so the
    -- original open date is preserved to keep the aging metric honest.
    IF (:suppress_id IS NOT NULL) THEN
        UPDATE "EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "SUPPRESS_DATE" = NULL,
               "MODIFIED_DATE" = :now_ts,
               "MODIFIED_BY"   = 'system'
         WHERE e."STATUS_ID"    = :suppress_id
           AND e."SUPPRESS_DATE" IS NOT NULL
           AND e."SUPPRESS_DATE" < :today
           AND e."RULE_ID" IN (
               SELECT r."RULE_ID"
                 FROM "RULE" r
                 JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
                WHERE rc."NAME" = 'Bloomberg Compare Differences'
           );
        suppress_affected := SQLROWCOUNT;
    END IF;

    RETURN drift_affected + suppress_affected;
END;
$$;
