-- Country-Of-Risk-Null-For-Benchmark catalog-scoped revert workflow.
-- Modeled on SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES but the
-- drift / override "values disagree" checks are replaced with a direct
-- NULL check against SECURITY_CURRENT_VW.COUNTRY_OF_RISK_CODE for the
-- row's ASSET_ID.
--
-- Three passes, mirroring the Bloomberg SP:
--
--   Pass 1 (condition-still-true): any non-New, non-Suppress,
--   non-Override row in the catalog whose asset still shows
--   COUNTRY_OF_RISK_CODE IS NULL is reverted to New. Suppress and
--   Override are handled by passes 2 and 3 so each status is reverted
--   through exactly one path.
--
--   Pass 2 (suppress-expiry): any Suppress row whose SUPPRESS_DATE
--   has passed (< today UTC) reverts to New and the SUPPRESS_DATE is
--   cleared. Independent of the null check - an expired suppression
--   always re-evaluates.
--
--   Pass 3 (override): any Override row whose asset still shows
--   COUNTRY_OF_RISK_CODE IS NULL reverts. CLOSE_DATE always carried
--   by an Override row, so clearing it here is required not
--   defensive.
--
-- "No SECURITY_CURRENT_VW row for the ASSET_ID" is treated as "not
-- null" (EXISTS fails) and does NOT revert - that keeps the proc
-- conservative: without a confirmed null we leave the operator's
-- closure alone.
--
-- Returns the total number of EXCEPTION rows reverted
-- (null-check + suppress-expiry + override combined).

CREATE OR REPLACE PROCEDURE SP_REVERT_TO_NEW_COUNTRY_OF_RISK_NULL_FOR_BENCHMARK()
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
    null_affected     NUMBER        := 0;
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

    -- Pass 1: non-New, non-Suppress, non-Override rows where the
    -- asset's COUNTRY_OF_RISK_CODE is still NULL.
    UPDATE "EXCEPTION" e
       SET "STATUS_ID"     = 1,
           "OPEN_DATE"     = COALESCE(e."OPEN_DATE", :today),
           "SUPPRESS_DATE" = NULL,
           "CLOSE_DATE"    = NULL,
           "MODIFIED_DATE" = :now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE e."STATUS_ID" <> 1
       AND (:suppress_id IS NULL OR e."STATUS_ID" <> :suppress_id)
       AND (:override_id IS NULL OR e."STATUS_ID" <> :override_id)
       AND e."RULE_ID" IN (
           SELECT r."RULE_ID"
             FROM "RULE" r
             JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
            WHERE rc."NAME" = 'Country Of Risk Null For Benchmark'
       )
       AND EXISTS (
           SELECT 1
             FROM TDC.SECURITY_CURRENT_VW scv
            WHERE scv."ALADDIN_ID"           = e."ASSET_ID"
              AND scv."COUNTRY_OF_RISK_CODE" IS NULL
       );
    null_affected := SQLROWCOUNT;

    -- Pass 2: expired Suppress sweep.
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
                WHERE rc."NAME" = 'Country Of Risk Null For Benchmark'
           );
        suppress_affected := SQLROWCOUNT;
    END IF;

    -- Pass 3: Override rows where the asset's COUNTRY_OF_RISK_CODE is
    -- still NULL. Mirrors the Bloomberg SP's dedicated Override pass.
    IF (:override_id IS NOT NULL) THEN
        UPDATE "EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "CLOSE_DATE"    = NULL,
               "SUPPRESS_DATE" = NULL,
               "OPEN_DATE"     = COALESCE(e."OPEN_DATE", :today),
               "MODIFIED_DATE" = :now_ts,
               "MODIFIED_BY"   = 'system'
         WHERE e."STATUS_ID" = :override_id
           AND e."RULE_ID" IN (
               SELECT r."RULE_ID"
                 FROM "RULE" r
                 JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
                WHERE rc."NAME" = 'Country Of Risk Null For Benchmark'
           )
           AND EXISTS (
               SELECT 1
                 FROM TDC.SECURITY_CURRENT_VW scv
                WHERE scv."ALADDIN_ID"           = e."ASSET_ID"
                  AND scv."COUNTRY_OF_RISK_CODE" IS NULL
           );
        override_affected := SQLROWCOUNT;
    END IF;

    RETURN null_affected + suppress_affected + override_affected;
END;
$$;
