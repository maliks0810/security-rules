DROP FUNCTION IF EXISTS public."SP_REVERT_TO_NEW_COUNTRY_OF_RISK_NULL_FOR_BENCHMARK"();

-- Country-Of-Risk-Null-For-Benchmark catalog-scoped revert workflow.
-- Copied verbatim from SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES
-- (same three passes: drift / suppress-expiry / override-mismatch),
-- with only the function name and the hard-coded catalog name
-- changed. RESULT_DATA field references (ALADDIN_VALUE / BBG_VALUE)
-- are kept as-is -- adjust them to the keys this catalog's SQL
-- actually emits if different.
CREATE OR REPLACE FUNCTION public."SP_REVERT_TO_NEW_COUNTRY_OF_RISK_NULL_FOR_BENCHMARK"()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_today             date      := (NOW() AT TIME ZONE 'UTC')::date;
    v_now_ts            timestamp := (NOW() AT TIME ZONE 'UTC');
    v_suppress_id       integer;
    v_override_id       integer;
    v_drift_affected    integer   := 0;
    v_suppress_affected integer   := 0;
    v_override_affected integer   := 0;
BEGIN
    SELECT "EXCEPTION_STATUS_ID"
      INTO v_suppress_id
      FROM public."EXCEPTION_STATUS"
     WHERE "NAME" = 'Suppress'
     LIMIT 1;

    SELECT "EXCEPTION_STATUS_ID"
      INTO v_override_id
      FROM public."EXCEPTION_STATUS"
     WHERE "NAME" = 'Override'
     LIMIT 1;

    WITH prev AS (
        SELECT DISTINCT ON ("RULE_ID", "ASSET_ID")
               "RULE_ID",
               "ASSET_ID",
               ("RESULT_DATA"->>'ALADDIN_VALUE') AS hist_aladdin,
               ("RESULT_DATA"->>'BBG_VALUE')     AS hist_bbg
          FROM public."EXCEPTION_HIST"
         ORDER BY "RULE_ID", "ASSET_ID",
                  "EXCEPTION_DATE" DESC,
                  "BATCH_ID"       DESC NULLS LAST
    ),
    scoped_rules AS (
        SELECT r."RULE_ID"
          FROM public."RULE" r
          JOIN public."RULE_CATALOG" rc
            ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
         WHERE rc."NAME" = 'Country Of Risk Null For Benchmark'
    ),
    drift_upd AS (
        UPDATE public."EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "OPEN_DATE"     = COALESCE(e."OPEN_DATE", v_today),
               "SUPPRESS_DATE" = NULL,
               "CLOSE_DATE"    = NULL,
               "MODIFIED_DATE" = v_now_ts,
               "MODIFIED_BY"   = 'system'
          FROM prev
         WHERE e."RULE_ID"  = prev."RULE_ID"
           AND e."ASSET_ID" = prev."ASSET_ID"
           AND e."STATUS_ID" <> 1
           AND e."RULE_ID" IN (SELECT "RULE_ID" FROM scoped_rules)
           AND ( (e."RESULT_DATA"->>'ALADDIN_VALUE') IS DISTINCT FROM prev.hist_aladdin
              OR (e."RESULT_DATA"->>'BBG_VALUE')     IS DISTINCT FROM prev.hist_bbg )
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int INTO v_drift_affected FROM drift_upd;

    IF v_suppress_id IS NOT NULL THEN
        WITH scoped_rules AS (
            SELECT r."RULE_ID"
              FROM public."RULE" r
              JOIN public."RULE_CATALOG" rc
                ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             WHERE rc."NAME" = 'Country Of Risk Null For Benchmark'
        ),
        suppress_upd AS (
            UPDATE public."EXCEPTION" e
               SET "STATUS_ID"     = 1,
                   "SUPPRESS_DATE" = NULL,
                   "CLOSE_DATE"    = NULL,
                   "MODIFIED_DATE" = v_now_ts,
                   "MODIFIED_BY"   = 'system'
             WHERE e."STATUS_ID"    = v_suppress_id
               AND e."SUPPRESS_DATE" IS NOT NULL
               AND e."SUPPRESS_DATE" < v_today
               AND e."RULE_ID" IN (SELECT "RULE_ID" FROM scoped_rules)
            RETURNING 1
        )
        SELECT COALESCE(COUNT(*), 0)::int INTO v_suppress_affected FROM suppress_upd;
    END IF;

    IF v_override_id IS NOT NULL THEN
        WITH scoped_rules AS (
            SELECT r."RULE_ID"
              FROM public."RULE" r
              JOIN public."RULE_CATALOG" rc
                ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             WHERE rc."NAME" = 'Country Of Risk Null For Benchmark'
        ),
        override_upd AS (
            UPDATE public."EXCEPTION" e
               SET "STATUS_ID"     = 1,
                   "CLOSE_DATE"    = NULL,
                   "SUPPRESS_DATE" = NULL,
                   "OPEN_DATE"     = COALESCE(e."OPEN_DATE", v_today),
                   "MODIFIED_DATE" = v_now_ts,
                   "MODIFIED_BY"   = 'system'
             WHERE e."STATUS_ID" = v_override_id
               AND (e."RESULT_DATA"->>'ALADDIN_VALUE')
                   IS DISTINCT FROM (e."RESULT_DATA"->>'BBG_VALUE')
               AND e."RULE_ID" IN (SELECT "RULE_ID" FROM scoped_rules)
            RETURNING 1
        )
        SELECT COALESCE(COUNT(*), 0)::int INTO v_override_affected FROM override_upd;
    END IF;

    RETURN v_drift_affected + v_suppress_affected + v_override_affected;
END;
$$;
