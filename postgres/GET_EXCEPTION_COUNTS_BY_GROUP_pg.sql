DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTION_COUNTS_BY_GROUP"(text, text, text, text, text);

-- Returns one row per RULE_GROUP with the count of EXCEPTION rows
-- currently in scope. Postgres mirror of SNOWFLAKE/
-- SP_GET_EXCEPTION_COUNTS_BY_GROUP.sql. Aggregation-only, replaces
-- the N-call fetchExceptions fanout the count panel used to run.
CREATE OR REPLACE FUNCTION public."SP_GET_EXCEPTION_COUNTS_BY_GROUP"(
    p_exception_type  text DEFAULT NULL,
    p_severity        text DEFAULT NULL,
    p_priority        text DEFAULT NULL,
    p_exception_state text DEFAULT NULL,
    p_assign_to       text DEFAULT NULL
)
RETURNS TABLE(
    "RULE_GROUP" character varying,
    "COUNT"      bigint
)
LANGUAGE sql
AS $$
    SELECT rg."NAME"::character varying AS "RULE_GROUP",
           COUNT(*)                     AS "COUNT"
    FROM public."EXCEPTION" e
    JOIN public."RULE"                        r   ON r."RULE_ID"                     = e."RULE_ID"
    JOIN public."RULE_CATALOG"                rc  ON rc."RULE_CATALOG_ID"            = r."RULE_CATALOG_ID"
    JOIN public."RULE_GROUP"                  rg  ON rg."RULE_GROUP_ID"              = rc."RULE_GROUP_ID"
    LEFT JOIN public."EXCEPTION_TYPE"          et  ON et."EXCEPTION_TYPE_ID"          = r."EXCEPTION_TYPE_ID"
    LEFT JOIN public."EXCEPTION_PRIORITY_TYPE" ept ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_SEVERITY_TYPE" est ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_STATE"         es  ON es."EXCEPTION_STATE_ID"         = e."STATE_ID"
    LEFT JOIN LATERAL (
        SELECT rao_inner."ASSIGN_TO_ID"
        FROM public."RULE_ASSIGN_OVERRIDE" rao_inner
        WHERE rao_inner."RULE_ID" = r."RULE_ID"
        ORDER BY rao_inner."CREATED_DATE" DESC,
                 rao_inner."RULE_ASSIGN_OVERRIDE_ID" DESC
        LIMIT 1
    ) rao ON TRUE
    LEFT JOIN public."DM_USER" du
      ON du."ID" = COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
    -- Every param treats BOTH '' and 'All' as "no filter". The two
    -- sentinels used to be split inconsistently (the first three
    -- honored '' only, the last two 'All' only), which zeroed the
    -- count panel either way: the client sends 'All' for a default
    -- dropdown, and an omitted query param arrives here as '' since
    -- the Go layer forwards the raw string with no nil conversion.
    -- Accepting both keeps this correct whichever the caller uses.
    WHERE (p_exception_type  IS NULL OR p_exception_type  IN ('', 'All') OR et."NAME"  = p_exception_type)
      AND (p_severity        IS NULL OR p_severity        IN ('', 'All') OR est."NAME" = p_severity)
      AND (p_priority        IS NULL OR p_priority        IN ('', 'All') OR ept."NAME" = p_priority)
      AND (p_exception_state IS NULL OR p_exception_state IN ('', 'All') OR es."NAME"  = p_exception_state)
      AND (p_assign_to       IS NULL OR p_assign_to       IN ('', 'All') OR du."USER" = p_assign_to)
    GROUP BY rg."NAME";
$$;
