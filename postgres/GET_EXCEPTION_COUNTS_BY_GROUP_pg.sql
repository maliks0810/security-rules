-- Every superseded signature dropped: adding a parameter creates a new
-- overload rather than replacing the old one, and leaving a stale
-- version resident would let an old caller keep resolving to it and
-- silently get the wrong counts.
DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTION_COUNTS_BY_GROUP"(text, text, text, text, text);
DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTION_COUNTS_BY_GROUP"(text, text, text, text, text, date);
DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTION_COUNTS_BY_GROUP"(text, text, text, text, text, date, boolean);

-- Returns one row per RULE_GROUP with the count of exception rows in
-- scope. Postgres mirror of SNOWFLAKE/
-- SP_GET_EXCEPTION_COUNTS_BY_GROUP.sql. Aggregation-only, replaces the
-- N-call fetchExceptions fanout the count panel used to run.
CREATE OR REPLACE FUNCTION public."SP_GET_EXCEPTION_COUNTS_BY_GROUP"(
    p_exception_type  text DEFAULT NULL,
    p_severity        text DEFAULT NULL,
    p_priority        text DEFAULT NULL,
    p_exception_state text DEFAULT NULL,
    p_assign_to       text DEFAULT NULL,
    -- EXCEPTION_DATE cut-off, mirroring SP_GET_EXCEPTIONS. Required --
    -- callers resolve the date rather than leaning on CURRENT_DATE,
    -- which breaks on holidays and weekends when the newest EXCEPTION
    -- rows predate today. Without it these counts spanned every date
    -- while the grid showed a single day, so the panel read far higher
    -- than the rows behind it. Hard equality below, not an
    -- "IS NULL OR" escape hatch -- an optional date is what let this
    -- drift away from SP_GET_EXCEPTIONS to begin with.
    p_exception_date  date DEFAULT NULL,
    -- Which table to count. FALSE reads EXCEPTION; TRUE reads
    -- EXCEPTION_HIST restricted to that day's latest BATCH_ID per
    -- group -- the same source split the grid makes between
    -- SP_GET_EXCEPTIONS and SP_GET_EXCEPTIONS_HIST.
    --
    -- Without this the panel always counted EXCEPTION, which only
    -- holds recent days, so every historical date the LHS date
    -- dropdown offers came back as 0 for every group while the grid
    -- beside it showed rows. The two also disagreed on dates present
    -- in BOTH tables, since the grid read the archived snapshot while
    -- the panel read the live one. The caller decides, so panel and
    -- grid read the same source by construction.
    p_use_hist        boolean DEFAULT false
)
RETURNS TABLE(
    "RULE_GROUP" character varying,
    "COUNT"      bigint
)
LANGUAGE sql
AS $$
    -- Latest archived batch per group for the requested day. Computed
    -- per group rather than globally, because SP_GET_EXCEPTIONS_HIST
    -- resolves MAX(BATCH_ID) within the caller's scope -- a single
    -- global max would silently zero any group whose rows were
    -- archived in an earlier batch that day.
    WITH max_batch AS (
        SELECT rg."RULE_GROUP_ID" AS grp_id, MAX(h."BATCH_ID") AS batch
        FROM public."EXCEPTION_HIST" h
        JOIN public."RULE"         r  ON r."RULE_ID"          = h."RULE_ID"
        JOIN public."RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
        JOIN public."RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
        WHERE p_use_hist
          AND h."EXCEPTION_DATE" = p_exception_date
        GROUP BY rg."RULE_GROUP_ID"
    )
    -- Live branch. Every param treats BOTH '' and 'All' as "no
    -- filter": the client sends 'All' for a default dropdown, and an
    -- omitted query param arrives as '' since the Go layer forwards
    -- the raw string with no nil conversion.
    SELECT rg."NAME"::character varying AS "RULE_GROUP",
           COUNT(*)                     AS "COUNT"
    FROM public."EXCEPTION" e
    JOIN public."RULE"                         r   ON r."RULE_ID"                      = e."RULE_ID"
    JOIN public."RULE_CATALOG"                 rc  ON rc."RULE_CATALOG_ID"             = r."RULE_CATALOG_ID"
    JOIN public."RULE_GROUP"                   rg  ON rg."RULE_GROUP_ID"               = rc."RULE_GROUP_ID"
    LEFT JOIN public."EXCEPTION_TYPE"          et  ON et."EXCEPTION_TYPE_ID"           = r."EXCEPTION_TYPE_ID"
    LEFT JOIN public."EXCEPTION_PRIORITY_TYPE" ept ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_SEVERITY_TYPE" est ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_STATE"         es  ON es."EXCEPTION_STATE_ID"          = e."STATE_ID"
    LEFT JOIN public."DM_USER" du
      ON du."ID" = COALESCE(e."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
    WHERE NOT p_use_hist
      AND e."EXCEPTION_DATE" = p_exception_date
      AND (p_exception_type  IS NULL OR p_exception_type  IN ('', 'All') OR et."NAME"  = p_exception_type)
      AND (p_severity        IS NULL OR p_severity        IN ('', 'All') OR est."NAME" = p_severity)
      AND (p_priority        IS NULL OR p_priority        IN ('', 'All') OR ept."NAME" = p_priority)
      AND (p_exception_state IS NULL OR p_exception_state IN ('', 'All') OR es."NAME"  = p_exception_state)
      AND (p_assign_to       IS NULL OR p_assign_to       IN ('', 'All') OR du."USER" = p_assign_to)
    GROUP BY rg."NAME"

    UNION ALL

    -- Archived branch: same shape, same filters, EXCEPTION_HIST pinned
    -- to each group's latest batch for the day.
    SELECT rg."NAME"::character varying AS "RULE_GROUP",
           COUNT(*)                     AS "COUNT"
    FROM public."EXCEPTION_HIST" e
    JOIN public."RULE"                         r   ON r."RULE_ID"                      = e."RULE_ID"
    JOIN public."RULE_CATALOG"                 rc  ON rc."RULE_CATALOG_ID"             = r."RULE_CATALOG_ID"
    JOIN public."RULE_GROUP"                   rg  ON rg."RULE_GROUP_ID"               = rc."RULE_GROUP_ID"
    JOIN max_batch mb ON mb.grp_id = rg."RULE_GROUP_ID" AND e."BATCH_ID" = mb.batch
    LEFT JOIN public."EXCEPTION_TYPE"          et  ON et."EXCEPTION_TYPE_ID"           = r."EXCEPTION_TYPE_ID"
    LEFT JOIN public."EXCEPTION_PRIORITY_TYPE" ept ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_SEVERITY_TYPE" est ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_STATE"         es  ON es."EXCEPTION_STATE_ID"          = e."STATE_ID"
    LEFT JOIN public."DM_USER" du
      ON du."ID" = COALESCE(e."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
    WHERE p_use_hist
      AND e."EXCEPTION_DATE" = p_exception_date
      AND (p_exception_type  IS NULL OR p_exception_type  IN ('', 'All') OR et."NAME"  = p_exception_type)
      AND (p_severity        IS NULL OR p_severity        IN ('', 'All') OR est."NAME" = p_severity)
      AND (p_priority        IS NULL OR p_priority        IN ('', 'All') OR ept."NAME" = p_priority)
      AND (p_exception_state IS NULL OR p_exception_state IN ('', 'All') OR es."NAME"  = p_exception_state)
      AND (p_assign_to       IS NULL OR p_assign_to       IN ('', 'All') OR du."USER" = p_assign_to)
    GROUP BY rg."NAME";
$$;
