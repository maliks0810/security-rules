-- GET_EXCEPTION_COUNTS_BY_GROUP -----------------------------------------------
-- Returns one row per RULE_GROUP with the count of EXCEPTION rows
-- currently in scope, filtered by the same predicates the count
-- panel used to send to SP_GET_EXCEPTIONS in its N-call fanout.
-- Aggregation-only, so this stays one query regardless of how many
-- groups the operator is authorized for. Status filter is
-- intentionally NOT respected (see DqMonitorPage groupCounts effect).
CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_COUNTS_BY_GROUP(
    P_EXCEPTION_TYPE  VARCHAR DEFAULT NULL,
    P_SEVERITY        VARCHAR DEFAULT NULL,
    P_PRIORITY        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATE VARCHAR DEFAULT NULL,
    P_ASSIGN_TO       VARCHAR DEFAULT NULL,
    -- EXCEPTION_DATE cut-off, mirroring SP_GET_EXCEPTIONS. Required —
    -- callers resolve the date themselves rather than leaning on a
    -- server-side CURRENT_DATE default, which breaks on holidays and
    -- weekends when the newest EXCEPTION rows predate today.
    --
    -- Without it these counts spanned every date in EXCEPTION while the
    -- grid showed a single day, so the panel read far higher than the
    -- rows behind it. Deliberately a hard equality below rather than an
    -- "IS NULL OR" escape hatch: an optional date is exactly what let
    -- this procedure drift away from SP_GET_EXCEPTIONS to begin with.
    P_EXCEPTION_DATE  DATE    DEFAULT NULL
)
RETURNS TABLE(
    "RULE_GROUP" VARCHAR,
    "COUNT"      NUMBER
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT rg."NAME"  AS "RULE_GROUP",
               COUNT(*)   AS "COUNT"
        FROM "EXCEPTION" e
        JOIN "RULE"                        r   ON r."RULE_ID"                     = e."RULE_ID"
        JOIN "RULE_CATALOG"                rc  ON rc."RULE_CATALOG_ID"            = r."RULE_CATALOG_ID"
        JOIN "RULE_GROUP"                  rg  ON rg."RULE_GROUP_ID"              = rc."RULE_GROUP_ID"
        LEFT JOIN "EXCEPTION_TYPE"          et  ON et."EXCEPTION_TYPE_ID"          = r."EXCEPTION_TYPE_ID"
        LEFT JOIN "EXCEPTION_PRIORITY_TYPE" ept ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
        LEFT JOIN "EXCEPTION_SEVERITY_TYPE" est ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
        LEFT JOIN "EXCEPTION_STATE"         es  ON es."EXCEPTION_STATE_ID"         = e."STATE_ID"
        LEFT JOIN "DM_USER" du
          ON du."ID" = COALESCE(e."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
        -- Every param treats BOTH '' and 'All' as "no filter". The two
        -- sentinels used to be split inconsistently (the first three
        -- honored '' only, the last two 'All' only), which zeroed the
        -- count panel either way: the client sends 'All' for a default
        -- dropdown, and an omitted query param arrives here as ''
        -- since the Go layer forwards the raw string with no nil
        -- conversion. Accepting both keeps this correct whichever
        -- the caller uses.
        WHERE e."EXCEPTION_DATE" = :P_EXCEPTION_DATE
          AND (:P_EXCEPTION_TYPE  IS NULL OR :P_EXCEPTION_TYPE  IN ('', 'All') OR et."NAME"  = :P_EXCEPTION_TYPE)
          AND (:P_SEVERITY        IS NULL OR :P_SEVERITY        IN ('', 'All') OR est."NAME" = :P_SEVERITY)
          AND (:P_PRIORITY        IS NULL OR :P_PRIORITY        IN ('', 'All') OR ept."NAME" = :P_PRIORITY)
          AND (:P_EXCEPTION_STATE IS NULL OR :P_EXCEPTION_STATE IN ('', 'All') OR es."NAME"  = :P_EXCEPTION_STATE)
          AND (:P_ASSIGN_TO       IS NULL OR :P_ASSIGN_TO       IN ('', 'All') OR du."USER" = :P_ASSIGN_TO)
        GROUP BY rg."NAME"
    );
    RETURN TABLE(res);
END;
$$;
