-- Returns one row per RULE_GROUP with the count of EXCEPTION rows
-- currently in scope, filtered by the same predicates the count
-- panel used to send to SP_GET_EXCEPTIONS in its N-call fanout.
-- Aggregation-only, so this stays one query regardless of how many
-- groups the operator is authorized for.
--
-- Filter contract mirrors what the frontend passes when populating
-- the "All" mode count summary — status filter is intentionally
-- NOT respected (see DqMonitorPage groupCounts effect comment).
--
-- Assign-to precedence uses the same COALESCE order as
-- SP_GET_EXCEPTIONS (per-row override → rao override → rule default)
-- so filtering by an assignee returns matching counts.

CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_COUNTS_BY_GROUP(
    P_EXCEPTION_TYPE  VARCHAR DEFAULT NULL,
    P_SEVERITY        VARCHAR DEFAULT NULL,
    P_PRIORITY        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATE VARCHAR DEFAULT NULL,
    P_ASSIGN_TO       VARCHAR DEFAULT NULL
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
        LEFT JOIN "DM_USER" du
          ON du."ID" = COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
        WHERE (:P_EXCEPTION_TYPE  IS NULL OR :P_EXCEPTION_TYPE = '' OR et."NAME"  = :P_EXCEPTION_TYPE)
          AND (:P_SEVERITY        IS NULL OR :P_SEVERITY       = '' OR est."NAME" = :P_SEVERITY)
          AND (:P_PRIORITY        IS NULL OR :P_PRIORITY       = '' OR ept."NAME" = :P_PRIORITY)
          AND (:P_EXCEPTION_STATE IS NULL OR :P_EXCEPTION_STATE = 'All' OR es."NAME" = :P_EXCEPTION_STATE)
          AND (:P_ASSIGN_TO       IS NULL OR :P_ASSIGN_TO       = 'All' OR du."USER" = :P_ASSIGN_TO)
        GROUP BY rg."NAME"
    );
    RETURN TABLE(res);
END;
$$;
