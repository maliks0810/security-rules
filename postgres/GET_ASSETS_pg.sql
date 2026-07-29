-- GET_ASSETS sources from the slim EXCEPTION table. Priority / severity /
-- type / rule-catalog all come from RULE (the rule's own attributes),
-- joined to the corresponding EXCEPTION_*_TYPE lookups for their NAMEs.
-- FIGI is the most-recent EXCEPTION.ID_BB_GLOBAL per asset, and ASSIGN_TO
-- is the most-recent DM_USER.USER. The aggregate result is one row per
-- asset that has at least one matching exception.

DROP FUNCTION IF EXISTS public."SP_GET_ASSETS"(text, text, text, text, text, text, text);
DROP FUNCTION IF EXISTS public."SP_GET_ASSETS"(text, text, text, text, text, text, text, text);

CREATE OR REPLACE FUNCTION public."SP_GET_ASSETS"(
    p_exception_type   text DEFAULT NULL,
    p_severity         text DEFAULT NULL,
    p_priority         text DEFAULT NULL,
    p_rule_catalog     text DEFAULT NULL,
    p_rule_name        text DEFAULT NULL,
    p_exception_state  text DEFAULT NULL,
    p_assign_to        text DEFAULT NULL,
    p_rule_group       text DEFAULT NULL
)
RETURNS TABLE(
    "EXCEPTION_DATE"       timestamp without time zone,
    "PRIORITY"             text,
    "SEVERITY"             text,
    "TYPE"                 text,
    "ASSIGN_TO"            text,
    "ASSET_ID"             character varying,
    "FIGI"                 text,
    "SECURITY_DESCRIPTION" text,
    "TRADER"               text,
    "TRADING_TEAM"         text,
    "EXCEPTION_COUNT"      integer,
    "BBG_LAST_REFRESH"     text,
    "ALL_COMPLETE"         boolean
)
LANGUAGE sql
AS $$
    WITH filtered AS (
        SELECT
            e."ASSET_ID",
            e."EXCEPTION_TIME",
            e."ID_BB_GLOBAL",
            ept."NAME"       AS priority_name,
            ept."SORT_ORDER" AS priority_rank,
            est."NAME"       AS severity_name,
            est."SORT_ORDER" AS severity_rank,
            et."NAME"        AS type_name,
            et."SORT_ORDER"  AS type_rank,
            es."NAME"        AS state_name,
            du."USER"        AS assign_to_user
        FROM public."EXCEPTION" e
        JOIN public."RULE" r
          ON r."RULE_ID" = e."RULE_ID"
        LEFT JOIN public."EXCEPTION_PRIORITY_TYPE" ept
          ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
        LEFT JOIN public."EXCEPTION_SEVERITY_TYPE" est
          ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
        LEFT JOIN public."EXCEPTION_TYPE" et
          ON et."EXCEPTION_TYPE_ID" = r."EXCEPTION_TYPE_ID"
        LEFT JOIN public."RULE_CATALOG" rc
          ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
        LEFT JOIN public."RULE_GROUP" rg
          ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
        LEFT JOIN public."EXCEPTION_STATE" es
          ON es."EXCEPTION_STATE_ID" = e."STATE_ID"
        -- Latest RULE_ASSIGN_OVERRIDE row per RULE_ID (see
        -- SP_GET_EXCEPTIONS for the full precedence rationale).
        LEFT JOIN (
            SELECT DISTINCT ON ("RULE_ID") "RULE_ID", "ASSIGN_TO_ID"
            FROM public."RULE_ASSIGN_OVERRIDE"
            ORDER BY "RULE_ID",
                     "CREATED_DATE" DESC,
                     "RULE_ASSIGN_OVERRIDE_ID" DESC
        ) rao ON rao."RULE_ID" = r."RULE_ID"
        LEFT JOIN public."DM_USER" du
          ON du."ID" = COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
        WHERE (p_exception_type   IS NULL OR et."NAME"  = p_exception_type)
          AND (p_severity         IS NULL OR est."NAME" = p_severity)
          AND (p_priority         IS NULL OR ept."NAME" = p_priority)
          AND (p_rule_group       IS NULL OR p_rule_group       = 'All' OR rg."NAME"      = p_rule_group)
          AND (p_rule_catalog     IS NULL OR p_rule_catalog     = 'All' OR rc."NAME"      = p_rule_catalog)
          AND (p_rule_name        IS NULL OR p_rule_name        = 'All' OR r."RULE_NAME" = p_rule_name)
          AND (p_exception_state  IS NULL OR p_exception_state  = 'All' OR es."NAME"      = p_exception_state)
          AND (p_assign_to        IS NULL OR p_assign_to        = 'All' OR du."USER"      = p_assign_to)
    )
    SELECT
        MAX(f."EXCEPTION_TIME")                                                      AS "EXCEPTION_DATE",
        (array_agg(f.priority_name ORDER BY f.priority_rank ASC NULLS LAST))[1]      AS "PRIORITY",
        (array_agg(f.severity_name ORDER BY f.severity_rank ASC NULLS LAST))[1]      AS "SEVERITY",
        (array_agg(f.type_name     ORDER BY f.type_rank     ASC NULLS LAST))[1]      AS "TYPE",
        (array_agg(f.assign_to_user ORDER BY f."EXCEPTION_TIME" DESC NULLS LAST))[1] AS "ASSIGN_TO",
        f."ASSET_ID"                                                                 AS "ASSET_ID",
        (array_agg(f."ID_BB_GLOBAL"::text ORDER BY f."EXCEPTION_TIME" DESC NULLS LAST))[1]
                                                                                     AS "FIGI",
        'XYZ'                                                                        AS "SECURITY_DESCRIPTION",
        'Colman Slain'                                                               AS "TRADER",
        'ABS'                                                                        AS "TRADING_TEAM",
        COUNT(*) FILTER (WHERE f.state_name IS DISTINCT FROM 'Complete')::int        AS "EXCEPTION_COUNT",
        '10:55 AM'                                                                   AS "BBG_LAST_REFRESH",
        -- ALL_COMPLETE is an asset-level property: true iff every EXCEPTION row
        -- for the asset has status 'Complete', regardless of the user's filters.
        -- Computed via a correlated subquery against the unfiltered EXCEPTION
        -- table so the green styling tracks the underlying reality, not the
        -- current view.
        (SELECT COUNT(*) > 0
                AND COUNT(*) FILTER (WHERE es_all."NAME" IS DISTINCT FROM 'Complete') = 0
           FROM public."EXCEPTION" e_all
           LEFT JOIN public."EXCEPTION_STATE" es_all
             ON es_all."EXCEPTION_STATE_ID" = e_all."STATE_ID"
          WHERE e_all."ASSET_ID" = f."ASSET_ID")                                     AS "ALL_COMPLETE"
    FROM filtered f
    GROUP BY f."ASSET_ID"
    ORDER BY f."ASSET_ID";
$$;
