-- Returns one row per RULE under the given RULE_GROUP, projected as
-- (rule_name, catalog_name, description). Collapses what the LHS
-- tree used to do in N+1 round-trips (SP_GET_RULE_CATALOGS(group) →
-- SP_GET_RULE_NAMES(catalog) per catalog) into a single call, powers
-- the count panel's ruleName → catalog + description lookup map.
--
-- Only IS_ACTIVE = 1 rules are returned — matches SP_GET_RULE_NAMES.
-- Empty group → empty result.

CREATE OR REPLACE PROCEDURE SP_GET_RULES_FOR_GROUP(
    P_RULE_GROUP VARCHAR
)
RETURNS TABLE(
    "RULE_NAME"        VARCHAR,
    "CATALOG_NAME"     VARCHAR,
    "RULE_DESCRIPTION" VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT r."RULE_NAME"        AS "RULE_NAME",
               rc."NAME"            AS "CATALOG_NAME",
               r."RULE_DESCRIPTION" AS "RULE_DESCRIPTION"
        FROM "RULE" r
        JOIN "RULE_CATALOG" rc
          ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
        JOIN "RULE_GROUP"   rg
          ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
        WHERE rg."NAME" = :P_RULE_GROUP
          AND r."IS_ACTIVE" = 1
        ORDER BY rc."NAME" ASC, r."RULE_NAME" ASC
    );
    RETURN TABLE(res);
END;
$$;
