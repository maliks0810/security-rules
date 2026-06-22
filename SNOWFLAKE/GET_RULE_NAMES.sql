CREATE OR REPLACE PROCEDURE GET_RULE_NAMES(
    P_RULE_CATALOG VARCHAR
)
RETURNS TABLE("RULE_NAME" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    -- Returns individual RULE_NAMEs belonging to a given catalog. Used by
    -- the tcw-dqm tree view (Group -> Catalog -> Rule) since GET_RULES now
    -- returns one row per catalog rather than one row per rule.
    res := (
        SELECT r."RULE_NAME"
        FROM "RULE" r
        JOIN "RULE_CATALOG" rc
          ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
        WHERE rc."NAME" = :P_RULE_CATALOG
        ORDER BY r."RULE_NAME" ASC
    );
    RETURN TABLE(res);
END;
$$;
