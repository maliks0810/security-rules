CREATE OR REPLACE PROCEDURE SP_GET_RULE_NAMES(
    P_RULE_CATALOG VARCHAR
)
RETURNS TABLE(
    "RULE_NAME"        VARCHAR,
    "RULE_DESCRIPTION" VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    -- Returns individual RULE_NAMEs (and their RULE_DESCRIPTION) belonging
    -- to a given catalog. Used by the tcw-dqm tree view to display the
    -- friendlier description on the leaf when present (fall back to
    -- RULE_NAME) and to populate the Exceptions header subtitle when a
    -- specific rule is selected.
    res := (
        SELECT r."RULE_NAME"        AS "RULE_NAME",
               r."RULE_DESCRIPTION" AS "RULE_DESCRIPTION"
        FROM "RULE" r
        JOIN "RULE_CATALOG" rc
          ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
        WHERE rc."NAME" = :P_RULE_CATALOG
        ORDER BY r."RULE_NAME" ASC
    );
    RETURN TABLE(res);
END;
$$;
