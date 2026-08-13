-- GET_USER_PREFERENCES --------------------------------------------------------
-- Returns the saved COLUMN_ORDER (opaque VARCHAR the client encodes
-- as a JSON array of grid column names) for the (user, rule_group,
-- rule_catalog) scope. Name-based inputs so the client never needs
-- surrogate ids — the proc resolves DM_USER.USER, RULE_GROUP.NAME
-- and RULE_CATALOG.NAME internally, mirroring
-- SP_UPDATE_USER_PREFERENCES.
--
-- Inputs:
--   P_USER          — DM_USER."USER" display name.
--   P_RULE_GROUP    — RULE_GROUP.NAME (required for a scoped lookup;
--                     unknown / empty → no row returned).
--   P_RULE_CATALOG  — RULE_CATALOG.NAME. Pass NULL / '' when the LHS
--                     tree is at the group root — the row is then
--                     matched against RULE_CATALOG_ID IS NULL via
--                     EQUAL_NULL (same convention as the upsert).
--
-- Returns a single-column result set with COLUMN_ORDER, or zero
-- rows when no matching preferences row exists. Callers treat zero
-- rows as "no saved layout — fall back to the canonical default".
CREATE OR REPLACE PROCEDURE SP_GET_USER_PREFERENCES(
    P_USER          VARCHAR,
    P_RULE_GROUP    VARCHAR,
    P_RULE_CATALOG  VARCHAR
)
RETURNS TABLE(
    "COLUMN_ORDER" VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT up."COLUMN_ORDER"
        FROM "USER_PREFERENCES" up
        JOIN "DM_USER"    du ON du."ID"            = up."DM_USER_ID"
        JOIN "RULE_GROUP" rg ON rg."RULE_GROUP_ID" = up."RULE_GROUP_ID"
        LEFT JOIN "RULE_CATALOG" rc
               ON rc."RULE_CATALOG_ID" = up."RULE_CATALOG_ID"
        WHERE du."USER" = :P_USER
          AND rg."NAME" = :P_RULE_GROUP
          AND EQUAL_NULL(
                  rc."NAME",
                  CASE
                      WHEN :P_RULE_CATALOG IS NULL OR :P_RULE_CATALOG = ''
                          THEN NULL
                      ELSE :P_RULE_CATALOG
                  END
              )
        LIMIT 1
    );
    RETURN TABLE(res);
END;
$$;
