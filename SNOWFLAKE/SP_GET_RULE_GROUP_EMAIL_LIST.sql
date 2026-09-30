-- Resolves the distinct DM_USER emails to notify for a set of rule
-- catalogs. Chain: P_RULE_CATALOG_IDS -> RULE_CATALOG.RULE_GROUP_ID
-- -> RULE_GROUP_AUTHORIZATION.ACCESS_LIST -> DM_USER rows whose EMAIL
-- appears in that list AND whose FLAG_EMAIL_ON_RULE_FAILURE = 'Y'.
--
-- P_RULE_CATALOG_IDS is a comma-separated list of ids (matches the
-- SPLIT_TO_TABLE convention used by the rest of the bulk SPs).
-- Non-numeric / empty tokens are dropped so a trailing comma or a
-- stray malformed value does not fail the batch.
--
-- ACCESS_LIST is a free-form comma-separated email list: fence both
-- sides with ',' and match ',<email>,' so 'joe@x.com' does not match
-- inside 'joesmith@x.com'. Same pattern as
-- SP_GET_RULE_GROUPS_FOR_USER.
--
-- Empty result is a normal outcome (no authorization row, nobody
-- opted in) and not an error.

CREATE OR REPLACE PROCEDURE SP_GET_RULE_GROUP_EMAIL_LIST(
    P_RULE_CATALOG_IDS VARCHAR
)
RETURNS TABLE("EMAIL" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        WITH ids AS (
            SELECT TRY_TO_NUMBER(TRIM(t.VALUE::STRING)) AS "RULE_CATALOG_ID"
              FROM TABLE(SPLIT_TO_TABLE(:P_RULE_CATALOG_IDS, ',')) t
             WHERE TRY_TO_NUMBER(TRIM(t.VALUE::STRING)) IS NOT NULL
        ),
        groups AS (
            SELECT DISTINCT rc."RULE_GROUP_ID"
              FROM "RULE_CATALOG" rc
              JOIN ids ON ids."RULE_CATALOG_ID" = rc."RULE_CATALOG_ID"
             WHERE rc."RULE_GROUP_ID" IS NOT NULL
        )
        SELECT DISTINCT du."EMAIL"
          FROM "RULE_GROUP_AUTHORIZATION" rga
          JOIN "DM_USER" du
            ON ',' || REPLACE(UPPER(rga."ACCESS_LIST"), ' ', '') || ','
               LIKE '%,' || UPPER(du."EMAIL") || ',%'
         WHERE rga."RULE_GROUP_ID" IN (SELECT "RULE_GROUP_ID" FROM groups)
           AND du."EMAIL" IS NOT NULL
           AND du."EMAIL" <> ''
           AND UPPER(COALESCE(du."FLAG_EMAIL_ON_RULE_FAILURE", 'N')) = 'Y'
    );
    RETURN TABLE(res);
END;
$$;
