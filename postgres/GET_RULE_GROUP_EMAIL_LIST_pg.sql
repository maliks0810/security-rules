DROP FUNCTION IF EXISTS public."SP_GET_RULE_GROUP_EMAIL_LIST"(text);

-- Resolves the distinct DM_USER emails to notify for a set of rule
-- catalogs. Chain: p_rule_catalog_ids -> RULE_CATALOG.RULE_GROUP_ID
-- -> RULE_GROUP_AUTHORIZATION.ACCESS_LIST -> DM_USER rows whose EMAIL
-- appears in that list AND whose FLAG_EMAIL_ON_RULE_FAILURE = 'Y'.
--
-- p_rule_catalog_ids is a comma-separated list of ids (matches the
-- SPLIT_TO_TABLE / unnest(string_to_array(...)) convention used by the
-- rest of the bulk SPs). Non-numeric / empty tokens are dropped so a
-- trailing comma or a stray malformed value does not fail the batch.
--
-- ACCESS_LIST is a free-form comma-separated email list: fence both
-- sides with ',' and match ',<email>,' to stop 'joe@x.com' matching
-- inside 'joesmith@x.com'. Same pattern as
-- SP_GET_RULE_GROUPS_FOR_USER.
--
-- Empty result is a normal outcome (no authorization row, nobody
-- opted in) and not an error.
CREATE OR REPLACE FUNCTION public."SP_GET_RULE_GROUP_EMAIL_LIST"(
    p_rule_catalog_ids text
)
RETURNS TABLE("EMAIL" varchar)
LANGUAGE sql
AS $$
    WITH ids AS (
        SELECT btrim(t.id)::bigint AS "RULE_CATALOG_ID"
          FROM unnest(string_to_array(p_rule_catalog_ids, ',')) AS t(id)
         WHERE btrim(t.id) ~ '^[0-9]+$'
    ),
    groups AS (
        SELECT DISTINCT rc."RULE_GROUP_ID"
          FROM public."RULE_CATALOG" rc
          JOIN ids ON ids."RULE_CATALOG_ID" = rc."RULE_CATALOG_ID"
         WHERE rc."RULE_GROUP_ID" IS NOT NULL
    )
    SELECT DISTINCT du."EMAIL"::varchar AS "EMAIL"
      FROM public."RULE_GROUP_AUTHORIZATION" rga
      JOIN public."DM_USER" du
        ON ',' || REPLACE(UPPER(rga."ACCESS_LIST"), ' ', '') || ','
           LIKE '%,' || UPPER(du."EMAIL") || ',%'
     WHERE rga."RULE_GROUP_ID" IN (SELECT "RULE_GROUP_ID" FROM groups)
       AND du."EMAIL" IS NOT NULL
       AND du."EMAIL" <> ''
       AND UPPER(COALESCE(du."FLAG_EMAIL_ON_RULE_FAILURE", 'N')) = 'Y';
$$;
