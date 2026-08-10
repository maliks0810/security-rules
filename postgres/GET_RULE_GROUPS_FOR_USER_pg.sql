DROP FUNCTION IF EXISTS public."SP_GET_RULE_GROUPS_FOR_USER"(text);

-- Same column shape as SP_GET_RULE_GROUPS but filtered to the rule
-- groups the given operator is authorized to see via
-- RULE_GROUP_AUTHORIZATION. The authorization row's ACCESS_LIST is a
-- comma-separated email list; membership is verified by splitting on
-- ',' and comparing each token (case-insensitive, whitespace-trimmed)
-- against the user's DM_USER.EMAIL. Unknown user, no email, or no
-- auth row → empty result (least-privileged). Powers the LHS tree
-- view; the frontend hard-codes p_user pre-Okta.
CREATE OR REPLACE FUNCTION public."SP_GET_RULE_GROUPS_FOR_USER"(
    p_user text
)
RETURNS TABLE (
    "NAME"                   text,
    "FLAG_STATUS_VISIBLE"    boolean,
    "FLAG_COMMENTS_VISIBLE"  boolean,
    "FLAG_SUPPRESS_DATE"     boolean,
    "FLAG_ASSIGN_TO_VISIBLE" boolean
)
LANGUAGE sql
AS $$
    SELECT rg."NAME"::text,
           COALESCE(rg."FLAG_STATUS_VISIBLE",    FALSE) AS "FLAG_STATUS_VISIBLE",
           COALESCE(rg."FLAG_COMMENTS_VISIBLE",  FALSE) AS "FLAG_COMMENTS_VISIBLE",
           COALESCE(rg."FLAG_SUPPRESS_DATE",     FALSE) AS "FLAG_SUPPRESS_DATE",
           COALESCE(rg."FLAG_ASSIGN_TO_VISIBLE", FALSE) AS "FLAG_ASSIGN_TO_VISIBLE"
    FROM public."RULE_GROUP" rg
    WHERE rg."RULE_GROUP_ID" IN (
        SELECT DISTINCT rga."RULE_GROUP_ID"
        FROM public."RULE_GROUP_AUTHORIZATION" rga
        JOIN public."DM_USER" du
          ON upper(du."USER") = upper(p_user)
        WHERE du."EMAIL" IS NOT NULL
          AND du."EMAIL" <> ''
          AND EXISTS (
              SELECT 1
              FROM unnest(string_to_array(rga."ACCESS_LIST", ',')) AS t(email)
              WHERE upper(btrim(t.email)) = upper(du."EMAIL")
          )
    )
    ORDER BY rg."RULE_GROUP_ID" ASC;
$$;
