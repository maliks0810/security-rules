-- Returns the subset of RULE_GROUP rows the given operator is
-- authorized to see, filtered via RULE_GROUP_AUTHORIZATION. The
-- authorization row's ACCESS_LIST is a comma-separated list of
-- emails; membership is checked by splitting on ',' and comparing
-- each token (case-insensitive, whitespace-trimmed) against the
-- user's DM_USER.EMAIL.
--
-- Inputs:
--   P_USER — DM_USER."USER" display name (Okta will supply this once
--            integration lands; hard-coded pre-cutover on the client).
--
-- Column shape matches SP_GET_RULE_GROUPS exactly so the LHS tree
-- can consume either endpoint without reshape logic.
--
-- Unknown user, user with no email, or a rule group with no
-- authorization row → row not returned. Callers treat "no groups"
-- as least-privileged (empty tree).

CREATE OR REPLACE PROCEDURE SP_GET_RULE_GROUPS_FOR_USER(
    P_USER VARCHAR
)
RETURNS TABLE(
    "NAME"                   VARCHAR,
    "FLAG_STATUS_VISIBLE"    BOOLEAN,
    "FLAG_COMMENTS_VISIBLE"  BOOLEAN,
    "FLAG_SUPPRESS_DATE"     BOOLEAN,
    "FLAG_ASSIGN_TO_VISIBLE" BOOLEAN
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT rg."NAME",
               COALESCE(rg."FLAG_STATUS_VISIBLE",    FALSE) AS "FLAG_STATUS_VISIBLE",
               COALESCE(rg."FLAG_COMMENTS_VISIBLE",  FALSE) AS "FLAG_COMMENTS_VISIBLE",
               COALESCE(rg."FLAG_SUPPRESS_DATE",     FALSE) AS "FLAG_SUPPRESS_DATE",
               COALESCE(rg."FLAG_ASSIGN_TO_VISIBLE", FALSE) AS "FLAG_ASSIGN_TO_VISIBLE"
        FROM "RULE_GROUP" rg
        WHERE rg."RULE_GROUP_ID" IN (
            SELECT DISTINCT rga."RULE_GROUP_ID"
            FROM "RULE_GROUP_AUTHORIZATION" rga
            JOIN "DM_USER" du
              ON UPPER(du."USER") = UPPER(:P_USER)
            WHERE du."EMAIL" IS NOT NULL
              AND du."EMAIL" <> ''
              AND EXISTS (
                  SELECT 1
                  FROM LATERAL SPLIT_TO_TABLE(rga."ACCESS_LIST", ',') t
                  WHERE UPPER(TRIM(t.VALUE::STRING)) = UPPER(du."EMAIL")
              )
        )
        ORDER BY rg."RULE_GROUP_ID" ASC
    );
    RETURN TABLE(res);
END;
$$;
