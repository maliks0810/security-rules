DROP FUNCTION IF EXISTS public."SP_GET_RULE_GROUPS"();

CREATE OR REPLACE FUNCTION public."SP_GET_RULE_GROUPS"()
RETURNS TABLE(
    "NAME"                   character varying,
    "FLAG_STATUS_VISIBLE"    boolean,
    "FLAG_COMMENTS_VISIBLE"  boolean,
    "FLAG_SUPPRESS_DATE"     boolean,
    "FLAG_ASSIGN_TO_VISIBLE" boolean
)
LANGUAGE sql
AS $$
    SELECT "NAME",
           COALESCE("FLAG_STATUS_VISIBLE",    false),
           COALESCE("FLAG_COMMENTS_VISIBLE",  false),
           COALESCE("FLAG_SUPPRESS_DATE",     false),
           COALESCE("FLAG_ASSIGN_TO_VISIBLE", false)
    FROM public."RULE_GROUP"
    ORDER BY "RULE_GROUP_ID" ASC;
$$;
