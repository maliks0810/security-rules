DROP FUNCTION IF EXISTS public."LIST_RULES"(varchar);

CREATE OR REPLACE FUNCTION public."LIST_RULES"("PROCESS_TYPE" varchar(15))
RETURNS TABLE(
    "RULE_ID"      numeric(38, 0),
    "RULE_NAME"    varchar,
    "RULE_COMMAND" varchar,
    "ENVIRONMENT"  varchar
)
LANGUAGE sql
AS $$
    SELECT
        "RULE_ID",
        "RULE_NAME",
        "RULE_COMMAND",
        "ENVIRONMENT"
    FROM public."RULE";
$$;
