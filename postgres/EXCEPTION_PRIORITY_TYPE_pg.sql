DROP TABLE IF EXISTS public."EXCEPTION_PRIORITY_TYPE";

CREATE TABLE public."EXCEPTION_PRIORITY_TYPE" (
    "EXCEPTION_PRIORITY_TYPE_ID" integer,
    "NAME"                       varchar(100),
    "SORT_ORDER"                 integer,
    "CREATED_BY"                 varchar(100),
    "CREATED_DATE"               timestamp
);

INSERT INTO public."EXCEPTION_PRIORITY_TYPE" (
    "EXCEPTION_PRIORITY_TYPE_ID", "NAME", "SORT_ORDER", "CREATED_BY", "CREATED_DATE"
) VALUES
    (1, 'High',   10, CURRENT_USER, CURRENT_TIMESTAMP),
    (2, 'Medium', 20, CURRENT_USER, CURRENT_TIMESTAMP),
    (3, 'Low',    30, CURRENT_USER, CURRENT_TIMESTAMP);
