DROP TABLE IF EXISTS public."EXCEPTION_TYPE";

CREATE TABLE public."EXCEPTION_TYPE" (
    "EXCEPTION_TYPE_ID" integer,
    "NAME"              varchar(100),
    "SORT_ORDER"        integer,
    "CREATED_BY"        varchar(100),
    "CREATED_DATE"      timestamp
);

INSERT INTO public."EXCEPTION_TYPE" (
    "EXCEPTION_TYPE_ID", "NAME", "SORT_ORDER", "CREATED_BY", "CREATED_DATE"
) VALUES
    (1, 'Security Setup',         10,  CURRENT_USER, CURRENT_TIMESTAMP),
    (2, 'Trade Queue Management', 20,  CURRENT_USER, CURRENT_TIMESTAMP),
    (3, 'Process/Workflow',       30,  CURRENT_USER, CURRENT_TIMESTAMP),
    (4, 'Corporate Actions',      40,  CURRENT_USER, CURRENT_TIMESTAMP),
    (5, 'Analytics',              50,  CURRENT_USER, CURRENT_TIMESTAMP),
    (6, 'Portfolio',              110, CURRENT_USER, CURRENT_TIMESTAMP),
    (7, 'Index',                  120, CURRENT_USER, CURRENT_TIMESTAMP);
