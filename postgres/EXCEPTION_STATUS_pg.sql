DROP TABLE IF EXISTS public."EXCEPTION_STATUS";

CREATE TABLE public."EXCEPTION_STATUS" (
    "EXCEPTION_STATUS_ID" integer,
    "NAME"                varchar(100),
    "SORT_ORDER"          integer,
    "CREATED_BY"          varchar(100),
    "CREATED_DATE"        timestamp
);

INSERT INTO public."EXCEPTION_STATUS" (
    "EXCEPTION_STATUS_ID", "NAME", "SORT_ORDER", "CREATED_BY", "CREATED_DATE"
) VALUES
    (1, 'New',       10, CURRENT_USER, CURRENT_TIMESTAMP),
    (2, 'Accept',    20, CURRENT_USER, CURRENT_TIMESTAMP),
    (3, 'Suppress',  30, CURRENT_USER, CURRENT_TIMESTAMP),
    -- Hold: a Suppress whose SUPPRESS_DATE is fixed at 2 business days
    -- out rather than operator-chosen. SORT_ORDER 35 puts it directly
    -- after Suppress in the status dropdown.
    (7, 'Hold',      35, CURRENT_USER, CURRENT_TIMESTAMP),
    (4, 'Challenge', 40, CURRENT_USER, CURRENT_TIMESTAMP),
    (5, 'Override',  50, CURRENT_USER, CURRENT_TIMESTAMP),
    (6, 'Research',  60, CURRENT_USER, CURRENT_TIMESTAMP);
