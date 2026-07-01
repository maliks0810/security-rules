DROP TABLE IF EXISTS public."EXCEPTION_HIST";

CREATE TABLE public."EXCEPTION_HIST" (
    "EXCEPTION_ID"        integer,
    "RULE_ID"             integer,
    "ASSET_ID"            varchar(100),
    "EXCEPTION_DATE"      date,
    "ID_BB_GLOBAL"        varchar(15),
    "STATE_ID"            integer,
    "COMMENT_ID"          integer,
    "EXCEPTION_TIME"      timestamp,
    "ISSUE_DESCRIPTION"   varchar(512),
    "RESULT_DATA"         json,
    "SUPPRESS_DATE"       date,
    "ASSIGN_TO_ID"        integer,
    "RESULT_TYPE_ID"      integer,
    "CREATED_DATE"        timestamp,
    "CREATED_BY"          varchar(100),
    "MODIFIED_DATE"       timestamp,
    "MODIFIED_BY"         varchar(100)
);
