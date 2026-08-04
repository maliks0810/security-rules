DROP TABLE IF EXISTS public."EXCEPTION_HIST";

CREATE TABLE public."EXCEPTION_HIST" (
    "EXCEPTION_ID"        integer,
    "RULE_ID"             integer,
    "ASSET_ID"            varchar(100),
    "EXCEPTION_DATE"      date,
    "BATCH_ID"            bigint,
    "ID_BB_GLOBAL"        varchar(15),
    "STATE_ID"            integer,
    "STATUS_ID"           integer,
    "COMMENTS"            varchar(2048),
    "EXCEPTION_TIME"      timestamp,
    "ISSUE_DESCRIPTION"   varchar(512),
    "RESULT_DATA"         json,
    "SUPPRESS_DATE"       date,
    -- Copied straight through from EXCEPTION.OPEN_DATE by
    -- SP_ARCHIVE_EXCEPTIONS. History rows never get a fresh OPEN_DATE
    -- of their own — they carry whatever the live row had at archive.
    "OPEN_DATE"           date,
    -- Copied straight through from EXCEPTION.CLOSE_DATE by
    -- SP_ARCHIVE_EXCEPTIONS. Same carry-forward semantics as
    -- OPEN_DATE: history rows never get a fresh CLOSE_DATE of their
    -- own.
    "CLOSE_DATE"          date,
    "ASSIGN_TO_ID"        integer,
    "RESULT_TYPE_ID"      integer,
    "CREATED_DATE"        timestamp,
    "CREATED_BY"          varchar(100),
    "MODIFIED_DATE"       timestamp,
    "MODIFIED_BY"         varchar(100)
);
