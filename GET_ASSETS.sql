CREATE OR REPLACE PROCEDURE GET_ASSETS()
RETURNS TABLE(
    "EXCEPTION_DATE" TIMESTAMP,
    "PRIORITY" VARCHAR,
    "TYPE" VARCHAR,
    "ASSIGN_TO" VARCHAR,
    "ASSET_ID" VARCHAR,
    "FIGI" VARCHAR,
    "SECURITY_DESCRIPTION" VARCHAR,
    "TRADER" VARCHAR,
    "TRADING_TEAM" VARCHAR,
    "EXCEPTION_COUNT" NUMBER(38,0),
    "BBG_LAST_REFRESH" VARCHAR
)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT se.RUN_DATE            AS EXCEPTION_DATE,
               st.CODE                AS PRIORITY,
               'Security Set up'      AS TYPE,
               se.ASSIGN_TO           AS ASSIGN_TO,
               se.ALADDIN_ID          AS ASSET_ID,
               'BBG00G6M2LZ2'         AS FIGI,
               'XYZ'                  AS SECURITY_DESCRIPTION,
               'Colman Slain'         AS TRADER,
               'ABS'                  AS TRADING_TEAM,
               7                      AS EXCEPTION_COUNT,
               '10:55 AM'             AS BBG_LAST_REFRESH
        FROM SECURITY_EXCEPTION se
        JOIN SEVERITY_TYPE st
          ON st.SEVERITY_TYPE_ID = se.SEVERITY_TYPE_ID
        QUALIFY ROW_NUMBER() OVER (PARTITION BY se.ALADDIN_ID ORDER BY se.RUN_DATE DESC) = 1
    );
    RETURN TABLE(res);
END;
$$;
