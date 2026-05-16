
--SELECT * FROM 
--SELECT * FROM TCW_CORE_DEV.DATA_QUALITY.SECURITY_EXCEPTION WHERE ASSET_ID = '38384LJ83'
--SELECT COALESCE(MAX("SECURITY_EXCEPTION_ID"), 0) FROM SECURITY_EXCEPTION
--SELECT * FROM RULE
--SELECT CURRENT_TIMESTAMP()
--38384LJ83




CALL INSERT_SECURITY_EXCEPTION(
    20133,                          -- SECURITY_EXCEPTION_ID
    101,                             -- RULE_ID
    CURRENT_TIMESTAMP(),             -- RUN_DATE
    CURRENT_TIMESTAMP(),             -- RUN_START
    NULL,                            -- RUN_END
    1,                               -- RESULT_TYPE_ID
    1,                               -- EXCEPTION_STATUS_ID
    1,                               -- SEVERITY_TYPE_ID
    1,                               -- PROCESS_TYPE_ID
    1,                               -- CATEGORY_TYPE_ID
    'demo',                          -- ASSIGN_TO
    NULL,                            -- ASSIGN_TO_DATE
    NULL,                            -- RESOLVE_DATE
    NULL,                            -- BUS_TERM_SOURCE_ID
    'Test Exception 12',               -- ISSUE_DESCRIPTION
    NULL,                            -- SOURCE_SYSTEM_CODE
    CURRENT_TIMESTAMP(),             -- CREATED_DATE
    'demo',                          -- CREATED_BY
    'demo',                          -- MODIFIED_BY
    CURRENT_TIMESTAMP(),             -- MODIFIED_DATE
    1,                               -- EXCEPTION_SOURCE_ID
    NULL,                            -- EXCEPTION_TYPE_ID
    NULL,                            -- DQM_APP_ID
    NULL,                            -- ASSET_TYPE_ID
    NULL,                            -- ASSET
    NULL,                            -- CUSIP_TYPE_CODE
    'demo',                          -- ASSIGNED_BY
    NULL,                            -- COMMENTS
    '38384LJ83'                      -- ALADDIN_ID
);

select 124.0/558.0
select (631.97 - 723.87) / 631.97


SELECT 
S.AS_OF_DATE
,BH.ASOFDATEKEY
,CREATED_DATE
,S.SECURITY_GROUP_TYPE
,S.ALADDIN_ID
,S.ID_BB_GLOBAL
,CASE WHEN S.HELD_STATUS IN (1,3) THEN 'HELD'
WHEN S.HELD_STATUS = 2 THEN 'BENCHMARK'
ELSE 'NOT_HELD' END HELD_STATUS_DESC
,S.BCLASS_LEVEL1
,S.BCLASS_LEVEL2
,S.BCLASS_LEVEL3
,S.BCLASS_LEVEL4
,BH.CLASSIFICATION_LEVEL_1_NAME
,BH.CLASSIFICATION_LEVEL_2_NAME
,BH.CLASSIFICATION_LEVEL_3_NAME
,BH.CLASSIFICATION_LEVEL_4_NAME

FROM TCW_CORE.TDC.SECURITY_VW S 
JOIN TCW_CORE.COMMON.BBG_DATA_LICENSE_SECURITY_HIST_VW BH ON S.ID_BB_GLOBAL = BH.ID_BB_GLOBAL AND S.AS_OF_DATE_KEY = BH.ASOFDATEKEY

WHERE S.ALADDIN_ID = 'Z96LJ05G1'


SELECT SECTOR_TITLE, BREAKDOWN_TAG, AS_OF_DATE FROM TCW_ALADDIN.INVESTMENTS.SECURITY_BREAKDOWN WHERE ALADDIN_ID = 'Z96LJ05G1' AND BREAKDOWN_TAG = 'TCWBCLASS' ORDER BY AS_OF_DATE DESC


select dfs.field_label, dfs.list_name, dfs.list_type, dft.field_type_name
from dim_field_specification dfs
join dim_field_type dft on dft.field_type_id = dfs.field_type_id
where dfs.field_type_id = 2
;

AS_OF_DATE_KEY
LIST_NAME
LIST_DESCRIPTION
LIST_TYPE
