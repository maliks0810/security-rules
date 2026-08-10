-- =============================================================================
-- INIT.RULE_GROUP_AUTHORIZATION.sql
--
-- Seeds the initial authorized-operator list for each RULE_GROUP.
-- Rule-group id is resolved by name (RULE_GROUP.NAME) so this stays
-- valid across environments where the IDENTITY sequence has shifted.
--
-- Prerequisites:
--   RULE_GROUP_AUTHORIZATION table exists (created by
--   RULE_GROUP_AUTHORIZATION.sql / dqm_init.sql).
--   RULE_GROUP row for 'Security Master' exists (seeded by
--   dqm_seed_data.sql).
--
-- Idempotent: DELETEs any prior rows for the target group before
-- INSERTing, so re-running the file overwrites the access list rather
-- than appending duplicates.
-- =============================================================================

-- Security Master --------------------------------------------------------------
DELETE FROM RULE_GROUP_AUTHORIZATION
 WHERE RULE_GROUP_ID = (
    SELECT RULE_GROUP_ID FROM RULE_GROUP WHERE NAME = 'Security Master'
 );

INSERT INTO RULE_GROUP_AUTHORIZATION
    (RULE_GROUP_ID, ACCESS_LIST, CREATED_DATE, CREATED_BY)
SELECT
    RULE_GROUP_ID,
    'Joann.Banks@tcw.com,paul.cohen@tcw.com,jimmy.fu@tcw.com,anush.safaryan@tcw.com,naomi.lynch@tcw.com,jake.rigney@tcw.com',
    CURRENT_TIMESTAMP()::TIMESTAMP_NTZ(9),
    CURRENT_USER()
FROM RULE_GROUP
WHERE NAME = 'Security Master';
