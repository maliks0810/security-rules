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
--   RULE_GROUP rows for the target group names exist (seeded by
--   dqm_seed_data.sql; the INSERT SELECT below no-ops for any group
--   name that isn't present, so it's safe to run in partially-seeded
--   environments).
--
-- Idempotent: DELETEs any prior rows for the target group before
-- INSERTing, so re-running the file overwrites the access list rather
-- than appending duplicates.
--
-- ACCESS_LIST format: comma-separated emails; matching is case-
-- insensitive and space-tolerant (SP_GET_RULE_GROUPS_FOR_USER
-- normalises both sides with UPPER/REPLACE). IT_SUPPORT operators
-- are included in every group's access list so support staff can see
-- and act on any group's exceptions.
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
    'Joann.Banks@tcw.com,paul.cohen@tcw.com,jimmy.fu@tcw.com,anush.safaryan@tcw.com,naomi.lynch@tcw.com,jake.rigney@tcw.com,Sumit.Malik@tcw.com,Ethan.Abraham@tcw.com,Mukesh.Verma@tcw.com,Shrenik.Doshi@tcw.com,Mark.Segura@tcw.com,Ken.Desouza@tcw.com,Manish.Ghayalod@tcw.com,Ari.Novosyolok@tcw.com,Gregory.Killeen@tcw.com,Jay.Nolledo@tcw.com,Bruce.Pople@tcw.com,Melissa.Stolfi@tcw.com,Sidharth.Joshi@tcw.com,Prasanna.Ramamoorthy@tcw.com',
    CURRENT_TIMESTAMP()::TIMESTAMP_NTZ(9),
    CURRENT_USER()
FROM RULE_GROUP
WHERE NAME = 'Security Master';

-- Security Master Benchmark ----------------------------------------------------
DELETE FROM RULE_GROUP_AUTHORIZATION
 WHERE RULE_GROUP_ID = (
    SELECT RULE_GROUP_ID FROM RULE_GROUP WHERE NAME = 'Security Master Benchmark'
 );

INSERT INTO RULE_GROUP_AUTHORIZATION
    (RULE_GROUP_ID, ACCESS_LIST, CREATED_DATE, CREATED_BY)
SELECT
    RULE_GROUP_ID,
    'Joann.Banks@tcw.com,paul.cohen@tcw.com,jimmy.fu@tcw.com,anush.safaryan@tcw.com,naomi.lynch@tcw.com,jake.rigney@tcw.com,Sumit.Malik@tcw.com,Ethan.Abraham@tcw.com,Mukesh.Verma@tcw.com,Shrenik.Doshi@tcw.com,Mark.Segura@tcw.com,Ken.Desouza@tcw.com,Manish.Ghayalod@tcw.com,Ari.Novosyolok@tcw.com,Gregory.Killeen@tcw.com,Jay.Nolledo@tcw.com,Bruce.Pople@tcw.com,Melissa.Stolfi@tcw.com,Sidharth.Joshi@tcw.com,Prasanna.Ramamoorthy@tcw.com',
    CURRENT_TIMESTAMP()::TIMESTAMP_NTZ(9),
    CURRENT_USER()
FROM RULE_GROUP
WHERE NAME = 'Security Master Benchmark';

-- TOD SOD ----------------------------------------------------------------------
DELETE FROM RULE_GROUP_AUTHORIZATION
 WHERE RULE_GROUP_ID = (
    SELECT RULE_GROUP_ID FROM RULE_GROUP WHERE NAME = 'TOD SOD'
 );

INSERT INTO RULE_GROUP_AUTHORIZATION
    (RULE_GROUP_ID, ACCESS_LIST, CREATED_DATE, CREATED_BY)
SELECT
    RULE_GROUP_ID,
    'Joann.Banks@tcw.com,paul.cohen@tcw.com,jimmy.fu@tcw.com,anush.safaryan@tcw.com,naomi.lynch@tcw.com,jake.rigney@tcw.com,Sumit.Malik@tcw.com,Ethan.Abraham@tcw.com,Mukesh.Verma@tcw.com,Shrenik.Doshi@tcw.com,Mark.Segura@tcw.com,Ken.Desouza@tcw.com,Manish.Ghayalod@tcw.com,Ari.Novosyolok@tcw.com,Gregory.Killeen@tcw.com,Jay.Nolledo@tcw.com,Bruce.Pople@tcw.com,Melissa.Stolfi@tcw.com,Sidharth.Joshi@tcw.com,Prasanna.Ramamoorthy@tcw.com',
    CURRENT_TIMESTAMP()::TIMESTAMP_NTZ(9),
    CURRENT_USER()
FROM RULE_GROUP
WHERE NAME = 'TOD SOD';
