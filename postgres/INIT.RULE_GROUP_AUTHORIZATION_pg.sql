-- =============================================================================
-- INIT.RULE_GROUP_AUTHORIZATION_pg.sql
--
-- Postgres mirror of SNOWFLAKE/INIT.RULE_GROUP_AUTHORIZATION.sql.
-- Seeds the initial authorized-operator list for each RULE_GROUP.
-- Rule-group id is resolved by name so this stays valid across
-- environments where the surrogate sequence has shifted.
--
-- Prerequisites:
--   RULE_GROUP_AUTHORIZATION table exists (RULE_GROUP_AUTHORIZATION_pg.sql).
--   RULE_GROUP rows for the target group names exist (seeded elsewhere);
--   the INSERT SELECT no-ops for any name that isn't present.
--
-- Idempotent: DELETEs any prior rows for the target group before
-- INSERTing. IT_SUPPORT operators are included in every group's
-- access list.
-- =============================================================================

-- Security Master --------------------------------------------------------------
DELETE FROM public."RULE_GROUP_AUTHORIZATION"
 WHERE "RULE_GROUP_ID" = (
    SELECT "RULE_GROUP_ID" FROM public."RULE_GROUP" WHERE "NAME" = 'Security Master'
 );

INSERT INTO public."RULE_GROUP_AUTHORIZATION"
    ("RULE_GROUP_ID", "ACCESS_LIST", "CREATED_DATE", "CREATED_BY")
SELECT
    "RULE_GROUP_ID",
    'Joann.Banks@tcw.com,paul.cohen@tcw.com,jimmy.fu@tcw.com,anush.safaryan@tcw.com,naomi.lynch@tcw.com,jake.rigney@tcw.com,Sumit.Malik@tcw.com,Ethan.Abraham@tcw.com,Mukesh.Verma@tcw.com,Shrenik.Doshi@tcw.com,Mark.Segura@tcw.com,Ken.Desouza@tcw.com,Manish.Ghayalod@tcw.com,Ari.Novosyolok@tcw.com,Gregory.Killeen@tcw.com,Jay.Nolledo@tcw.com,Bruce.Pople@tcw.com,Melissa.Stolfi@tcw.com,Sidharth.Joshi@tcw.com,Prasanna.Ramamoorthy@tcw.com',
    (NOW() AT TIME ZONE 'UTC'),
    CURRENT_USER
FROM public."RULE_GROUP"
WHERE "NAME" = 'Security Master';

-- Security Master Benchmark ----------------------------------------------------
DELETE FROM public."RULE_GROUP_AUTHORIZATION"
 WHERE "RULE_GROUP_ID" = (
    SELECT "RULE_GROUP_ID" FROM public."RULE_GROUP" WHERE "NAME" = 'Security Master Benchmark'
 );

INSERT INTO public."RULE_GROUP_AUTHORIZATION"
    ("RULE_GROUP_ID", "ACCESS_LIST", "CREATED_DATE", "CREATED_BY")
SELECT
    "RULE_GROUP_ID",
    'Joann.Banks@tcw.com,paul.cohen@tcw.com,jimmy.fu@tcw.com,anush.safaryan@tcw.com,naomi.lynch@tcw.com,jake.rigney@tcw.com,Sumit.Malik@tcw.com,Ethan.Abraham@tcw.com,Mukesh.Verma@tcw.com,Shrenik.Doshi@tcw.com,Mark.Segura@tcw.com,Ken.Desouza@tcw.com,Manish.Ghayalod@tcw.com,Ari.Novosyolok@tcw.com,Gregory.Killeen@tcw.com,Jay.Nolledo@tcw.com,Bruce.Pople@tcw.com,Melissa.Stolfi@tcw.com,Sidharth.Joshi@tcw.com,Prasanna.Ramamoorthy@tcw.com',
    (NOW() AT TIME ZONE 'UTC'),
    CURRENT_USER
FROM public."RULE_GROUP"
WHERE "NAME" = 'Security Master Benchmark';

-- TOD SOD ----------------------------------------------------------------------
DELETE FROM public."RULE_GROUP_AUTHORIZATION"
 WHERE "RULE_GROUP_ID" = (
    SELECT "RULE_GROUP_ID" FROM public."RULE_GROUP" WHERE "NAME" = 'TOD SOD'
 );

INSERT INTO public."RULE_GROUP_AUTHORIZATION"
    ("RULE_GROUP_ID", "ACCESS_LIST", "CREATED_DATE", "CREATED_BY")
SELECT
    "RULE_GROUP_ID",
    'Joann.Banks@tcw.com,paul.cohen@tcw.com,jimmy.fu@tcw.com,anush.safaryan@tcw.com,naomi.lynch@tcw.com,jake.rigney@tcw.com,Sumit.Malik@tcw.com,Ethan.Abraham@tcw.com,Mukesh.Verma@tcw.com,Shrenik.Doshi@tcw.com,Mark.Segura@tcw.com,Ken.Desouza@tcw.com,Manish.Ghayalod@tcw.com,Ari.Novosyolok@tcw.com,Gregory.Killeen@tcw.com,Jay.Nolledo@tcw.com,Bruce.Pople@tcw.com,Melissa.Stolfi@tcw.com,Sidharth.Joshi@tcw.com,Prasanna.Ramamoorthy@tcw.com',
    (NOW() AT TIME ZONE 'UTC'),
    CURRENT_USER
FROM public."RULE_GROUP"
WHERE "NAME" = 'TOD SOD';
