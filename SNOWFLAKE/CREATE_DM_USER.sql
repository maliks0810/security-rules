DROP TABLE IF EXISTS "DQM_USER";
DROP TABLE IF EXISTS "DM_USER";

CREATE TABLE "DM_USER" (
    "ID"   NUMBER AUTOINCREMENT START 1 INCREMENT 1 PRIMARY KEY,
    "USER" VARCHAR(100) NOT NULL,
    -- 'Y' = email this user when a rule run fails. Carried as a
    -- VARCHAR(1) Y/N flag to match the rest of the schema's boolean
    -- style rather than a native BOOLEAN.
    --
    -- No column DEFAULT on purpose: Snowflake cannot add a literal
    -- default to an existing column, so a DEFAULT here would exist only
    -- on freshly created schemas and never on the deployed table. The
    -- value is seeded by the UPDATE below instead, which is the same
    -- thing 200_UPDATE_ADHOC.sql does to an existing deployment - so
    -- both paths end up identical.
    "FLAG_EMAIL_ON_RULE_FAILURE" VARCHAR(1)
);

INSERT INTO "DM_USER" ("USER") VALUES
    ('Unassigned'),
    ('Paul Cohen'),
    ('Jake Rigney'),
    ('Anush Safaryan'),
    ('Jimmy Fu'),
    ('Natasha Cabrera');

-- Every user is opted in to rule-failure email. Unconditional rather
-- than name-by-name: the flag applies to whoever is in the table, and a
-- new seeded user should not silently arrive opted out.
UPDATE "DM_USER" SET "FLAG_EMAIL_ON_RULE_FAILURE" = 'Y';
