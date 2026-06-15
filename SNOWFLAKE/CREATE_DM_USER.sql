DROP TABLE IF EXISTS "DQM_USER";
DROP TABLE IF EXISTS "DM_USER";

CREATE TABLE "DM_USER" (
    "ID"   NUMBER AUTOINCREMENT START 1 INCREMENT 1 PRIMARY KEY,
    "USER" VARCHAR(100) NOT NULL
);

INSERT INTO "DM_USER" ("USER") VALUES
    ('Unassigned'),
    ('Paul Cohen'),
    ('Jake Rigney'),
    ('Anush Safaryan'),
    ('Jimmy Fu'),
    ('Natasha Cabrera');
