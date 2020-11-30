-- sqls for learning/testing purposes; make sure the db is created before running
-- CREATE DATABASE hr_restricted;
REVOKE CONNECT ON DATABASE hr_restricted FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS employees;

CREATE ROLE employees_schema_admin WITH LOGIN PASSWORD 'foobarbizzbang';
CREATE ROLE employees_webuser_base NOINHERIT;
CREATE ROLE employees_admin BYPASSRLS;
CREATE ROLE employees_reader;
CREATE ROLE employees_writer;

-- cascading base webuser role to read, write, admin
GRANT employees_webuser_base TO employees_reader, employees_writer, employees_admin;

-- **** GRANT PRIVILEGES TO SCHEMA OWNER ****
GRANT CONNECT ON DATABASE hr_restricted TO employees_schema_admin;
GRANT ALL ON SCHEMA employees TO employees_schema_admin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA employees TO employees_schema_admin;
GRANT TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA employees TO employees_schema_admin;

-- **** GRANT PRIVILEGES TO BASE WEB USER (that others inherit) ****
GRANT CONNECT ON DATABASE hr_restricted TO employees_webuser_base;

GRANT USAGE ON SCHEMA employees TO employees_webuser_base;

GRANT SELECT ON ALL TABLES IN SCHEMA employees TO employees_webuser_base;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA employees TO employees_webuser_base;

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA employees TO employees_webuser_base;

-- ********* GRANT ADDITIONAL PRIVILEGES TO WRITE & ADMIN ROLES ********
GRANT INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA employees TO employees_writer, employees_admin;

GRANT ALL ON ALL SEQUENCES IN SCHEMA employees TO employees_writer, employees_admin;

GRANT ALL ON ALL FUNCTIONS IN SCHEMA employees TO employees_writer, employees_admin;

-- **** Ensure future objects created by the schema owner are accesible to other roles ****

ALTER DEFAULT PRIVILEGES FOR ROLE employees_schema_admin IN SCHEMA employees GRANT SELECT ON TABLES TO employees_webuser_base;

ALTER DEFAULT PRIVILEGES FOR ROLE employees_schema_admin IN SCHEMA employees GRANT SELECT, USAGE ON SEQUENCES TO employees_webuser_base;

ALTER DEFAULT PRIVILEGES FOR ROLE employees_schema_admin IN SCHEMA employees GRANT EXECUTE ON FUNCTIONS TO employees_webuser_base;

ALTER DEFAULT PRIVILEGES FOR ROLE employees_schema_admin IN SCHEMA employees GRANT INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON TABLES TO employees_writer, employees_admin;

ALTER DEFAULT PRIVILEGES FOR ROLE employees_schema_admin IN SCHEMA employees GRANT ALL ON SEQUENCES TO employees_writer, employees_admin;

ALTER DEFAULT PRIVILEGES FOR ROLE employees_schema_admin IN SCHEMA employees GRANT ALL ON FUNCTIONS TO employees_writer, employees_admin;

-- **** CREATE USERS WE'LL USE TO LOGIN ****
CREATE ROLE employees_webapp WITH LOGIN PASSWORD 'foo';
ALTER ROLE employees_webapp SET search_path TO employees;
GRANT employees_writer TO employees_webapp;

CREATE ROLE employees_webapp_admin WITH LOGIN PASSWORD 'foobar';
ALTER ROLE employees_webapp_admin SET search_path TO employees;
GRANT employees_admin TO employees_webapp_admin;

CREATE ROLE employees_webapp_ro WITH LOGIN PASSWORD 'foobarbizz';
ALTER ROLE employees_webapp_ro SET search_path TO employees;
GRANT employees_reader TO employees_webapp_ro;
