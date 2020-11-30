REVOKE CONNECT ON DATABASE restricted_apps FROM PUBLIC;
-- PUBLIC is an implicit group everybody belongs to
-- remove connect privileges from implicitly created users
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;
-- remove all privileges from the public schema for implicitly created users
CREATE SCHEMA IF NOT EXISTS priv;
SET search_path to priv;

-- SCHEMA OWNER --
CREATE ROLE priv_schema_admin_role NOLOGIN;
GRANT CONNECT ON DATABASE restricted_apps TO priv_schema_admin_role;
GRANT CREATE ON SCHEMA priv TO priv_schema_admin_role;
-- Allows grantee to create objects in the schema but not look them up
GRANT TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA priv TO priv_schema_admin_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA priv TO priv_schema_admin_role;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA priv TO priv_schema_admin_role;
CREATE USER priv_schema_admin_user PASSWORD 'schemaadmin';
GRANT priv_schema_admin_role TO priv_schema_admin_user;
-- write a migration that changes table owner to schema_admin

-- WEB APPLICATION CLIENT
CREATE ROLE priv_web_app_client_role NOLOGIN;
GRANT CONNECT ON DATABASE restricted_apps TO priv_web_app_client_role;
GRANT USAGE ON SCHEMA priv TO private_web_app_client_role;
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA priv TO priv_web_app_client_role;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA priv TO priv_web_app_client_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA priv TO priv_web_app_client_role;

--Only the table owner is allowed to ALTER the table. Changing existing tables to the schema_admin



--opposite (for delete resources)
GRANT CONNECT ON DATABASE restricted_apps TO PUBLIC;
GRANT ALL PRIVILEGES ON SCHEMA public TO PUBLIC;
DROP SCHEMA IF EXISTS priv;
DROP ROLE private_schema_admin_role;
--
DROP DATABASE restricted_apps;
DROP ROLE private_schema_admin_role;