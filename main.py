import psycopg2
from psycopg2 import sql
import logging

logger = logging.getLogger(__name__)

"""
  CloudFormation Custom Resource for creating roles for web applications serving data from restricted databases
  ** For Create Change Sets
  Required Inputs: 
    1) Database name
    2) Schema name (will be created if doesn't exist)
    3) Secrets Manager ARN for: database's superuser, webapp, webapp_admin, schema_admin
  ** For Update Change Sets
  Nothing will happen.
  ** For Deletion Change Sets
  Everything will be undone: roles' privs revoked, roles dropped and privs returned to its initial state.
  Object ownership will be re-sassigned to the db's superuser.
"""
class RestrictedRolesNamespace:
  def __init__(self, db_name, host, superuser, schema_name):
    self.db = db_name
    self.schema = schema_name
    self.host = host
    self.superuser = superuser

  def app_roles(self):
    return {
      "admin_role":       F"{self.schema}_webadmin_role",
      "read_role":        F"{self.schema}_readonly_role",
      "readwrite_role":   F"{self.schema}_readwrite_role",
      "schema_role":      F"{self.schema}_schema_role",
      "webapp_base":      F"{self.schema}_webapp_base",
    }
  
  def app_logins(self):
    return {
      "webapp":       F"{self.schema}_webapp",
      "webapp_admin": F"{self.schema}_webapp_admin",
      "schema_admin": F"{self.schema}_schema_admin"
    }

def db_connection(context):
  return psycopg2.connect(database=context.db, user=context.superuser)

def grant_schema_usage(context):
  sqls = []
  sqls.append(sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC;")
              .format(sql.Identifier(context.db)))
  sqls.append(sql.SQL("REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;"))
  sqls.append(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}")
              .format(sql.Identifier(context.schema)))
  sqls.append(sql.SQL("SET search_path TO {}")
              .format(sql.Identifier(context.schema)))
  return sqls

def create_roles(context):
  sqls = []
  roles = context.app_roles()

  sqls.append(sql.SQL("CREATE ROLE {};")
              .format(sql.Identifier(roles["schema_role"])))
  sqls.append(sql.SQL("CREATE ROLE {} NOINHERIT;")
              .format(sql.Identifier(roles["webapp_base"])))
  sqls.append(sql.SQL("CREATE ROLE {} BYPASSRLS;")
              .format(sql.Identifier(roles["admin_role"])))
  sqls.append(sql.SQL("CREATE ROLE {};")
              .format(sql.Identifier(roles["read_role"])))
  sqls.append(sql.SQL("CREATE ROLE {};")
              .format(sql.Identifier(roles["readwrite_role"])))
  # **** Grant privileges to the base web user role to others for inheritance ****
  sqls.append(sql.SQL("GRANT {appbase} TO {readonly}, {readwrite}, {appadmin};")
              .format(appbase=sql.Identifier(roles["webapp_base"]), 
                      readonly=sql.Identifier(roles["read_role"]),
                      readwrite=sql.Identifier(roles["readwrite_role"]),
                      appadmin=sql.Identifier(roles["admin_role"])))
  return sqls

def grant_schema_owner_privileges(context):
  sqls = []
  schema_role = context.app_roles().get('schema_role')
  sqls.append(sql.SQL("GRANT CONNECT ON DATABASE {db} TO {role};")
              .format(db=sql.Identifier(context.db),
                      role=sql.Identifier(schema_role)))
  sqls.append(sql.SQL("GRANT ALL ON SCHEMA {schema} TO {role};")
              .format(schema=sql.Identifier(context.schema),
                      role=sql.Identifier(schema_role)))
  sqls.append(sql.SQL("GRANT ALL ON ALL SEQUENCES IN SCHEMA {schema} TO {role};")
              .format(schema=sql.Identifier(context.schema),
                      role=sql.Identifier(schema_role)))
  sqls.append(sql.SQL("GRANT TRUNCATE,REFERENCES,TRIGGER ON ALL TABLES IN SCHEMA {schema} TO {role};")
              .format(schema=sql.Identifier(context.schema),
                      role=sql.Identifier(schema_role)))
  return sqls

def grant_base_webapp_privileges(context):
  sqls = []
  webapp_base_role = context.app_roles().get('webapp_base')

  sqls.append(sql.SQL("GRANT CONNECT ON DATABASE {db} TO {role};")
              .format(db=sql.Identifier(context.db),
                      role=sql.Identifier(webapp_base_role)))
  sqls.append(sql.SQL("GRANT USAGE ON SCHEMA {schema} TO {role};")
              .format(schema=sql.Identifier(context.schema),
                      role=sql.Identifier(webapp_base_role)))
  sqls.append(sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role};")
              .format(schema=sql.Identifier(context.schema),
                      role=sql.Identifier(webapp_base_role)))
  sqls.append(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role};")
              .format(schema=sql.Identifier(context.schema),
                      role=sql.Identifier(webapp_base_role)))
  sqls.append(sql.SQL("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO {role};")
              .format(schema=sql.Identifier(context.schema),
                      role=sql.Identifier(webapp_base_role)))
  return sqls

# Ensure future tables created by the schema owner are accesible to other users
def modify_default_privileges_for_schema_owner(context):
  sqls = []
  roles = context.app_roles()
  schema_role = roles.get('schema_role')
  webapp_base_role = roles.get('webapp_base')
  webapp_admin_role = roles.get('admin_role')
  readwrite_role = roles.get('readwrite_role')

  sqls.append(sql.SQL(
              """
              ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
              GRANT SELECT ON TABLES TO {grantee};
              """).format(grantor=sql.Identifier(schema_role),
                          schema=sql.Identifier(context.schema),
                          grantee=sql.Identifier(webapp_base_role)))
  
  sqls.append(sql.SQL(
              """
              ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
              GRANT SELECT, USAGE ON SEQUENCES TO {grantee};
              """).format(grantor=sql.Identifier(schema_role),
                          schema=sql.Identifier(context.schema),
                          grantee=sql.Identifier(webapp_base_role)))
  
  sqls.append(sql.SQL(  
              """
              ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
              GRANT EXECUTE ON FUNCTIONS TO {grantee};
              """).format(grantor=sql.Identifier(schema_role),
                          schema=sql.Identifier(context.schema),
                          grantee=sql.Identifier(webapp_base_role)))
  
  sqls.append(sql.SQL(
              """
              ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
              GRANT INSERT,UPDATE,DELETE,REFERENCES,TRIGGER ON TABLES TO {rw_grantee}, {admin_grantee};
              """).format(grantor=sql.Identifier(schema_role),
                          schema=sql.Identifier(context.schema),
                          rw_grantee=sql.Identifier(readwrite_role),
                          admin_grantee=sql.Identifier(webapp_admin_role)))
  
  sqls.append(sql.SQL(
              """
              ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
              GRANT ALL ON SEQUENCES TO {rw_grantee}, {admin_grantee};
              """).format(grantor=sql.Identifier(schema_role),
                          schema=sql.Identifier(context.schema),
                          rw_grantee=sql.Identifier(webapp_base_role),
                          admin_grantee=sql.Identifier(webapp_admin_role)))
  
  sqls.append(sql.SQL(
              """
              ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
              GRANT ALL ON FUNCTIONS TO {rw_grantee}, {admin_grantee};
              """).format(schema=sql.Identifier(context.schema),
                          grantor=sql.Identifier(schema_role),
                          admin_grantee=sql.Identifier(readwrite_role),
                          rw_grantee=sql.Identifier(webapp_base_role)))
  return sqls

def create_webapp_logins(context):
  sqls = []
  roles = context.app_roles()
  logins = context.app_logins()

  schema_role = roles.get('schema_role')
  schema_user = logins.get('schema_admin')

  webapp_admin_role = roles.get('admin_role')
  webapp_admin_user = logins.get('webapp_admin')
  
  readwrite_role = roles.get('readwrite_role')
  webapp_user = logins.get('webapp')
  
  sqls.append(sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD 'foo';")
              .format(sql.Identifier(schema_user)))
  sqls.append(sql.SQL("GRANT {role} TO {user};")
              .format(role=sql.Identifier(schema_role),
                      user=sql.Identifier(schema_user)))

  sqls.append(sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD 'foobar';")
              .format(sql.Identifier(webapp_user)))
  sqls.append(sql.SQL("GRANT {role} TO {user};")
              .format(role=sql.Identifier(readwrite_role),
                      user=sql.Identifier(webapp_user)))
  
  sqls.append(sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD 'foobarbizz';")
              .format(sql.Identifier(webapp_admin_user)))
  sqls.append(sql.SQL("GRANT {role} TO {user};")
              .format(role=sql.Identifier(webapp_admin_role),
                      user=sql.Identifier(webapp_admin_user)))
  return sqls

def execute_sql(conn, statements):
  with conn.cursor() as cursor:
    for stmt in statements:
      try:
        print(F"Executing: {stmt.as_string(conn)}")
        cursor.execute(stmt)
        conn.commit()
      except Exception as e:
        print(F"WARNING: An Error occurred: {e}")
        conn.rollback()
  cursor.close()
  conn.close()
  print("DONE")

def main():
  db_context = RestrictedRolesNamespace('restricted_apps', 
                                        'localhost',
                                        'kaylawebb',
                                        'confidential')
  
  connection = db_connection(db_context)
  sqls = grant_schema_usage(db_context) + \
         create_roles(db_context) + \
         grant_schema_owner_privileges(db_context) + \
         grant_base_webapp_privileges(db_context) + \
         modify_default_privileges_for_schema_owner(db_context) + \
         create_webapp_logins(db_context)
  
  execute_sql(connection, sqls)

if __name__ == "__main__":
  main()