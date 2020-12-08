class Base:  
  def __str__(self):
    return f"<Base type>"

  def create_role(self, role_name):
    print(f"CREATE ROLE {role_name};")
  
  # Grants access for existing objects
  def access_privileges(self, db, schema, role):    
    print(f"GRANT CONNECT ON DATABASE {db} TO {role};")
    print(f"GRANT USAGE ON SCHEMA {schema} TO {role};")
    print(f"GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {role};")
    print(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role};")
    print(f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO {role};")
    
  # Grants access to any objects created in the future
  def default_access_privileges(self, grantor, schema, grantee):
      print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT SELECT ON TABLES TO {grantee};
      """)
  
      print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT SELECT, USAGE ON SEQUENCES TO {grantee};
      """)

      print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT EXECUTE ON FUNCTIONS TO {grantee};
      """)

class ReadWrite(Base):
  def __str__(self):
    return f"<ReadWrite type>"
  
  def access_privileges(self, db, schema, role):    
    super().access_privileges(db, schema, role)

    print(f"GRANT INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA {schema} TO {role};")
    print(f"GRANT ALL ON ALL SEQUENCES IN SCHEMA {schema} TO {role};")
    print(f"GRANT ALL ON ALL FUNCTIONS IN SCHEMA {schema} TO {role};")

  def default_access_privileges(self, grantor, schema, grantee):
    super().default_access_privileges(grantor, schema, grantee)
    
    print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT INSERT,UPDATE,DELETE,REFERENCES,TRIGGER ON TABLES TO {grantee};
      """)
  
    print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT ALL ON SEQUENCES TO {grantee};
      """)
  
    print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT ALL ON FUNCTIONS TO {grantee};
      """)
  
class Admin(ReadWrite):
  def __str__(self):
    return f"<Admin type>"
  
  def create_role(self, role_name):
    print(f"CREATE ROLE {role_name} BYPASSRLS") 
  
  def access_privileges(self, db, schema, role):
    super().access_privileges(db, schema, role)

  def default_access_privileges(self, grantor, schema, grantee):
    super(Admin, self).default_access_privileges(db_name, schema, role)

  