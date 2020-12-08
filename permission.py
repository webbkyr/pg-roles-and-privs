from abc import ABC, abstractmethod

class Base(ABC):
  def __init__(self, role):
    self.role = role
  
  @abstractmethod
  def create_role(self):
    pass

  @abstractmethod
  def drop_role(self):
    pass

  @abstractmethod
  def grant_access_privileges(self):
    pass
  
  @abstractmethod
  def grant_default_access_privileges(self):
    pass


class Read(Base):
  def __init__(self, role):
    super().__init__(role)
  
  def __str__(self):
    return f"<Base type>"

  def create_role(self):
    print(f"CREATE ROLE {self.role};")

  def drop_role(self, master_user):
    print(f"REASSIGN OWNED BY {self.role} TO {master_user};")
    print(f"DROP OWNED BY {self.role};")
    print(f"DROP ROLE {self.role};")
  
  # Grants access for existing objects
  def grant_access_privileges(self, db, schema): 
    print(f"GRANT CONNECT ON DATABASE {db} TO {self.role};")
    print(f"GRANT USAGE ON SCHEMA {schema} TO {self.role};")
    print(f"GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO {self.role};")
    print(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {self.role};")
    print(f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO {self.role};")
    
  # Grants access to any objects created in the future
  def grant_default_access_privileges(self, grantor, schema):
    print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT SELECT ON TABLES TO {self.role};
    """)
  
    print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT SELECT, USAGE ON SEQUENCES TO {self.role};
      """)

    print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT EXECUTE ON FUNCTIONS TO {self.role};
      """)

class ReadWrite(Read):
  def __init__(self, role):
    super().__init__(role)
  
  def __str__(self):
    return f"<ReadWrite type>"
  
  def grant_access_privileges(self, db, schema):    
    super().grant_access_privileges(db, schema)

    print(f"GRANT INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA {schema} TO {self.role};")
    print(f"GRANT ALL ON ALL SEQUENCES IN SCHEMA {schema} TO {self.role};")
    print(f"GRANT ALL ON ALL FUNCTIONS IN SCHEMA {schema} TO {self.role};")

  def grant_default_access_privileges(self, grantor, schema):
    super().grant_default_access_privileges(grantor, schema)
    print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT INSERT,UPDATE,DELETE,REFERENCES,TRIGGER ON TABLES TO {self.role};
      """)
  
    print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT ALL ON SEQUENCES TO {self.role};
      """)
  
    print(f"""
      ALTER DEFAULT PRIVILEGES FOR ROLE {grantor} IN SCHEMA {schema} 
      GRANT ALL ON FUNCTIONS TO {self.role};
      """)
  
class Admin(ReadWrite):
  def __init__(self, role):
    super().__init__(role)
  
  def __str__(self):
    return f"<Admin type>"
  
  def create_role(self):
    print(f"CREATE ROLE {self.role} BYPASSRLS") 
  
  def grant_access_privileges(self, db, schema):
    super().grant_access_privileges(db, schema)

  def grant_default_access_privileges(self, grantor, schema):
    super().grant_default_access_privileges(grantor, schema)


  