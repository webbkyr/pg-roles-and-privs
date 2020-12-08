from abc import ABC, abstractmethod
from psycopg2 import sql, connect

class DbConnection:
  def __init__(self, db, host, port, user, password):
    self.db = db
    self.host = host
    self.port = port
    self.user = user
    self.password = password

  def connect_to_db(self):
    return connect(dbname=self.db,
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password)

class BaseUser:
  def __init__(self,
              db_schema, 
              db_user=None,
              allowed_role=None,
              master_username=None):
    self.schema           = db_schema
    self.db_user          = db_user
    self.allowed_role     = allowed_role
    self.master_username  = master_username

  def __str__(self):
    return f"<BaseUser db_schema={self.schema},db_user={self.username},allowed_role={self.allowed_role},master_username={self.master_username}>"
  
  def secret(self):
    return ''
  
  @property
  def username(self):
    return f"{self.schema}_{self.db_user}"
  
  @property
  def role_name(self):
    return f"{self.schema}_{self.allowed_role}_role"
  
  @property
  def default_privilege_grantor(self):
    return f"{self.master_user_name}"
  
  def create_user(self, password):
    print(f"CREATE USER {self.username} WITH PASSWORD '{password}';")
    print(f"ALTER ROLE {self.username} SET search_path TO {self.schema}")
    print(f"GRANT {self.role_name} TO {self.username};")


class DbUser(BaseUser):
  def __init__(self,
              db_schema, 
              db_user, 
              allowed_role,
              master_user_name):
    super().__init__(db_schema,
                     db_user, 
                     allowed_role, 
                     master_user_name)
  @property
  def default_privilege_grantor(self):
    return f"{self.schema}"


class SchemaOwner(BaseUser):
  def __init__(self, db_schema):
    super().__init__(db_schema)
  
  @property
  def username(self):
    return f"{self.schema}"

