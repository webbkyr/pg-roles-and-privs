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
              master_user_name=None):
    self.schema           = db_schema
    self.db_user          = db_user
    self.allowed_role     = allowed_role
    self.master_user_name = master_user_name

  def __str__(self):
    return f"<BaseUser db_schema={self.schema},
                       db_user={self.db_user},
                       allowed_role={self.allowed_role}, 
                       master_user_name={self.master_user_name}>"
  
  def secret(self):
    return ''
  
  @property
  def user_name(self):
    return f"{self.schema}_{self.db_user}"
  
  @property
  def role_name(self):
    return f"{self.schema}_{self.allowed_role}_role"
  
  @property
  def default_privilege_grantor(self):
    return f"{self.master_user_name}"


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
  def user_name(self):
    return f"{self.schema}"

  