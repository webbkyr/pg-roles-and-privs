import pytest
from database import DbConnection, DbUser, SchemaOwner
from permission import ReadWrite, Admin

@pytest.fixture
def db_credentials():
  return {
    "db": "restricted_test",
    "host": "localhost",
    "port": "30002",
    "user": "docker",
    "password": "docker"
  }

@pytest.fixture
def connection(db_credentials):
  return DbConnection(**db_credentials).connect_to_db()

def test_database_connection(db_credentials):
  credentials = db_credentials
  cursor = DbConnection(**credentials).connect_to_db().cursor();
  cursor.execute("SELECT current_user")
  assert cursor.fetchone()[0] == 'docker'


def test_create_schema(connection):
  cursor = connection.cursor()
  cursor.execute("CREATE SCHEMA test")
  cursor.execute("SELECT schema_name from information_schema.schemata WHERE schema_name='test';") 
  assert cursor.fetchone()[0] == 'test'


def test_create_db_user():
  user = DbUser('test', 'my_app', 'read', 'postgres')
  assert user.default_privilege_grantor == 'test'
  assert user.user_name == 'test_my_app'
  assert user.role_name == 'test_read_role'

def test_create_schema_owner():
  schema_owner = SchemaOwner('test')
  assert schema_owner.user_name == 'test'

# def test_create_user():
#   schema_owner = SchemaOwner('test')
#   db_user = DbUser('test', 'my_app', 'read', 'postgres')
  
#   assert schema_owner.create_user('xyz')[0] == "CREATE USER test WITH PASSWORD 'xyz';"
#   assert db_user.create_user('abc')[0] == "CREATE USER test_my_app WITH PASSWORD 'abc';"

def test_readwrite_permission():
  user = DbUser('test', 'my_app', 'readwrite', 'postgres')
  rw = ReadWrite()

  # create role
  print("CREATING ROLE >>>>>>>>>>")
  print(rw.create_role(user.role_name))
  # base sqls
  print("GRANTING PRIVILEGES TO ROLE >>>>>>>>>>")
  print(rw.access_privileges('restricted_test', 'test', user.role_name))
  # future objects
  print("GRANTING DEFAULT PRIVS FOR SCHEMA OWNER TO ROLE >>>")
  print(rw.default_access_privileges(user.default_privilege_grantor, user.schema, user.role_name))
  # create user
  print("CREATING USER >>>>>>>")
  print(user.create_user('abc'))

def test_admin_permission():
  user = DbUser('test', 'my_app', 'admin', 'postgres')
  admin = Admin()
  # print(admin.sql('test','my_app', user.role_name))
  # print(admin.future_object_sql(user.default_privilege_grantor, user.schema, user.user_name))
