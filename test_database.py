import pytest
from database import DbConnection, DbUser, SchemaOwner

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
