## CloudFormation Custom Resource for creating roles for web applications serving data from restricted databases

Todos:
* Write SQLS (done)
* Convert to psycopg2 statements (done)
* Add CFN resource
* Test with RDS + Lambda

-----
##  For Create Change Sets
### Required Inputs: 
    1) Database name
    2) Schema name (will be created if doesn't exist)
    3) Secrets Manager ARN for: database's superuser, webapp, webapp_admin, schema_admin
## For Update Change Sets
    Nothing will happen.
## For Deletion Change Sets
    Everything will be undone: roles' privs revoked, roles dropped and privs returned to its initial state.
    Object ownership will be re-sassigned to the db's superuser.
