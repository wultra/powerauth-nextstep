# Database Table Structure

Next Step requires a database to store data. It is tested with Oracle and PostgreSQL. It should be easily adapted to any other SQL database which supports JDBC.

Next Step can coexist with PowerAuth in the same database schema, or it can use a different database schema.

## Database Scripts

### Oracle

- [create_schema.sql](./sql/oracle/create_schema.sql) - DDL script for creating the database schema
- [initial_data.sql](./sql/oracle/initial_data.sql) - script with initial data
- [drop_schema.sql](./sql/oracle/drop_schema.sql) - drop schema script

### PostgreSQL

- [create_schema.sql](./sql/postgresql/create_schema.sql) - DDL script for creating the database schema
- [initial_data.sql](./sql/postgresql/initial_data.sql) - script with initial data
- [drop_schema.sql](./sql/postgresql/drop_schema.sql) - drop schema script

## Database Tables

### Database Tables for the Next Step Server

- **ns_auth_method** - the table stores configuration of authentication methods. Data in this table needs to be loaded before Next Step is started.

- **ns_user_prefs** - the table stores user preferences. Status of authentication methods is stored in this table per user (methods can be enabled or disabled).

- **ns_operation** - the table stores details of operations. Only the last status is stored in this table, changes of operations are stored in table ns_operation_history.

- **ns_operation_config** - the table stores configuration of operations including configuration of mobile templates. Data in this table needs to be loaded before Next Step is started.

- **ns_operation_method_config** - the table stores configuration of authentication methods per operation name.

- **ns_operation_history** - the table stores all changes of operations.

- **ns_organization** - the table stores definitions of organizations.

- **ns_step_definition** - the table stores definitions of authentication/authorization steps. Data in this table needs to be loaded before Next Step is started.

- **ns_operation_afs** - the table stores responses from AFS for operations.

- **ns_application** - the table stores Next Step applications.

- **ns_credential_policy** - the table stores credential policies.

- **ns_otp_policy** - the table stores OTP policies.

- **ns_user_identity** - the table stores Next Step user identities.

- **ns_user_contact** - the table stores contact information for user identities.

- **ns_user_identity_history** - the table stores history for user identities.

- **ns_role** - the table stores user role definitions.

- **ns_user_role** - the table stores assignment of roles to user identities.

- **ns_user_alias** - the table stores user aliases.

- **ns_hashing_config** - the table stores configuration of hashing algorithms.

- **ns_credential_definition** - the table stores definitions of credentials with reference to credential policies and applications.

- **ns_otp_definition** - the table stores definitions of one time passwords with reference to one time password policies and applications.

- **ns_credential_storage** - the table stores credential values, attempt counters and other data related to credentials.

- **ns_credential_history** - the table stores historical values of credentials.

- **ns_otp_storage** - the table stores one time password values, attempt counters and other data related to one time passwords.

- **ns_authentication** - the table stores user authentication attempts.

### Database Table for Scheduled Task Locking

- **shedlock** - the table prevents execution of the same scheduled task from more than one node.

### Database Tables for the Auditing Functionality

- **audit_log** - the table stores audit records.

- **audit_param** - the table stores parameters of audit records which can be used in queries.
