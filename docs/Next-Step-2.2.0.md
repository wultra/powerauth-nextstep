# Migration from 2.0.0 to 2.2.0

This guide contains instructions for migration from PowerAuth Next Step version `2.0.x` to version `2.2.0`.

## REST API

### Credential Reset

Similar to a credential update, the NextStep API endpoint `POST /credential/reset` resets credentials with source `LDAP` or `PROXY` and target `LOCAL`. The stored credential source is then updated to `LOCAL`.

### Configurable Special Characters in Password Generation (since 2.2.2)

The `credentialGenParam` object in credential policy requests now supports an optional `specialChars` field (string, max 256 characters). When `includeSpecialChars` is `true`:
- If `specialChars` is provided, only the characters in that string are used as special characters during password generation.
- If `specialChars` is `null` or omitted, the default character set `^<>{};:.,~!?@#$%=&*[]()` is used — matching the previous behavior.

No database migration is required. Existing credential policies without `specialChars` continue to use the default character set.

## Database Changes

For convenience, you can use liquibase for your database migration.

The main Liquibase script is located in path [db/changelog/db.changelog-master.xml](db/changelog/db.changelog-master.xml).

For manual changes use SQL scripts:

- [PostgreSQL script](sql/postgresql/migration_2.0.0_2.2.0.sql)
- [Oracle script](./sql/oracle/migration_2.0.0_2.2.0.sql)

### `audit_log` Table

Added a new indexed column `subject_id` holding an identifier linking the audit record to an entity it is related to (e.g. user ID for user-related audit records).

<!-- begin box warning -->
The auditing tables may be already updated in your database schema if the database schema is not separated for different PowerAuth applications. In case the column `audit_log.subject_id` and its index `audit_log_subject_id_idx` are already present, you can safely skip this migration step.
<!-- end -->

### `ns_user_contact` and `ns_otp_storage` Tables (since 2.2.3)

A new Liquibase changeset adds three nullable columns to support contact verification. All three are nullable with no default value; existing rows remain unverified (`null`) and no data backfill is required.

- `ns_user_contact.verification_method` (`varchar(32)`) – verification method that confirmed the contact.
- `ns_user_contact.timestamp_verified` (`timestamp`) – time at which the contact was verified.
- `ns_otp_storage.verification_method` (`varchar(32)`) – verification method the OTP was issued for.

For operators applying the change manually (without Liquibase), run the following statements.

PostgreSQL:

```sql
ALTER TABLE ns_user_contact ADD verification_method VARCHAR(32);
ALTER TABLE ns_user_contact ADD timestamp_verified TIMESTAMP;
ALTER TABLE ns_otp_storage ADD verification_method VARCHAR(32);
```

Oracle:

```sql
ALTER TABLE ns_user_contact ADD verification_method VARCHAR2(32 CHAR);
ALTER TABLE ns_user_contact ADD timestamp_verified TIMESTAMP;
ALTER TABLE ns_otp_storage ADD verification_method VARCHAR2(32 CHAR);
```


## Dependency Updates


### Docker Base Image Upgrade

The Docker base image has been upgraded from `ibm-semeru-runtimes:open-21.0.9_10-jre-noble` (OpenJDK 21) to `ibm-semeru-runtimes:open-jdk-25.0.3.0-jre-noble` (OpenJDK 25).

