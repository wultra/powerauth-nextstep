# Migration from 2.2.0 to 2.3.0

This guide contains instructions for migration from PowerAuth Next Step version `2.2.x` to version `2.3.0`.

## Database Changes

For convenience, you can use liquibase for your database migration.

The main Liquibase script is located in path [db/changelog/db.changelog-master.xml](db/changelog/db.changelog-master.xml).

### `ns_user_contact` and `ns_otp_storage` Tables

A new Liquibase changeset adds three columns to support contact verification. The `verification_method` and `timestamp_verified` columns are nullable with no default value, so existing contacts remain unverified (`null`). The `otp_purpose` column defaults to `GENERIC`, and existing OTPs bound to an operation (`operation_id` is not null) are set to `OPERATION`.

- `ns_user_contact.verification_method` (`varchar(32)`) – verification method that confirmed the contact.
- `ns_user_contact.timestamp_verified` (`timestamp`) – time at which the contact was verified.
- `ns_otp_storage.otp_purpose` (`varchar(32)`, not null, default `GENERIC`) – purpose the OTP was issued for (`GENERIC`, `OPERATION` or `CONTACT_VERIFICATION`).

For manual changes use SQL scripts:

- [PostgreSQL script](sql/postgresql/migration_2.2.0_2.3.0.sql)
- [Oracle script](./sql/oracle/migration_2.2.0_2.3.0.sql)
