# Migration from 2.2.0 to 2.3.0

This guide contains instructions for migration from PowerAuth Next Step version `2.2.x` to version `2.3.0`.

## Database Changes

For convenience, you can use liquibase for your database migration.

The main Liquibase script is located in path [db/changelog/db.changelog-master.xml](db/changelog/db.changelog-master.xml).

### `ns_user_contact` and `ns_otp_storage` Tables

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

## Behavior

Creating or updating a user or its contacts now acquires a per-user lock to serialize concurrent contact changes and OTP issuance.
