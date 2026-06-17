# Developer - How to Start Guide


## NextStep


### Standalone Run

- Use IntelliJ Idea run configuration at `../.run/NextStepApplication.run.xml`
- Open [http://localhost:9082/powerauth-nextstep/actuator/health](http://localhost:9082/powerauth-nextstep/actuator/health) and you should get `{"status":"UP"}`


### Database

Database changes are driven by Liquibase.

This is an example how to manually check the Liquibase status.
Important and fixed parameter is `changelog-file`.
Others (like URL, username, password) depend on your environment.

```shell
liquibase --changelog-file=./docs/db/changelog/changesets/powerauth-nextstep/db.changelog-module.xml --url=jdbc:postgresql://localhost:5432/powerauth --username=powerauth status
```

When all user identities are stored in Next Step, add foreign keys for user identity manually (they are not part of liquibase changesets).

```sql
-- Foreign keys for user identity, to be used only when all user identities are stored in Next Step
ALTER TABLE ns_operation ADD CONSTRAINT ns_operation_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
ALTER TABLE ns_user_prefs ADD CONSTRAINT ns_user_prefs_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
ALTER TABLE ns_otp_storage ADD CONSTRAINT ns_otp_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
ALTER TABLE ns_authentication ADD CONSTRAINT ns_auth_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
```
