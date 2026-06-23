# Migration from 1.4.0 to 1.5.0

This guide contains instructions for migration from PowerAuth Next Step version `1.4.x` to version `1.5.0`.

## Migration to Spring Boot 3

### Required Java Version

Next Step requires Java 17 or higher due to migration to Spring Boot 3. Support for older Java versions is not available.

## Database Changes

### Dropped MySQL Support

Since version `1.5.0`, MySQL database is not supported anymore.


## Dependencies

PostgreSQL JDBC driver is already included in the WAR file.
Oracle JDBC driver remains optional and must be added to your deployment if desired.
