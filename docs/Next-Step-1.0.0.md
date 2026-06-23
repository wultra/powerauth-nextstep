# Migration from 0.24.0 to 1.0.0

## Migration of PowerAuth client to REST interface

PowerAuth client uses REST interface in version `1.0.0`. Previous versions of Web Flow used the SOAP interface. This change needs to be reflected in configuration property `powerauth.service.url`.

Property value before migration:
`powerauth.service.url=http://[server]:[port]/powerauth-java-server/soap`

Property value after migration:
`powerauth.service.url=http://[server]:[port]/powerauth-java-server/rest`
