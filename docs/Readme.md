# PowerAuth Web Flow Documentation

PowerAuth Web Flow provides federated authentication and authorization services for securing web applications. Web Flow is built using [PowerAuth security protocol](https://github.com/wultra/powerauth-crypto) and performs role of [an OAuth 2.1 provider](http://projects.spring.io/spring-security-oauth/docs/oauth2.html).

The typical use-case for the software stack is securing the RESTful API interfaces, or authentication / authorization for internet banking via central authentication / authorization component.

Web Flow handles the authentication and authorization from user point of view. The user interacts with Web Flow using web browser and using mobile device (optional). The authentication flow starts when user performs a request to a protected URL and the user session has not been authenticated yet. This event triggers an OAuth 2.1 authentication process where Web Flow serves as an OAuth 2.1 provider. Based on configuration of current operation, user gets authenticated using various authentication steps. User session becomes authenticated once all required steps have been successfully completed for given operation.

Web Flow can handle various types of authentication and authorization steps during the OAuth 2.1 dance:
* Form based authentication (login using username and password)
* User ID assignment (user identification is resolved using backend systems)
* SMS OTP authorization (user receives a SMS with one time code which is used for authorization)
* Mobile token authorization (user confirms operation on mobile device, PowerAuth signature is used for authorization)
* SCA login (user specifies username in the first screen, the second screen uses password and SMS code verification)
* SCA approval (SCA login followed by approval using password and SMS code verification)

Web Flow can also display OAuth 2.1 consent page with options required to be selected for completing the operation.

Additional authentication and authorization steps can be implemented by extending Web Flow. Each operation can be configured to require a different authentication/authorization flow based on security requirements of the operation.

Web Flow can be integrated with anti-fraud systems, provide information for fraud detection as well as perform an authentication step-down based on response from anti-fraud system. 

## Overview

- [Introduction](./Readme.md)
- [Basic Definitions](./Basic-Definitions.md)

## Applications
- [Next Step Server](./Next-Step-Server.md)
- [Data Adapter](./Data-Adapter.md)
- [PowerAuth Server](https://github.com/wultra/powerauth-server)
- [PowerAuth Admin](https://github.com/wultra/powerauth-admin)
- [PowerAuth Push Server](https://github.com/wultra/powerauth-push-server)

## REST APIs

- [NextStep Server REST API Reference](./Next-Step-Server-REST-API-Reference.md)
- [Data Adapter REST API Reference](./Data-Adapter-REST-API-Reference.md)

## Deployment

- [Deploying Web Flow on JBoss / Wildfly](./Deploying-Wildfly.md)
- [Database Table Structure](./Database-Table-Structure.md)
- [Migration Instructions](./Migration-Instructions.md)
- [Docker Deployment](./Docker-Deployment.md)

## Customizing Web Flow
- [Customizing Web Flow Appearance](https://github.com/wultra/powerauth-webflow-customization/blob/develop/docs/Customizing-Web-Flow-Appearance.md)
- [Implementing Data Adapter Interface](https://github.com/wultra/powerauth-webflow-customization/blob/develop/docs/Implementing-the-Data-Adapter-Interface.md)
- [Configuring Next Step](./Configuring-Next-Step.md)
- [Customizing Operation Form Data](./Customizing-Operation-Form-Data.md)
- [Mobile Token Configuration](./Mobile-Token-Configuration.md)

## Technical Notes

- [Operation Data Structure](./Operation-Data.md)

## Releases

- [Releases](https://github.com/wultra/powerauth-webflow/releases)