# PowerAuth Next Step Documentation

PowerAuth Next Step is a workflow orchestration platform for authentication and authorization operations. It coordinates operation lifecycle, evaluates configured policies, and drives required verification steps through integration with surrounding components (for example digital channels, mobile token, and data adapter services).

The typical use-case is securing digital channels with configurable operation flows, including transaction approval and strong customer authentication. Each operation can use a different sequence of steps based on business context and security requirements.

Next Step is designed for extensibility and integration. It supports implementation-specific adapters, custom operation data, and integration with risk or fraud decisioning services to dynamically adjust required authentication strength.

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

- [Deploying Next Step on JBoss / Wildfly](./Deploying-Wildfly.md)
- [Database Table Structure](./Database-Table-Structure.md)
- [Migration Instructions](./Migration-Instructions.md)
- [Docker Deployment](./Docker-Deployment.md)

## Customizing Next Step
- [Configuring Next Step](./Configuring-Next-Step.md)
- [Customizing Operation Form Data](./Customizing-Operation-Form-Data.md)
- [Mobile Token Configuration](./Mobile-Token-Configuration.md)

## Technical Notes

- [Operation Data Structure](./Operation-Data.md)

## Releases

- [Releases](https://github.com/wultra/powerauth-nextstep/releases)