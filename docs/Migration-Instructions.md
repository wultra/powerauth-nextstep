# Migration Instructions

This page contains PowerAuth Next Step migration instructions.

- [PowerAuth Next Step 2.2.0](./Next-Step-2.2.0.md)

## Unreleased

### Configuration Change: `CredentialGenerationParam.specialChars`

A new optional field `specialChars` has been added to `CredentialGenerationParam`. When `includeSpecialChars` is `true` and `specialChars` is not set (or `null`), the default set `^<>{};:.,~!?@#$%=&*[]()` is used — matching the previous hardcoded behavior. No action is required for existing deployments unless you wish to customize the set of special characters.
- [PowerAuth Next Step 2.0.0](./Next-Step-2.0.0.md)
- [PowerAuth Next Step 1.10.0](./Next-Step-1.10.0.md)
- [PowerAuth Next Step 1.9.0](./Next-Step-1.9.0.md)
- [PowerAuth Next Step 1.8.0](./Next-Step-1.8.0.md)
- [PowerAuth Next Step 1.7.0](./Next-Step-1.7.0.md)
- [PowerAuth Next Step 1.6.0](./Next-Step-1.6.0.md)
- [PowerAuth Next Step 1.5.0](./Next-Step-1.5.0.md)
- [PowerAuth Next Step 1.4.0](./Next-Step-1.4.0.md)
- [PowerAuth Next Step 1.3.0](./Next-Step-1.3.0.md)
- [PowerAuth Next Step 1.2.0](./Next-Step-1.2.0.md)
- [PowerAuth Next Step 1.1.0](./Next-Step-1.1.0.md)
- [PowerAuth Next Step 1.0.0](./Next-Step-1.0.0.md)
- [PowerAuth Next Step 0.24.0](./Next-Step-0.24.0.md)
- [PowerAuth Next Step 0.23.0](./Next-Step-0.23.0.md)
- [PowerAuth Next Step 0.22.0](./Next-Step-0.22.0.md)
- [PowerAuth Next Step 0.21.0](./Next-Step-0.21.0.md)
- [PowerAuth Next Step 0.20.0](./Next-Step-0.20.0.md)
- [PowerAuth Next Step 0.19.0](./Next-Step-0.19.0.md)
