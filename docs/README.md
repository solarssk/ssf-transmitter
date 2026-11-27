# Operator documentation

Start with the task you need to complete. These files are maintained in the repository; selected guides are mirrored automatically to the [GitHub Wiki](https://github.com/solarssk/ssf-transmitter/wiki).

## Install or upgrade

| Task | Guide |
|---|---|
| Deploy the container and reverse proxy | [Deployment](Deployment.md) |
| Add the service to Synology and Authentik | [Synology walkthrough](synology-authentik-compose.md) |
| Upgrade an existing installation | [Upgrade and rollback](Upgrading.md) |
| Configure environment variables | [Configuration reference](Configuration.md) |

## Connect Authentik and Apple

| Task | Guide |
|---|---|
| Choose which events revoke Apple sessions | [Event mapping and Authentik setup](Event-Mapping.md) |
| Check Apple's expected issuer and SET acceptance | [Apple SSF validation](Apple-SSF-Validation.md) |
| Synchronize Apple accounts | [Apple SCIM setup and operations](Apple-SCIM-Sync.md) |

## Operate and troubleshoot

| Task | Guide |
|---|---|
| Diagnose startup, delivery, or SCIM errors | [Troubleshooting](Troubleshooting.md) |
| Call management and delivery endpoints | [HTTP API reference](API.md) |
| Back up or rotate keys and tokens | [Key management](Key-Management.md) |
| Review production hardening and stored data | [Security documentation](security/README.md) |
| Review release changes | [Changelog](../CHANGELOG.md) |

## Contribute

[Automated PR review](AI-Review.md) explains subscription setup, approval rules, and the branch-protection rollout.

Use the [contribution guide](../.github/CONTRIBUTING.md), [dependency maintenance guide](Dependencies.md), [test guide](../tests/README.md), and [maintenance scripts](../scripts/README.md). Authentik expressions live under [integrations](../integrations/README.md).

**Current stable release:** `v0.6.0` — [Validated Apple SCIM and SSF integration](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.6.0)
