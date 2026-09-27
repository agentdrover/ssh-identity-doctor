# SSH Identity Doctor Audit Report

## Summary

- **Scan ID**: `00000000-0000-0000-0000-000000000000`
- **Platform**: `linux`
- **Started at**: `2026-09-24T16:00:00+00:00`
- **Completed at**: `2026-09-24T16:00:01+00:00`
- **Identities**: 2
- **Findings**: 5 (1 error, 0 warnings, 4 info)
- **Host bindings**: 9
- **Unresolved directives**: 3

## Source coverage

| Source | State | Required | Detail |
| --- | --- | --- | --- |
| agent | timeout | no | ssh-add timed out |
| config | available | no | 9 host blocks parsed |
| filesystem | available | yes | 3 public keys discovered |
| github | unavailable | no | gh: not authenticated |

## Identities

| Fingerprint | Algorithm | References | Agent | GitHub |
| --- | --- | --- | --- | --- |
| `SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk` | ssh-ed25519 (256) | `/home/user/.ssh/id_ed25519`, `/home/user/.ssh/id_ed25519`, `/home/user/.ssh/id_ed25519.pub`, `/home/user/.ssh/id_ed25519_copy.pub` | no | - |
| `SHA256:Kskz06nJKSQVXxudvVa4i2SSMi4R2H2KjSMgpNUyyFE` | ssh-rsa (3072) | `/home/user/.ssh/id_rsa`, `/home/user/.ssh/id_rsa`, `/home/user/.ssh/id_rsa.pub` | no | - |

## Host bindings

| Patterns | HostName | User | IdentityFile | Fingerprints | Source | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| `gh`, `github.com` | `github.com` | `git` | `~/.ssh/id_ed25519` | `SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk` | `/home/user/.ssh/config:1` | certain |
| `server` | `server.example.com` | `admin` | `~/.ssh/id_rsa` | `SHA256:Kskz06nJKSQVXxudvVa4i2SSMi4R2H2KjSMgpNUyyFE` | `/home/user/.ssh/config:6` | certain |
| `canary-test` | - | - | `~/.ssh/id_canary` | - | `/home/user/.ssh/config:11` | unresolved |
| `missing-key` | - | - | `~/.ssh/nonexistent_key` | - | `/home/user/.ssh/config:14` | unresolved |
| `wildcard-test`, `*.example.com` | - | `wildcard` | - | - | `/home/user/.ssh/config:17` | certain |
| `cycle-host` | - | - | `~/.ssh/id_rsa` | `SHA256:Kskz06nJKSQVXxudvVa4i2SSMi4R2H2KjSMgpNUyyFE` | `/home/user/.ssh/config.d/cycle.conf:1` | certain |
| `cycle-host` | - | - | `~/.ssh/id_rsa` | `SHA256:Kskz06nJKSQVXxudvVa4i2SSMi4R2H2KjSMgpNUyyFE` | `/home/user/.ssh/config.d/cycle.conf:1` | certain |
| `included-host` | `inc.example.com` | - | `~/.ssh/id_ed25519` | `SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk` | `/home/user/.ssh/config.d/included.conf:1` | certain |
| `included-host` | `inc.example.com` | - | `~/.ssh/id_ed25519` | `SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk` | `/home/user/.ssh/config.d/included.conf:1` | certain |

## Unresolved items

The following configuration directives could not be resolved and are marked as **unresolved**:

| Kind | Location | Detail | Status |
| --- | --- | --- | --- |
| `unsupported_match` | `/home/user/.ssh/config:20` | Match host specific.example.com | unresolved |
| `include_cycle` | `/home/user/.ssh/config.d/cycle.conf:4` | /home/user/.ssh/config.d/included.conf | unresolved |
| `include_cycle` | `/home/user/.ssh/config.d/included.conf:5` | /home/user/.ssh/config.d/cycle.conf | unresolved |

## Findings

### CFG001-82674a9a729c - Unresolved IdentityFile: /home/user/.ssh/nonexistent_key

- **Rule**: CFG001
- **Severity**: error
- **Confidence**: certain
- **Summary**: IdentityFile '/home/user/.ssh/nonexistent_key' referenced at /home/user/.ssh/config:15 cannot be resolved (missing).
- **Affected hosts**: missing-key
- **Evidence**:
  - `/home/user/.ssh/config:15`: /home/user/.ssh/nonexistent_key
- **Manual remediation**:
  - `ls -l /home/user/.ssh/nonexistent_key`
  - `ssh -G missing-key`

### ID001-95b5b9220d43 - Duplicate public key paths or labels: SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk

- **Rule**: ID001
- **Severity**: info
- **Confidence**: certain
- **Summary**: Identity SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk appears under multiple local paths (/home/user/.ssh/id_ed25519.pub, /home/user/.ssh/id_ed25519_copy.pub) and distinct comments (copy@example, work@example).
- **Affected fingerprints**: SHA256:+92RsVKGXDDG2XlZkoQSG2sRjqnoPwysscnoHoCIdMk
- **Evidence**:
  - `/home/user/.ssh/id_ed25519.pub`: /home/user/.ssh/id_ed25519.pub
  - `/home/user/.ssh/id_ed25519_copy.pub`: /home/user/.ssh/id_ed25519_copy.pub
- **Manual remediation**:
  - `Review duplicate key files and consolidate references to the canonical path`
  - `Check where this fingerprint appears with each comment and decide which comment to keep as its label`

### CFG002-a15886002032 - Unsupported Match directive in SSH config

- **Rule**: CFG002
- **Severity**: info
- **Confidence**: unresolved
- **Summary**: Match directive at /home/user/.ssh/config:20 is not evaluated: Match host specific.example.com
- **Evidence**:
  - `/home/user/.ssh/config:20`: Match host specific.example.com
- **Manual remediation**:
  - `Review Match block at /home/user/.ssh/config:20 manually: ssh -G <alias>`

### CFG002-546ce76712fa - Include cycle in SSH config: /home/user/.ssh/config.d/included.conf

- **Rule**: CFG002
- **Severity**: info
- **Confidence**: unresolved
- **Summary**: Recursive Include directive detected at /home/user/.ssh/config.d/cycle.conf:4.
- **Evidence**:
  - `/home/user/.ssh/config.d/cycle.conf:4`: /home/user/.ssh/config.d/included.conf
- **Manual remediation**:
  - `Review include chain around /home/user/.ssh/config.d/cycle.conf:4`

### CFG002-28bb51a07fac - Include cycle in SSH config: /home/user/.ssh/config.d/cycle.conf

- **Rule**: CFG002
- **Severity**: info
- **Confidence**: unresolved
- **Summary**: Recursive Include directive detected at /home/user/.ssh/config.d/included.conf:5.
- **Evidence**:
  - `/home/user/.ssh/config.d/included.conf:5`: /home/user/.ssh/config.d/cycle.conf
- **Manual remediation**:
  - `Review include chain around /home/user/.ssh/config.d/included.conf:5`

## Limitations

This report is based solely on local SSH configuration files, discovered public keys, active SSH agent identities, and explicitly queried remote registries.

Remote registries (such as GitHub, GitLab, SaaS providers, or internal servers) that are not configured or queried cannot be detected by this scan. Keys may be authorized on external systems even if no local or known remote references exist.

In accordance with safety principles (SEC-006), this tool does not guarantee that any key is safe to delete. Always verify with system administrators and access management records before revoking or removing any SSH key.
