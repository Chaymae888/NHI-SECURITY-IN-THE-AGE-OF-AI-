# Threat Model — Non-Human Identity Security for AI Agents

## 1. Scope

The prototype controls which identity an AI agent uses, what that identity may do on three simulated tools, how its credential is issued, expires and is revoked, and how misuse is detected and audited.

**Out of scope:** a new authentication protocol, enterprise-wide IAM, training a model, real cloud IAM.

**Central question:** How can non-human identities used by AI agents be securely managed and constrained when agents interact with external tools and resources?

## 2. Trust boundaries

| Component | Trust level | Rationale |
|---|---|---|
| LLM agent | Untrusted | Tool requests can be manipulated (prompt injection) |
| Security API (policy decision point) | Trusted | Single source of truth for allow/deny |
| Tool servers (policy enforcement points) | Trusted, but verify | Each tool validates the token itself; never trusts "the agent said it is allowed" |
| Registry and credential store | Trusted, isolated | Secrets never reach the agent's prompt or the logs |

Key principle: an AI model deciding to perform an action does not mean the action is authorized.

## 3. Tools and resources

| Tool | Actions | Resources |
|---|---|---|
| `documents` | `read` | `docs/public/*`, `docs/internal/*` |
| `database` | `query` | table `deployments` (normal), table `customers` (sensitive) |
| `tickets` | `create` | project `OPS` |

## 4. Identities (seed data)

| Identity | Purpose | Owner | Permissions | Credential | Status | Role in demo |
|---|---|---|---|---|---|---|
| `agent-deploy-reader` | Summarize deployment status | alice | `database.query` on `deployments`; `documents.read` on `docs/public/*` | valid, 24 h | active | Normal path, then revoked |
| `agent-ticket-writer` | Open tickets | bob | `tickets.create` on `OPS` | valid, 24 h (shared, see below) | active | Cannot read anything |
| `agent-legacy-admin` | Old test agent | none | `*` on `*` | expired | active | Seeded risk: orphan + wildcard + expired-but-active |
| `agent-reporting` | Reporting | carol | `database.query` on `deployments` | same credential as `agent-ticket-writer` | active | Seeded risk: shared credential |
| `agent-unknown` | n/a | n/a | n/a | not in registry | n/a | Unauthenticated test |

## 5. Threats

Verify the exact OWASP NHI Top 10 numbering against the OWASP page before citing it in the report.

| # | Threat | OWASP NHI theme | Control | Detected by |
|---|---|---|---|---|
| T1 | Prompt injection makes the agent request an out-of-scope action | Overprivileged NHI | Enforcement independent of the LLM | Audit: DENY |
| T2 | Expired or stolen credential is replayed | Long-lived secrets, insecure authentication | Expiry check, short TTL | Audit + risk check |
| T3 | Revoked identity keeps working | Improper offboarding | Revocation checked on every call | Audit |
| T4 | Wildcard or excessive permissions | Overprivileged NHI | Least-privilege permission model | Risk check |
| T5 | Secret leaks into logs, prompts or a repository | Secret leakage | Secrets only in the credential store; log redaction; repo scanner | Secret scan |
| T6 | One credential shared by several identities | NHI reuse | One credential per identity | Risk check |
| T7 | Identity with no owner | Improper offboarding | Mandatory `owner` field in policy | Risk check |
| T8 | A tool trusts the agent's claim without checking | Confused deputy | Each tool validates the token itself | Forged-request test |

## 6. Authorization decision rules

Evaluate in order, stop at the first failure, default deny. Every decision writes an audit event. The audit event never contains the secret.

| Step | Check | If it fails |
|---|---|---|
| 1 | Credential present and known | `DENY_UNAUTHENTICATED` |
| 2 | Credential not expired | `DENY_EXPIRED` |
| 3 | Credential not revoked | `DENY_REVOKED` |
| 4 | Identity status is `active` | `DENY_IDENTITY_INACTIVE` |
| 5 | Tool is in the identity's allowed tools | `DENY_TOOL_NOT_ALLOWED` |
| 6 | Action is permitted on that tool | `DENY_ACTION_NOT_ALLOWED` |
| 7 | Resource matches the permission scope | `DENY_RESOURCE_OUT_OF_SCOPE` |
| 8 | All checks passed | `ALLOW` |

The expected result of each scenario is in `decision-matrix.csv`.

## 7. Risk checks (expected findings on seed data)

| Check | Rule | Expected finding |
|---|---|---|
| `EXPIRED_BUT_ACTIVE` | status = active and all credentials expired | `agent-legacy-admin` |
| `NO_OWNER` | owner is null | `agent-legacy-admin` |
| `WILDCARD_PERMISSION` | any permission uses `*` | `agent-legacy-admin` |
| `SHARED_CREDENTIAL` | same `secret_ref` on more than one identity | `agent-ticket-writer`, `agent-reporting` |
| `SECRET_IN_REPO` | secret pattern found in the controlled test repository | seeded test file |

## 8. Evaluation metrics

- Authorization accuracy: matrix scenarios whose actual result equals the expected result
- Unauthorized requests rejected: denied / total out-of-policy requests
- Revocation effectiveness: requests denied after revocation / requests made after revocation
- Seeded risk detection: findings raised / findings seeded
- Secret exposure: occurrences of credential values in logs (target: 0)

## 9. Known limitations (to complete during evaluation)

- Simulated tools, not real business systems
- Local credential store unless Vault is integrated
- No protection against a compromised Security API or registry host
