# AgentShield documentation

AgentShield is a local-first prototype: execution is simulated and the API listens on
loopback only. Start with the project [README](../README.md) for what it is and is not.

## Integrating an agent

Read these in order:

1. [quick-start.md](quick-start.md). Covers:
   - build and test;
   - start the API with a policy and create a test credential;
   - run the reference agent through `ALLOW`, `CONFIRM` and `BLOCK`.
2. [integration-guide.md](integration-guide.md). Covers the SDK:
   - credential loading and client set-up;
   - evaluation and approval polling;
   - error handling, and unconfirmed outcomes.
3. [troubleshooting.md](troubleshooting.md). Every status code and SDK error, and the four
   kinds of outcome: confirmed, refused, pending and unconfirmed.

## Understanding the design

- [architecture.md](architecture.md). The signed protocol, credentials, verification and
  replay protection, authorization, policies, approvals, the SDK and the reference agent,
  with diagrams.
- [security-model.md](security-model.md). What is protected and what is not: the trust
  model, key handling, replay limits, approval versus execution, and restart limits.
- [security-assessment.md](security-assessment.md). The M3-E E9 security and
  production-readiness assessment: findings by severity, the threat model, the dependency
  review, and the deferred risks.

## Reference

| Document | Covers |
|---|---|
| [agent-identity.md](agent-identity.md) | Credentials (Ed25519 and legacy bearer), the store, the `agent-credential` CLI, signed-request verification, agent approval visibility, incident response |
| [agent-policies.md](agent-policies.md) | The policy file schema, enforcement and recheck |
| [approval-persistence.md](approval-persistence.md) | Durable approvals: transitions, crash recovery, `OUTCOME_UNKNOWN`, limits, integration |
| [replay-and-idempotency.md](replay-and-idempotency.md) | Durable replay protection and evaluation idempotency: contract, storage, crash behaviour, residual risks |
| [beta-gate-evidence.md](beta-gate-evidence.md) | M3-E E17: the evidence record for the three beta gates, filled in only from operator-supplied evidence; current decision and open findings |
| [beta-gate-checklist.md](beta-gate-checklist.md) | M3-E E16: the three mandatory, human-run beta gates (browser smoke test, real-installation recovery drill, storage CLI), evidence templates and the GO / CONDITIONAL GO / NO-GO rules. Prepared, not run. |
| [beta-readiness.md](beta-readiness.md) | M3-E E15 beta-readiness assessment: validated workflows, findings, residual risks, operating conditions, and the conditional GO verdict |
| [operations.md](operations.md) | Operator guide: storage inventory, health monitoring, offline backup, restore, crash and disk-full recovery, lock files, disaster-recovery limits |
| [storage-integrity.md](storage-integrity.md) | Integrity chains (corruption detection), filesystem hardening, operator recovery, and why tamper evidence needs a new trust boundary |
| [audit-log.md](audit-log.md) | The durable audit log: file format, recovery, failure handling, operation, residual risks |
| [`packages/agent-sdk/README.md`](../packages/agent-sdk/README.md) | The SDK's API, options, errors and retries |
| [`apps/reference-agent/README.md`](../apps/reference-agent/README.md) | The reference agent's configuration, workflow, statuses and boundaries |
| [security-baseline.md](security-baseline.md) | The repository secret scan and secret-handling rules |
| [scanning.md](scanning.md) | Website scanning (off by default) |
| [live-readiness.md](live-readiness.md) | The advisory model and the live Muse Spark readiness notes |

## Research and audit records

These are historical records. They are not needed for integration:
- `phase7-audit.md`;
- `phase11-sentinel-research.md`;
- `phase11a-*.md`: the Sentinel ML research track, kept separate from the prototype.
