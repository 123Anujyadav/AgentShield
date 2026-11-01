# Storage integrity and filesystem hardening (M3-E E13)

AgentShield keeps four local state files:
- the audit log (E10);
- the replay journal (E11);
- the idempotency journal (E11);
- the approval journal (E12).

This document says what M3-E E13 does to detect damage to them, what it does **not** protect
against, and how operators recover.

## The decision on tamper evidence

**Cryptographic tamper protection is not implemented, and that is deliberate.** Every state file,
the API process and anything the API could use as a key belong to **one Windows account**. Such
a key could be a key file, or a DPAPI secret under the current user. Anyone who can rewrite the
files, as that account or an administrator, can also read the key and produce valid
authentication codes again. A keyed MAC stored this way would look like tamper protection
without being any. The E13 instructions say to report this instead of building a misleading
substitute.

**What real tamper evidence would need.** A trust boundary that the API's own account cannot
cross. Options, all outside this prototype:

| Option | How it works | What it adds |
|---|---|---|
| A separate signing service account | A small local service, running as a different account, holds the key and signs (HMAC or Ed25519) a running hash of each journal on request; the API cannot read the key | Detects rewriting by the API's account; not by that service's account or an administrator |
| A TPM-bound key | Ed25519 or HMAC with a key sealed to the TPM, usable but not exportable | Detects offline edits and copies to another machine; a live process on the same machine can still use the key |
| An external anchor | Periodically send the journal's chain head to an append-only service outside the machine (a log server, a transparency log) | Detects any rewrite older than the last anchor, including by an administrator |

Each one needs decisions this phase cannot make on the operator's behalf:
- key creation and storage;
- rotation, backup and recovery after key loss (which makes every journal unverifiable);
- the extra service or account, and what to do when the signer is unavailable.

That is a new key-management model, and it is left as a recommendation.

## What is implemented: an integrity chain (corruption detection)

**Every record carries a chain value.** In the three journals each line is
`<record>\t<chain>`. In the audit log, each v2 record's `prev` is the hash of the previous
record line. The chain value is a SHA-256 over the previous value and the record, starting from
a per-file genesis value.

**What it detects:**

| Change | Detected? |
|---|---|
| Modification of a record (disk damage, a partial or careless edit) | **Yes:** that record no longer verifies |
| Deletion of a record | **Yes:** the next record no longer verifies |
| Insertion of a record | **Yes:** it and the next record fail |
| Reordering | **Yes** |
| A record with missing or invalid integrity metadata | **Yes** |
| A journal copied from another store | **Yes:** each store has its own genesis value |
| Whole records removed from the end of the file | **No:** there is no external anchor |
| A deliberate edit that recomputes the chain | **No:** there is no key (see above) |

**This is corruption detection, not authenticity.** It catches accidents and unsophisticated
edits, never a determined local attacker.

## What each store does when the chain does not verify

**Nothing is ever silently accepted.** Every case is logged at start-up as
`… status=integrity-failure …`, and every store ends in a safe state.

| Store | On an unverified or damaged record |
|---|---|
| Approvals | Every pending approval the record names, or every pending approval if it names none, becomes `OUTCOME_UNKNOWN`. It is **never executable**, and cannot be approved or rejected. Final approvals stay final. |
| Replay journal | Unverified nonces are still honoured (refusing more is safe). The **recovery fence** applies: signed requests dated up to start-up + skew are refused. Replay protection never silently resets. |
| Idempotency journal | Every key named by an unverified record becomes **outcome-unknown**: a stored result is never replayed from it, and it is never evaluated again. Keys without a record are refused for 15 minutes (the retention). |
| Audit log | Unverified events stay in the file but are **left out of the event view**. They are reported at every start until the operator archives the file. New events are chained after the last valid record. |

**Recovery is preserved and durable.**
- **A damaged journal is copied** next to itself (`<name>.damaged-<time>`, restricted to the
  current user) before it is rewritten into its recovered state. The path is logged, never
  returned by the API.
- **A record cut short by a crash** is still recognised and dropped, without being treated as
  tampering. Since E13, owners also rewrite the journal after such a crash. This fixes an E12
  defect where the leftover line was read as damage at the next restart.

**Migration.** Journals written before E13 have no chain. They are accepted once, logged as
`status=migrated`, and rewritten in the chained form. Old audit records (v1) are accepted only as
a prefix, before the first chained record; new records are chained after them. An unchained
record after a chained one is an integrity failure.

## Filesystem hardening

| Concern | Status |
|---|---|
| A symbolic link or junction as the file itself | Refused (E10/E11) |
| **A symbolic link or junction as any parent directory** | **Refused since E13**, before and after creating missing directories. Applies to the journals, the audit log, and every restricted file the credential CLI writes. |
| A file replaced between check and use | The opened file's identity (device and file id) is compared with the inspected one; replacements during compaction reopen and re-check |
| **The lock file removed or replaced while the API runs** | **Detected before every write since E13.** The store stops writing (fail closed: `lock-lost`, then 503), so two processes never interleave records. Another process's lock is never removed. |
| A lock file that is a link | Never followed when reading the process id |
| Permissions | New files are created with a single ACL entry for the current user (Windows) or mode 0600. At start-up each journal reports `permissions-not-restricted` if an existing file is readable by others. |
| Atomic compaction | A restricted temporary file is fsynced and renamed over the journal. A crash before the rename leaves the old journal intact; this is tested. |

**Not changed:**
- the API token file is still created with mode 0600 only, so on Windows it inherits the
  profile's ACL;
- the `--out` ACL timing on shared directories (E9 L6).

## Operator recovery

1. **Read the start-up log.** Look for `integrity-failure`, `migrated`, `recovered` and `copy=`.
2. **Compare the damaged copy with the current journal.** Decide whether the damage was an
   accident (disk, editor) or interference.
3. **Approvals now `OUTCOME_UNKNOWN`:** establish what happened, and ask agents to submit a new
   evaluation where needed.
4. **An audit log with unverified events:** stop the API, archive the file (keep it: it is
   evidence), and start again.
5. **If interference is suspected,** treat the account as compromised: rotate the API token and
   every agent credential (see `agent-identity.md`, Incident response).

## Residual risks

- **Anyone controlling the API's Windows account, or an administrator,** can still read, rewrite
  or delete every state file undetectably: by recomputing the chain, by truncating whole records
  from the end, or by deleting a file. This is the same trust level as the API token and the
  credential store.
- **Deleting a journal while the API is stopped:**
  - the replay journal: covered by the recovery fence;
  - the approval journal: approvals are lost and ids restart (agents bound to `createdAt` notice);
  - the idempotency journal: retries within 15 minutes may run again.
- **Bypassing the pre-commit hook** (`git commit --no-verify`) is possible. `npm run
  security:verify` before pushing remains the gate (see `security-baseline.md`).
