# ADR-006: The audit log is append-only and written inside the transaction it describes

Status: accepted

## Context

The service needs to answer a question asked months after the fact, about one resource, by
someone who was not there: *who changed this, when, and from what state to what state?*

Three properties are needed for an answer to be worth trusting, and each rules out an
easier design:

- **Completeness.** Every change to an audited resource has an entry.
- **Immutability.** Recorded history cannot be rewritten.
- **Correctness.** An entry describes a change that actually happened, and does not
  describe one that did not.

## Decision

A single `audit_log` table, keyed by tenant, guarded by the same row-level security policy
as every other table, written **inside the transaction that performs the change**, and made
append-only by a database trigger rather than by privilege.

## Alternatives rejected

**Log lines.** A structured log line is cheaper and is where operational questions belong.
It is rejected for this one because it cannot carry the guarantee: the log stream is
sampled, rotated, mutable by whoever owns the log platform, and has no schema. A question
about one record six months later has to be answerable exactly, not by grepping text and
hoping the line survived.

**Recording after the fact, from a queue or a background worker.** Rejected because it fails
precisely when it matters. Any crash between the effect committing and the entry being
written leaves a changed resource with no record — and an attacker who can make the recorder
fail gets to act unlogged. A trail that can lose an entry while the effect persists is not an
audit trail; it is a best-effort log with a schema, and it is worse than nothing because it
is trusted.

**Immutable *because the application does not write UPDATE or DELETE*.** Rejected as a
promise rather than a mechanism. The application is not the only thing that can issue SQL:
a later migration, a maintenance script, or a debugging session with owner credentials all
can, and none of them will read this document.

**Immutable via privileges alone.** Rejected because privileges stop the application role but
not the owner, and because the failure is silent in the direction that matters. A grant that
is missing produces an error; a grant that is *present on the wrong role* produces a quiet
success. The trigger fails loudly under every role.

**Immutable via row-level security alone.** Rejected, and this is the subtle one. RLS makes
other tenants' rows *invisible*, which for `UPDATE` and `DELETE` means the statement affects
zero rows and **reports success**. An attempt to rewrite history would return "0 rows
affected" and the caller would conclude the trail had been pruned. A `BEFORE` trigger fires
on whatever rows are visible, so a scoped `DELETE` raises instead of no-opping.

**A nullable `tenant_id` so pre-tenant events can be recorded here too.** Rejected. A
nullable tenant column weakens the policy for every row in the table, to accommodate events
that do not belong here — a failed login for an address with no account is an operational
signal for the log stream and metrics, not a change to a tenant's resource. The gap is
stated below rather than papered over.

**Audit middleware.** Rejected because it cannot express the guarantee. Middleware sees a
request and a response, not the rows that changed, and cannot join a transaction it did not
open. The before/after images only exist inside the handler's own transaction. This is the
same constraint documented for idempotency in ADR-004; here it is not a limitation to work
around but the reason for the design.

## Consequences

**The entry and the effect commit together or neither does.** `audit.Write` takes a `pgx.Tx`
rather than opening its own. This is enforced by a test that revokes `INSERT` on `audit_log`
from the application role, attempts a create, and asserts that the resource was **not**
created either. Without that test the atomicity claim is a comment.

**A failed audit write fails the request, with a 500.** That is deliberate and is the correct
signal: the cause is the service's own configuration rather than the client's input, and an
operator needs to know the trail is not being written. Failing the request is the only
alternative to either losing the entry or claiming success.

**Only successful changes are recorded.** A duplicate-slug rejection produces no entry: the
trail must not claim a change that never happened. Failed attempts are the log stream's
business.

**Archiving is recorded only on the real transition.** Archiving an already-archived project
succeeds as a retry, and recording it would fill the trail with entries asserting a state
change that did not occur — the trail's only job is to be trustworthy, so an idempotent
no-op records nothing.

**Audited images are built explicitly, never by marshalling the struct.** The trail cannot be
pruned, so whatever is written is written permanently. Marshalling `Project` directly would
mean that adding a field later starts publishing it into a permanent record, silently, with
no reviewer looking at that consequence. `auditImage` lists the fields on purpose.

**The honest limit: an owner can drop the trigger or the table.** No SQL-level control
survives the owner. This is why owner credentials live in a separate binary (`cmd/migrate`)
and are never given to the service — the same separation that makes the idempotency reaper's
privilege guard meaningful. The trigger defends against every path the application could
take, including one added carelessly later, and that is the scope it claims.

**Append-only means it grows.** There is no pruning, by design; entries are small and are
cascaded away if their tenant is deleted. A deployment that needs a retention policy must
solve it outside this table — exporting to cold storage — rather than by deleting rows,
because a retention policy that can delete is a policy an attacker can invoke.

## Not covered

- **Pre-tenant events.** A failed login for an address with no account, or a refresh-reuse
  detection before any tenant is resolved, has no tenant to key on. These go to the log
  stream and to metrics. The gap is named here so that "the trail is complete" is not
  claimed of them.
- **Reads.** The trail records changes, not access. "Who viewed this" is a different
  requirement with a different cost profile, and conflating the two would make this table
  grow with traffic rather than with change.
- **Cross-tenant administrative actions.** No such operation exists yet. If one is added it
  will need its own table or a deliberate policy exemption, because the current policy cannot
  represent it.
