# ADR-001: Postgres transactional outbox, not a message broker

Status: accepted

## Context

Webhook delivery needs a durable queue of events that must not be lost and must not be sent for
changes that never happened. Two events in this service have that shape: a domain change (an
invoice issued, paid, voided) and the notification that is owed because of it.

The obvious architecture is a broker. NATS, RabbitMQ, and Kafka all offer durable streams, retries,
consumer groups, and dead-letter queues as first-class features — all of which had to be written by
hand for this service, and none of which are interesting code to write.

## Decision

The event rows are written to a `webhook_outbox` table **inside the same transaction** that changes
the domain object. A separate `cmd/worker` binary claims rows with `FOR UPDATE SKIP LOCKED`,
delivers them over HTTP, and settles the outcome.

## Why the broker was rejected

**The transaction boundary is the whole argument.** A broker client publishes over the network, and
a network publish cannot participate in a Postgres transaction. Every arrangement of the two is
broken in one direction:

- Publish after commit — a crash in the gap loses the event permanently. The change is in the
  database, the notification is nowhere, and nothing records that one was owed.
- Publish before commit — a rollback sends an event for a change that never happened. For
  `invoice.paid` that is a receiver shipping goods against an unsettled invoice.
- Publish inside the transaction with a two-phase commit — the broker must support XA, Postgres's
  XA is a documented footgun, and the operational complexity is greater than the queue it is
  keeping consistent.

There is no fourth option, because the atomicity has to span both systems and only one of them can
be the transaction's owner. An outbox sidesteps this rather than solving it: there is exactly one
system, so there is nothing to keep consistent.

**Secondary, and genuinely secondary:** the deployment gains no new moving part. The queue is the
database that is already there and already backed up, and an operator inspecting a stuck delivery
runs SQL against a table they already know. Broker-side ordering guarantees and consumer-group
semantics are not used here — the delivery model is at-least-once with a per-row lease, which is
what a broker would have been configured to provide anyway.

## Consequences

**Accepted costs:**

- **Throughput ceiling.** Claiming is a poll against one table. It is bounded by Postgres's write
  throughput, and this design would not carry tens of thousands of events per second. For a
  multi-tenant billing API that is not the operating point; the decision is recorded here so that
  reaching that scale is understood as a rewrite of this boundary rather than a surprise.
- **Polling latency.** An idle worker sleeps `WORKER_INTERVAL` (default 1s) between empty polls, so
  a delivery can wait up to that long. Claimed work is settled immediately, so the interval is idle
  cadence rather than delivery latency. A `LISTEN/NOTIFY` wakeup would remove it, and is a change
  to this design rather than a departure from it.
- **The queue is a table, so it needs pruning.** Delivered rows accumulate; `migrate sweep` exists
  for that and runs with owner credentials because it spans tenants.

**Load-bearing details that follow from this decision:**

- **The lease is the recovery mechanism.** `Claim` takes rows in `pending` or in `delivering` whose
  lease has lapsed. A worker killed mid-delivery is recovered by expiry rather than by a broker's
  redelivery, which is why `LeaseDuration` must exceed `DeliveryTimeout` plus the receiver's real
  latency.
- **The attempt number is a fencing token.** After a reclaim the row is `delivering` again with a
  fresh lease, so state and lease predicates alone cannot distinguish the old holder from the new
  one. `Settle` matches on `attempts = $N` so a stale worker's settle fails rather than marking a
  delivery complete while the live owner is mid-attempt.
- **Sweeps need owner credentials.** A maintenance query spans every tenant, which the application
  role's row-level security forbids by design. That is enforced at the call site rather than
  documented as a rule.
- **One event, one row per endpoint.** Fan-out happens at enqueue, so the count the caller acts on
  distinguishes "three receivers were notified" from "nobody is listening" — a distinction the API
  surfaces, and one a broker's publish-and-forget would have hidden.
