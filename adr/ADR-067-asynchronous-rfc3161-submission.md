# ADR-067: Asynchronous RFC 3161 submission

**Status:** Accepted
**Date:** 2026-10-06

## Context

Admission and gateway startup previously waited for RFC 3161 submissions.
A slow or unavailable TSA delayed durable admission acknowledgements and
listener binding. The existing sealed-segment rows already record durable
queued obligations alongside the exact artifact bytes and digest.

## Decision

Admission succeeds when its occurrence, sealed segments, producer state, and
idempotency result commit atomically. Timestamp submission runs after listener
binding in a fixed worker pool using separate PostgreSQL connections. Recovery
closures enter the same queue without a synchronous startup drain.

Workers claim one due segment in a short transaction using `SKIP LOCKED`.
Claims increment a persisted attempt generation and expire after five minutes.
The generation fences stale updates; a matching completed attachment is an
idempotent success and never replaces the first retained response. Artifact
bytes and digest are checked before submission; the existing RFC 3161 profile
validates the received response before attachment.

Submission is at least once. A crash or ambiguous remote outcome can cause
another request for the same digest and produce another valid token. Attachment
is atomic and retains the first committed valid response. Workers keep received
responses in memory while retrying database completion after reconnects.
A crash before attachment recovers through lease expiry and resubmission.

Failures persist an error, attempt count, and next attempt. Capped exponential
backoff defaults to five seconds initially and five minutes maximum; twenty
attempts are allowed by default. Exhausted jobs are terminal failures,
including an expired final claim. The operational database statuses are
`queued`, `verified`, and `failed`. An authenticated segment timestamp endpoint
exposes these as `queued`, `attached`, and `failed`; the existing admission
response vocabulary retains `verified`. Live submissions return `queued`.
Replay status is a best-effort projection and cannot revoke committed success.

A repeatable additive migration upgrades operational metadata for the current
profile's database slate. It does not migrate historical commitment profiles.
Queue metadata never changes sealed CBOR, artifact digests, or predecessor
bytes. Export still requires a retained verified response, and reports queued
or terminal failure refusal.

## Consequences

TSA outages affect timestamp availability rather than request or startup
latency. PostgreSQL remains required for durable admission. Operators can
inspect retry progress and tune the worker count, retry delays, and attempt
limit. A manual requeue HTTP API is deferred; failed jobs do not automatically
resume when configuration changes. Graceful shutdown stops new claims and
allows bounded active submissions to complete; abrupt termination leaves
recoverable leases.

## References

- [Issue #320](https://github.com/bilalobe/trackone/issues/320)
- [ADR-064](ADR-064-vtl-versioning-reset.md)
- [ADR-062](ADR-062-rfc5816-signer-certificate-binding.md)
