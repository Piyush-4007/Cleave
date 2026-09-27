# Opt-in: credential-in-content scanning

Cleave can find attack paths that begin with a **credential exposed in storage** — an
access key sitting in a `.env` or config file in an S3 bucket, which unlocks a principal
that can escalate. This is the `CONTAINS_CREDENTIAL` → `CAN_READ` chain (Phase 4).

Finding these requires reading the **contents** of S3 objects (`s3:GetObject`). The
default `CleaveAudit` role deliberately does **not** grant this:

| Policy | Grants `s3:GetObject` (object bodies)? |
|---|---|
| `ViewOnlyAccess` | No |
| `SecurityAudit` | No |

That is the correct default for a read-only auditor — a security tool should not read your
data unless you ask it to. So credential scanning is **off by default**. Turn it on only if
you want Cleave to read object bodies looking for leaked keys.

## What Cleave does and does not store

- It reads matching objects (extension allowlist + size cap) and looks for AWS key-ID
  patterns (`AKIA…`, `ASIA…`, `AROA…`).
- It records only the **key ID**, the object location, and the principal the key maps to.
- **It never stores the secret value.** Turn the LLM off, turn this off — the finding is a
  key ID and a location, nothing sensitive beyond that.
- Every object it reads is logged.

## Enabling it (two steps)

**1. Grant `s3:GetObject` to the `CleaveAudit` role.** Attach this as an inline policy.
Scope the `Resource` to the buckets you want scanned rather than `*` if you can:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "CleaveCredentialScan",
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::*/*"
  }]
}
```

**2. Set the toggle** in `.env`:

```
CLEAVE_CREDSCAN=true
```

Leave either step undone and Cleave skips credential scanning entirely (no errors, no
AccessDenied noise) and simply won't report credential-exposure paths.
