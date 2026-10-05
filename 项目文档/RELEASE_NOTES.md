# Local candidate 0.1.0

- Added a self-authored read-only downstream pool guard with exact principal/database keying and transaction-scoped database, execution-role and login-role checks.
- Added real isolated PostgreSQL 17.6 and fixed PgCat 1.3.0 live lab covering a deliberately weak application baseline, real permission denial, server-side activity checks, overlapping and repeated transactions, poisoned idle-slot rejection, reload and reconnect.
- This is a local review candidate only. GitHub publication, CI and Release are pending independent review. CVP eligibility remains OPEN.
