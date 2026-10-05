# PgPoolPrincipalIsolation 0.1.0

This is a self-authored, downstream application pool guard by **dhtfish98**. It accepts a principal that the caller has **already authenticated**, looks up the exact `(principal, database)` binding, starts a read-only transaction, and checks `current_user`, `session_user`, and `current_database()` against the binding before exposing a narrow read lease. The lease does not expose a general SQL executor. Every checkout is checked, including reused frontends. Policy reload drains idle connections.

The real local experiment uses PostgreSQL 17.6 and PgCat 1.3.0 built from the fixed upstream commit `5b038813eb14f181434ab7b5509e74d9b1fe123b`. The fixture owns two synthetic roles and two databases. A test-only weak application pool hands A's real PgCat frontend to B; that deliberately leaks a synthetic A marker. The guarded pool rejects the same deliberately misfiled connection **before** a read. The experiment then checks all four role/database combinations, overlapping and repeated transactions, server-side `pg_stat_activity`, bidirectional permission denial, release, reconnect, and policy plus PgCat reload.

The weak pool is **not** PgCat behavior or evidence of a PgCat vulnerability. The guard is an application-layer prototype, not a patch to PgCat. It is scoped to a fixed read-only fixture table. The caller must protect credentials and provide a verified principal; a caller with direct database access or arbitrary access to Python internals is outside this boundary. Policy reload does not terminate a transaction already in progress.

## Reproduce locally

Run from the workspace root. Build PostgreSQL 17.6 and the pinned PgCat commit inside `Build/环境/PgPoolPrincipalIsolation-20261006`; keep all runtime files under `Build/验证/PgPoolPrincipalIsolation-20261006`. The source tree contains `tests/live_lab.py`, which creates and tears down its own loopback PostgreSQL service and PgCat process. It never targets another database.

```sh
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=项目源码/当前项目/research-cvp30-c-20261005/PgPoolPrincipalIsolation/src \
Build/环境/PgPoolPrincipalIsolation-20261006/venv/bin/python \
项目源码/当前项目/research-cvp30-c-20261005/PgPoolPrincipalIsolation/tests/live_lab.py \
  --pg-prefix Build/环境/PgPoolPrincipalIsolation-20261006/pg17 \
  --pgcat-bin Build/环境/PgPoolPrincipalIsolation-20261006/pgcat-target/release/pgcat \
  --work-dir Build/验证/PgPoolPrincipalIsolation-20261006
```

`receipt.json` in the reported Build run directory records the exact runtime versions, PgCat executable digest, server identities and case outcomes. Its `PASS` status requires a live PostgreSQL and PgCat process. The server logs remain in Build; the generated credentials and database cluster are removed at teardown. Source-only unit tests use `pytest -q -p no:cacheprovider tests/test_gate_unit.py` with `PYTHONDONTWRITEBYTECODE=1` and `PYTHONPATH=src`.

The package depends on Psycopg 3. Its source and binary dependency licenses remain their own; see [THIRD_PARTY.md](THIRD_PARTY.md). This project does not redistribute PostgreSQL or PgCat source or binaries.

## Evidence boundary

The local synthetic comparison supports this **application guard's** behavior in the recorded environment. It does not prove a previously unknown upstream flaw, a production deployment, or Cyber Verification Program eligibility. CVP status is **OPEN** pending a real authorized defensive task and program-specific application evidence. See [CVP_STATUS.md](CVP_STATUS.md).
