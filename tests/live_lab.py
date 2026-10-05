"""Run a real, local PostgreSQL + pinned PgCat identity-isolation experiment.

All databases, users, passwords and markers are synthetic. Runtime state and
logs belong in Build, never inside the source package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timezone

import psycopg
from psycopg import sql

from pgpool_principal_isolation import Binding, PrincipalMismatch, PrincipalPool, Unauthorized


USERS = ("lab_alpha", "lab_beta")
DATABASES = ("lab_alpha", "lab_beta")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def wait_for_port(port: int, process: subprocess.Popen[str], timeout: float = 12.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"PgCat exited before listening: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("PgCat did not listen before timeout")


def pgcat_config(port: int, pg_port: int, passwords: dict[str, str]) -> str:
    lines = [
        "[general]",
        'host = "127.0.0.1"',
        f"port = {port}",
        'admin_username = "lab_admin_pgcat"',
        f"admin_password = {json.dumps(secrets.token_hex(20))}",
        "enable_prometheus_exporter = false",
        "worker_threads = 2",
        "autoreload = 15000",
    ]
    for database in DATABASES:
        lines.extend(
            [
                f"[pools.{database}]",
                'pool_mode = "transaction"',
                'default_role = "primary"',
                "query_parser_enabled = false",
                "primary_reads_enabled = true",
            ]
        )
        for index, user in enumerate(USERS):
            lines.extend(
                [
                    f"[pools.{database}.users.{index}]",
                    f"username = {json.dumps(user)}",
                    f"password = {json.dumps(passwords[user])}",
                    "pool_size = 4",
                ]
            )
        lines.extend(
            [
                f"[pools.{database}.shards.0]",
                f'servers = [["127.0.0.1", {pg_port}, "primary"]]',
                f"database = {json.dumps(database)}",
            ]
        )
    return "\n".join(lines) + "\n"


def make_databases(socket_dir: Path, pg_port: int, passwords: dict[str, str]) -> None:
    with psycopg.connect(host=str(socket_dir), port=pg_port, dbname="postgres", user="lab_admin", autocommit=True) as admin:
        for user in USERS:
            admin.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(user), sql.Literal(passwords[user])
                )
            )
        for database in DATABASES:
            admin.execute(
                sql.SQL("CREATE DATABASE {} OWNER {}").format(
                    sql.Identifier(database), sql.Identifier(database)
                )
            )
            admin.execute(
                sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database))
            )
            for user in USERS:
                admin.execute(
                    sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                        sql.Identifier(database), sql.Identifier(user)
                    )
                )
    for database, schema in zip(DATABASES, ("alpha", "beta"), strict=True):
        with psycopg.connect(host=str(socket_dir), port=pg_port, dbname=database, user="lab_admin", autocommit=True) as admin:
            admin.execute(
                sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(
                    sql.Identifier(schema), sql.Identifier(database)
                )
            )
            admin.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(database)))
            admin.execute(
                sql.SQL("CREATE TABLE {}.secret (token text NOT NULL)").format(sql.Identifier(schema))
            )
            admin.execute(
                sql.SQL("INSERT INTO {}.secret(token) VALUES (%s)").format(sql.Identifier(schema)),
                (f"{schema}-marker",),
            )
            admin.execute("RESET ROLE")


def server_audit(socket_dir: Path, pg_port: int, backend_pid: int) -> tuple[str, str]:
    with psycopg.connect(host=str(socket_dir), port=pg_port, dbname="postgres", user="lab_admin") as admin:
        row = admin.execute(
            "SELECT usename::text, datname::text FROM pg_stat_activity WHERE pid = %s", (backend_pid,)
        ).fetchone()
    if row is None:
        raise AssertionError("server-side backend PID missing from pg_stat_activity")
    return tuple(row)


def experiment(pg_port: int, pgcat_port: int, socket_dir: Path, passwords: dict[str, str], pgcat_pid: int) -> dict:
    bindings = {
        (user, database): Binding(user, database, user, passwords[user], port=pgcat_port)
        for user in USERS
        for database in DATABASES
    }
    cases: list[dict] = []

    # Test-only weak baseline: the application hands B's request an A connection.
    with psycopg.connect(host="127.0.0.1", port=pgcat_port, dbname="lab_alpha", user="lab_alpha", password=passwords["lab_alpha"], autocommit=True) as wrong_frontend:
        with wrong_frontend.transaction():
            weak_identity = wrong_frontend.execute(
                "SELECT current_user::text, session_user::text, current_database()::text"
            ).fetchone()
            weak_read = wrong_frontend.execute("SELECT token FROM alpha.secret").fetchone()
    assert weak_identity == ("lab_alpha", "lab_alpha", "lab_alpha")
    assert weak_read == ("alpha-marker",)
    cases.append({"case": "test_only_weak_pool_reuses_alpha_for_beta", "result": "LEAK", "actual_role": weak_identity[0], "synthetic_marker": weak_read[0]})

    pool = PrincipalPool(bindings)
    try:
        try:
            with pool.checkout("lab_beta", "unbound_db"):
                raise AssertionError("unbound pair was allowed")
        except Unauthorized:
            cases.append({"case": "unbound_database", "result": "DENY"})

        for round_index in range(3):
            for user, database in (("lab_alpha", "lab_alpha"), ("lab_beta", "lab_beta"), ("lab_beta", "lab_alpha"), ("lab_alpha", "lab_beta")):
                with pool.checkout(user, database) as lease:
                    identity = lease.identity
                    server_user, server_database = server_audit(socket_dir, pg_port, identity.backend_pid)
                    assert (identity.current_user, identity.session_user, identity.database) == (user, user, database)
                    assert (server_user, server_database) == (user, database)
                    if user == database:
                        own_schema = "alpha" if user == "lab_alpha" else "beta"
                        assert lease.read_secret(own_schema) == [f"{own_schema}-marker"]
                    cases.append({"case": "interleaved_transaction", "round": round_index, "requested": [user, database], "probe": [identity.current_user, identity.session_user, identity.database, identity.backend_pid], "server_audit": [server_user, server_database], "result": "PASS"})

        with pool.checkout("lab_alpha", "lab_alpha") as alpha_lease:
            with pool.checkout("lab_beta", "lab_beta") as beta_lease:
                assert alpha_lease.identity.backend_pid != beta_lease.identity.backend_pid
                assert alpha_lease.read_secret("alpha") == ["alpha-marker"]
                assert beta_lease.read_secret("beta") == ["beta-marker"]
                cases.append({"case": "overlapping_transactions", "result": "PASS", "backend_pids": [alpha_lease.identity.backend_pid, beta_lease.identity.backend_pid]})

        for user, database, schema in (("lab_beta", "lab_alpha", "alpha"), ("lab_alpha", "lab_beta", "beta")):
            try:
                with pool.checkout(user, database) as lease:
                    lease.read_secret(schema)
                raise AssertionError("cross-role table read succeeded")
            except psycopg.errors.InsufficientPrivilege:
                cases.append({"case": "cross_role_real_database_permission", "requested": [user, database], "result": "DENY"})

        # Deliberately poison an idle slot with A's real PgCat frontend.
        with pool.checkout("lab_alpha", "lab_alpha") as lease:
            first_pid = lease.identity.backend_pid
        assert len(pool._idle[("lab_alpha", "lab_alpha")]) == 1
        cases.append({"case": "frontend_released_to_idle_pool", "result": "PASS", "backend_pid": first_pid})
        alpha_conn = pool._idle[("lab_alpha", "lab_alpha")].pop()
        pool._idle[("lab_beta", "lab_alpha")].append(alpha_conn)
        try:
            with pool.checkout("lab_beta", "lab_alpha"):
                raise AssertionError("poisoned A connection reached B")
        except PrincipalMismatch:
            cases.append({"case": "guard_poisoned_idle_slot", "result": "DENY_BEFORE_READ", "prior_backend_pid": first_pid})
        with pool.checkout("lab_beta", "lab_alpha") as lease:
            assert lease.identity.current_user == "lab_beta"
            cases.append({"case": "guard_recovers_after_poison", "result": "PASS", "backend_pid": lease.identity.backend_pid})

        pool.reload(bindings)
        assert not any(pool._idle.values())
        os.kill(pgcat_pid, signal.SIGHUP)
        time.sleep(1.0)
        with pool.checkout("lab_alpha", "lab_alpha") as lease:
            assert lease.identity.current_user == "lab_alpha"
            assert lease.read_secret("alpha") == ["alpha-marker"]
            cases.append({"case": "policy_and_pgcat_reload", "result": "PASS", "backend_pid": lease.identity.backend_pid})
    finally:
        pool.close()

    reconnect = PrincipalPool(bindings)
    try:
        with reconnect.checkout("lab_beta", "lab_beta") as lease:
            assert lease.identity.current_user == "lab_beta"
            assert lease.read_secret("beta") == ["beta-marker"]
            cases.append({"case": "fresh_frontend_reconnect", "result": "PASS", "backend_pid": lease.identity.backend_pid})
    finally:
        reconnect.close()
    return {"cases": cases, "live_postgres_and_pgcat": True, "status": "PASS"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg-prefix", type=Path, required=True)
    parser.add_argument("--pgcat-bin", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    args.pg_prefix = args.pg_prefix.resolve()
    args.pgcat_bin = args.pgcat_bin.resolve()
    args.work_dir = args.work_dir.resolve()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="live-", dir=args.work_dir))
    # macOS limits Unix socket paths; keep this temporary endpoint in Build.
    socket_dir = args.work_dir.parents[1] / f"ps-{secrets.token_hex(4)}"
    socket_dir.mkdir()
    data_dir = run_dir / "pgdata"
    pg_log = run_dir / "postgres.log"
    pgcat_log = run_dir / "pgcat.log"
    pgcat_cfg = run_dir / "pgcat.toml"
    pg_port, pgcat_port = unused_port(), unused_port()
    pg_ctl = args.pg_prefix / "bin" / "pg_ctl"
    initdb = args.pg_prefix / "bin" / "initdb"
    postgres = args.pg_prefix / "bin" / "postgres"
    receipt: dict = {
        "status": "OPEN",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "postgres_version": subprocess.check_output([str(postgres), "--version"], text=True).strip(),
        "pgcat_version": subprocess.check_output([str(args.pgcat_bin), "--version"], text=True).strip(),
        "pgcat_binary_sha256": sha256(args.pgcat_bin),
        "pgcat_source_commit": "5b038813eb14f181434ab7b5509e74d9b1fe123b",
        "run_dir": str(run_dir),
    }
    pgcat_proc: subprocess.Popen[str] | None = None
    started_pg = False
    try:
        run(str(initdb), "-D", str(data_dir), "--username=lab_admin", "--auth-local=trust", "--auth-host=scram-sha-256", "--no-instructions")
        run(str(pg_ctl), "-D", str(data_dir), "-o", f"-h 127.0.0.1 -p {pg_port} -k {socket_dir}", "-l", str(pg_log), "start")
        started_pg = True
        passwords = {user: secrets.token_hex(20) for user in USERS}
        make_databases(socket_dir, pg_port, passwords)
        pgcat_cfg.write_text(pgcat_config(pgcat_port, pg_port, passwords))
        pgcat_cfg.chmod(0o600)
        receipt["pgcat_config_sha256"] = sha256(pgcat_cfg)
        with pgcat_log.open("w") as stream:
            pgcat_env = dict(os.environ, NO_COLOR="true", LOG_FORMAT="text")
            pgcat_proc = subprocess.Popen([str(args.pgcat_bin), "--log-format", "text", str(pgcat_cfg)], stdout=stream, stderr=subprocess.STDOUT, text=True, env=pgcat_env)
        wait_for_port(pgcat_port, pgcat_proc)
        receipt.update(experiment(pg_port, pgcat_port, socket_dir, passwords, pgcat_proc.pid))
        if "Reloading config" not in pgcat_log.read_text():
            raise AssertionError("PgCat did not log a config reload")
        receipt["pgcat_reload_log_seen"] = True
    except Exception as error:
        receipt["status"] = "OPEN"
        receipt["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        if pgcat_proc is not None:
            pgcat_proc.terminate()
            try:
                pgcat_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pgcat_proc.kill()
                pgcat_proc.wait(timeout=5)
        if started_pg:
            subprocess.run([str(pg_ctl), "-D", str(data_dir), "-m", "immediate", "stop"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pgcat_cfg.unlink(missing_ok=True)
        if data_dir.exists():
            shutil.rmtree(data_dir)
        if socket_dir.exists():
            socket_dir.rmdir()
        (run_dir / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"status": receipt["status"], "receipt": str(run_dir / "receipt.json"), "error": receipt.get("error")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
