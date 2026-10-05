"""Fail closed on version, author, rights, or unsafe files in release archives."""

from __future__ import annotations

import argparse
from email.parser import Parser
from pathlib import Path
import tarfile
import zipfile


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify(path: Path) -> None:
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path) as archive:
            members = {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}
        metadata_name = next(name for name in members if name.endswith("/PKG-INFO"))
    elif path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            members = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
        metadata_name = next(name for name in members if name.endswith(".dist-info/METADATA"))
    else:
        raise ValueError(f"unsupported archive: {path}")
    meta = Parser().parsestr(members[metadata_name].decode())
    require(meta["Name"] == "pgpool-principal-isolation", "package name mismatch")
    require(meta["Version"] == "0.1.0", "version mismatch")
    require("dhtfish98" in (meta["Author"] or ""), "author mismatch")
    require(meta["License-Expression"] == "MIT", "license metadata mismatch")
    require(any(name.endswith("/项目文档/LICENSE") for name in members), "own license absent")
    require(any(name.endswith("/gate.py") for name in members), "guard implementation absent")
    require(not any("/tests/" in name or "/Build/" in name or "__pycache__" in name for name in members), "tests or build output shipped")
    if path.name.endswith(".tar.gz"):
        rights_name = next((name for name in members if name.endswith("/项目文档/THIRD_PARTY.md")), None)
        require(rights_name is not None, "third-party notice absent")
        require(b"PgCat Contributors" in members[rights_name], "PgCat original rights absent")
    print(f"PASS {path.name}: {len(members)} files, 0 weak-baseline tests")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archives", type=Path, nargs="+")
    args = parser.parse_args()
    for archive in args.archives:
        verify(archive)


if __name__ == "__main__":
    main()
