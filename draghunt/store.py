"""Private, transactional case storage. One record owns drafts, evidence and results."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .schema import SchemaError

CASE_ID = re.compile(r"^[0-9]{8}-[0-9]{6}-[A-Z0-9-]+$")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_case_id(scenario_id: str = "", now=None) -> str:
    # IDs deliberately do not identify the scenario in a blind assessment.
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{secrets.token_hex(8).upper()}"


def private_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


class BusyError(RuntimeError):
    pass


class CaseStore:
    def __init__(self, data_dir: str | Path):
        self.root = Path(data_dir).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = self.root / "cases.sqlite3"
        fd = os.open(self.db, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.db.chmod(0o600)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, document TEXT NOT NULL)")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.db, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def validate_id(case_id: str) -> None:
        if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
            raise SchemaError("bad case ID")

    def create(self, doc: dict) -> None:
        self.validate_id(doc["id"])
        with self.connect() as db:
            db.execute("INSERT INTO cases VALUES (?, ?)", (doc["id"], json.dumps(doc)))

    def get(self, case_id: str) -> dict:
        self.validate_id(case_id)
        with self.connect() as db:
            row = db.execute("SELECT document FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise SchemaError("case not found")
        return json.loads(row[0])

    def update(self, case_id: str, change) -> dict:
        self.validate_id(case_id)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT document FROM cases WHERE id=?", (case_id,)).fetchone()
            if row is None:
                raise SchemaError("case not found")
            doc = json.loads(row[0])
            change(doc)
            doc["updated_utc"] = now()
            db.execute("UPDATE cases SET document=? WHERE id=?", (json.dumps(doc), case_id))
            return doc

    def all(self) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("SELECT document FROM cases ORDER BY id DESC").fetchall()
        return [json.loads(row[0]) for row in rows]

    @contextmanager
    def target_lock(self, target: str):
        directory = self.root / "locks"
        directory.mkdir(exist_ok=True, mode=0o700)
        key = hashlib.sha256(target.encode()).hexdigest()
        fd = os.open(directory / (key + ".lock"), os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "w") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BusyError("another reset or run is using this target") from exc
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)
