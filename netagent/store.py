"""Durable storage: change requests, pre-deploy snapshots, tamper-evident audit log."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .config import RouterConfig


class Store:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        (self.root / "changes").mkdir(parents=True, exist_ok=True)
        (self.root / "snapshots").mkdir(parents=True, exist_ok=True)
        self.audit_path = self.root / "audit.jsonl"

    # ---- change requests -------------------------------------------------
    def next_id(self) -> str:
        n = len(list((self.root / "changes").glob("CR-*.json"))) + 1
        return f"CR-{n:04d}"

    def save_change(self, cr: dict):
        cr["updated_at"] = _now()
        p = self.root / "changes" / f"{cr['id']}.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(cr, indent=2))
        tmp.replace(p)  # atomic write

    def load_change(self, cid: str) -> dict:
        p = self.root / "changes" / f"{cid}.json"
        if not p.exists():
            raise KeyError(f"no change request {cid}")
        return json.loads(p.read_text())

    def list_changes(self) -> list[dict]:
        return [json.loads(p.read_text()) for p in sorted((self.root / "changes").glob("CR-*.json"))]

    # ---- snapshots (written to disk BEFORE any device is touched) ----------
    def save_snapshot(self, cid: str, configs: dict[str, RouterConfig]):
        d = self.root / "snapshots" / cid
        d.mkdir(parents=True, exist_ok=True)
        for r, c in configs.items():
            (d / f"{r}.json").write_text(json.dumps(c.to_dict(), indent=2))

    def load_snapshot(self, cid: str) -> dict[str, RouterConfig]:
        d = self.root / "snapshots" / cid
        if not d.exists():
            raise KeyError(f"no snapshot for {cid}")
        return {p.stem: RouterConfig.from_dict(json.loads(p.read_text())) for p in sorted(d.glob("*.json"))}

    # ---- audit log: each entry hashes the previous one (tamper-evident) ----
    def audit(self, event: str, **data):
        prev = "0" * 64
        if self.audit_path.exists():
            lines = self.audit_path.read_text().strip().splitlines()
            if lines:
                prev = json.loads(lines[-1])["hash"]
        entry = {"ts": _now(), "event": event, **data, "prev": prev}
        entry["hash"] = _h(entry)
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def verify_audit(self) -> tuple[bool, str]:
        if not self.audit_path.exists():
            return True, "empty log"
        prev = "0" * 64
        for n, line in enumerate(self.audit_path.read_text().strip().splitlines(), 1):
            e = json.loads(line)
            h = e.pop("hash")
            if e["prev"] != prev or _h(e) != h:
                return False, f"audit log tampered at entry {n}"
            prev = h
        return True, f"{n} entries, chain intact"


def _h(entry: dict) -> str:
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")
