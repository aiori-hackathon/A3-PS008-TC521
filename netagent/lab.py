"""Device drivers for the lab.

* SimulatedLab   — three emulated FRR routers whose running configs persist as JSON.
                   They accept the *same* FRR commands a real router would and support
                   fault injection so failed deployments can be tested.
* FrrDockerLab   — talks to real FRR containers started by containerlab
                   (lab/ps008.clab.yml) through `docker exec ... vtysh`.

Both expose the same 2 methods, so the agent doesn't care which one it drives.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .config import CommandError, RouterConfig, apply_lines, is_allowed
from .topology import Topology


class DeploymentError(Exception):
    pass


class SimulatedLab:
    """Emulated routers. Faults (one-shot) are read from <state_dir>/faults.json:
         {"R3": "apply_error"}  -> device errors halfway through the commit
         {"R2": "silent_drop"}  -> device acks the commit but doesn't apply it
    """

    def __init__(self, topo: Topology, state_dir: str | Path):
        self.topo = topo
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        for r in topo.router_names:
            if not self._path(r).exists():
                self._save(r, RouterConfig())

    def _path(self, r: str) -> Path:
        return self.dir / f"{r}.running.json"

    def _save(self, r: str, cfg: RouterConfig):
        self._path(r).write_text(json.dumps(cfg.to_dict(), indent=2))

    # ---- driver API ----------------------------------------------------
    def get_config(self, r: str) -> RouterConfig:
        return RouterConfig.from_dict(json.loads(self._path(r).read_text()))

    def apply(self, r: str, lines: list[str]) -> None:
        for l in lines:
            if not is_allowed(l):
                raise DeploymentError(f"{r}: refused non-allowlisted command {l!r}")
        fault = self._take_fault(r)
        cfg = self.get_config(r)
        if fault == "silent_drop":
            return
        if fault == "apply_error":
            half = lines[: max(1, len(lines) // 2)]
            try:
                self._save(r, apply_lines(cfg, half))  # partial commit, like a real failure
            except CommandError:
                pass
            raise DeploymentError(f"{r}: commit failed after {len(half)}/{len(lines)} lines (injected fault)")
        try:
            self._save(r, apply_lines(cfg, lines))
        except CommandError as e:
            raise DeploymentError(f"{r}: {e}") from None

    # ---- lab helpers ---------------------------------------------------
    def inject_fault(self, r: str, kind: str):
        faults = self._faults()
        faults[r] = kind
        (self.dir / "faults.json").write_text(json.dumps(faults))

    def _faults(self) -> dict:
        p = self.dir / "faults.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def _take_fault(self, r: str):
        faults = self._faults()
        kind = faults.pop(r, None)
        (self.dir / "faults.json").write_text(json.dumps(faults))
        return kind

    def reset(self):
        for r in self.topo.router_names:
            self._save(r, RouterConfig())
        (self.dir / "faults.json").write_text("{}")


class FrrDockerLab:
    """Real FRR routers in containerlab: containers named clab-<lab>-<router>."""

    def __init__(self, topo: Topology, lab_name: str = "ps008"):
        self.topo = topo
        self.lab = lab_name

    def _c(self, r: str) -> str:
        return f"clab-{self.lab}-{r.lower()}"

    def _vtysh(self, r: str, *cmds: str) -> str:
        args = ["docker", "exec", self._c(r), "vtysh"]
        for c in cmds:
            args += ["-c", c]
        p = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if p.returncode != 0 or "% " in p.stdout:
            raise DeploymentError(f"{r}: vtysh error: {(p.stdout + p.stderr).strip()}")
        return p.stdout

    def get_config(self, r: str) -> RouterConfig:
        out = self._vtysh(r, "show running-config")
        return apply_lines(RouterConfig(), out.splitlines(), strict=False)

    def apply(self, r: str, lines: list[str]) -> None:
        for l in lines:
            if not is_allowed(l):
                raise DeploymentError(f"{r}: refused non-allowlisted command {l!r}")
        self._vtysh(r, "configure terminal", *[l.strip() for l in lines], "end", "write memory")
