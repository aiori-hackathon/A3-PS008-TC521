"""The network management agent: propose -> validate -> approve -> deploy -> verify / rollback.

Change-request lifecycle
    INVALID            intent failed schema or could not be realised
    VALIDATION_FAILED  digital twin found errors (loops, conflicts, regressions)
    PENDING_APPROVAL   passed the twin, waiting at the human gate
    REJECTED           reviewer said no — nothing was ever sent to a router
    APPROVED           reviewer said yes — may now be deployed
    STALE              network drifted since validation — must be re-proposed
    DEPLOYED           applied and verified on all routers
    ROLLED_BACK        deployment failed (or was reverted) and the snapshot was restored
    ROLLBACK_FAILED    manual intervention needed (should never happen in the lab)
"""
from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from .config import RouterConfig, diff_lines, fingerprint, render
from .generator import IntentError, generate
from .lab import DeploymentError
from .schema import load_request
from .store import Store
from .topology import Topology
from .twin import validate


class GateError(Exception):
    """An action was attempted that the approval workflow does not allow."""


class NetAgent:
    def __init__(self, topo: Topology, driver, workdir: str | Path):
        self.topo = topo
        self.driver = driver
        self.store = Store(workdir)

    # ------------------------------------------------------------------
    def running_configs(self) -> dict[str, RouterConfig]:
        return {r: self.driver.get_config(r) for r in self.topo.router_names}

    # ------------------------------------------------------------------ propose
    def propose(self, source) -> dict:
        cid = self.store.next_id()
        cr = {"id": cid, "status": None, "errors": [], "commands": {}, "report": None}
        try:
            req = load_request(source)
        except ValidationError as e:
            cr.update(status="INVALID", requested_by=_get(source, "requested_by"),
                      errors=[f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors()])
            return self._finish(cr, "proposal_invalid")
        except Exception as e:  # unreadable file, bad YAML …
            cr.update(status="INVALID", errors=[str(e)])
            return self._finish(cr, "proposal_invalid")

        cr.update(requested_by=req.requested_by, reason=req.reason,
                  intent=req.intent.model_dump(mode="json"))
        baseline = self.running_configs()
        cr["baseline_fingerprint"] = fingerprint(baseline)
        try:
            cand = generate(self.topo, baseline, req.intent)
        except IntentError as e:
            cr.update(status="INVALID", errors=[str(e)])
            return self._finish(cr, "proposal_invalid")

        report = validate(self.topo, baseline, cand.configs)
        cr.update(
            summary=cand.summary,
            commands=cand.commands,
            candidate={r: c.to_dict() for r, c in cand.configs.items()},
            report=report.to_dict(),
        )
        if report.ok:
            cr["status"] = "PENDING_APPROVAL"
            return self._finish(cr, "proposal_validated")
        cr["status"] = "VALIDATION_FAILED"
        cr["errors"] = [f"[{f.code}] {f.message}" + (f" ({f.router})" if f.router else "") for f in report.errors]
        return self._finish(cr, "proposal_failed_validation")

    # ------------------------------------------------------------------ human gate
    def approve(self, cid: str, approver: str, comment: str = "") -> dict:
        cr = self.store.load_change(cid)
        if cr["status"] != "PENDING_APPROVAL":
            raise GateError(f"{cid} is {cr['status']}; only PENDING_APPROVAL changes can be approved")
        if approver.strip().lower() == (cr.get("requested_by") or "").strip().lower():
            raise GateError("four-eyes rule: the requester cannot approve their own change")
        cr.update(status="APPROVED", approved_by=approver, approval_comment=comment)
        return self._finish(cr, "approved", approver=approver)

    def reject(self, cid: str, reviewer: str, reason: str) -> dict:
        cr = self.store.load_change(cid)
        if cr["status"] not in ("PENDING_APPROVAL", "APPROVED"):
            raise GateError(f"{cid} is {cr['status']}; it cannot be rejected")
        cr.update(status="REJECTED", rejected_by=reviewer, rejection_reason=reason)
        return self._finish(cr, "rejected", reviewer=reviewer)

    # ------------------------------------------------------------------ deploy
    def deploy(self, cid: str) -> dict:
        cr = self.store.load_change(cid)
        if cr["status"] != "APPROVED":
            self.store.audit("deploy_blocked", change=cid, status=cr["status"])
            raise GateError(f"{cid} is {cr['status']}; only APPROVED changes can be deployed")

        current = self.running_configs()
        if fingerprint(current) != cr["baseline_fingerprint"]:
            cr["status"] = "STALE"
            cr["errors"] = ["network changed since this change was validated; re-propose it"]
            return self._finish(cr, "deploy_stale")

        # 1. durable snapshot BEFORE touching anything
        self.store.save_snapshot(cid, current)
        self.store.audit("snapshot_saved", change=cid, fingerprint=fingerprint(current))

        # 2. apply router by router
        target = {r: RouterConfig.from_dict(d) for r, d in cr["candidate"].items()}
        cr["deploy_log"] = []
        try:
            for r, lines in cr["commands"].items():
                self.driver.apply(r, lines)
                cr["deploy_log"].append(f"{r}: applied {len(lines)} lines")
        except DeploymentError as e:
            cr["deploy_log"].append(f"FAILED: {e}")
            return self._rollback(cr, f"deployment failed: {e}")

        # 3. post-deploy verification: device state must equal the candidate
        #    AND the twin must still be clean on what is really running.
        actual = self.running_configs()
        mismatched = [r for r in self.topo.router_names if actual[r] != target[r]]
        if mismatched:
            return self._rollback(cr, f"verification failed: running config differs from candidate on {mismatched}")
        post = validate(self.topo, current, actual)
        if not post.ok:
            return self._rollback(cr, "verification failed: " + "; ".join(f.message for f in post.errors))

        cr["status"] = "DEPLOYED"
        cr["deploy_log"].append("verified: running config == candidate, twin clean")
        return self._finish(cr, "deployed", fingerprint=fingerprint(actual))

    # ------------------------------------------------------------------ rollback
    def rollback(self, cid: str) -> dict:
        """Manually revert a DEPLOYED change to its pre-deploy snapshot."""
        cr = self.store.load_change(cid)
        if cr["status"] != "DEPLOYED":
            raise GateError(f"{cid} is {cr['status']}; only DEPLOYED changes can be rolled back")
        return self._rollback(cr, "manual rollback requested")

    def _rollback(self, cr: dict, why: str) -> dict:
        cid = cr["id"]
        snap = self.store.load_snapshot(cid)
        log = cr.setdefault("deploy_log", [])
        log.append(f"ROLLBACK: {why}")
        failed = []
        for r in self.topo.router_names:
            cur = self.driver.get_config(r)
            lines = diff_lines(cur, snap[r])
            if not lines:
                continue
            try:
                self.driver.apply(r, lines)
                log.append(f"{r}: restored ({len(lines)} lines)")
            except DeploymentError as e:
                failed.append(r)
                log.append(f"{r}: restore FAILED: {e}")
        actual = self.running_configs()
        if failed or any(actual[r] != snap[r] for r in self.topo.router_names):
            cr["status"] = "ROLLBACK_FAILED"
            return self._finish(cr, "rollback_failed", reason=why)
        cr["status"] = "ROLLED_BACK"
        cr["errors"] = [why]
        log.append("verified: all routers match pre-deploy snapshot")
        return self._finish(cr, "rolled_back", reason=why)

    # ------------------------------------------------------------------ helpers
    def _finish(self, cr: dict, event: str, **extra) -> dict:
        self.store.save_change(cr)
        self.store.audit(event, change=cr["id"], status=cr["status"], **extra)
        return cr

    def show_running(self) -> dict[str, list[str]]:
        return {r: render(c) for r, c in self.running_configs().items()}


def _get(source, key):
    return source.get(key) if isinstance(source, dict) else None
