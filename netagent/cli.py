"""Command-line interface.

    python -m netagent propose intents/01_ospf_r1_r2.yaml
    python -m netagent show CR-0001
    python -m netagent approve CR-0001 --by bob
    python -m netagent reject  CR-0001 --by bob --reason "not in change window"
    python -m netagent deploy  CR-0001
    python -m netagent rollback CR-0001
    python -m netagent status            # running configs + reachability matrix
    python -m netagent history | audit | reset | fault R3 apply_error
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .agent import GateError, NetAgent
from .lab import FrrDockerLab, SimulatedLab
from .topology import Topology
from .twin import build_rib, reachability

ROOT = Path(os.environ.get("NETAGENT_HOME", Path.cwd()))
ICON = {"error": "✗", "warning": "!", "info": "·"}


def make_agent() -> tuple[NetAgent, object]:
    topo = Topology.load(ROOT / "topology.yaml")
    if os.environ.get("NETAGENT_DRIVER") == "frr":
        driver = FrrDockerLab(topo)
    else:
        driver = SimulatedLab(topo, ROOT / ".netagent" / "lab")
    return NetAgent(topo, driver, ROOT / ".netagent"), driver


def print_cr(cr: dict):
    print(f"\n{cr['id']}  [{cr['status']}]")
    if cr.get("summary"):
        print(f"  intent : {cr['summary']}")
    if cr.get("requested_by"):
        print(f"  by     : {cr['requested_by']} — {cr.get('reason', '')}")
    for e in cr.get("errors", []):
        print(f"  ✗ {e}")
    if cr.get("commands"):
        print("  candidate commands:")
        for r, lines in cr["commands"].items():
            print(f"    --- {r}")
            for l in lines:
                print(f"    + {l}")
    rep = cr.get("report")
    if rep:
        print(f"  digital twin: {'PASS' if rep['ok'] else 'FAIL'}")
        for f in rep["findings"]:
            where = f" ({f['router']})" if f.get("router") else ""
            print(f"    {ICON[f['severity']]} [{f['code']}] {f['message']}{where}")
    for l in cr.get("deploy_log", []):
        print(f"  > {l}")
    if cr.get("approved_by"):
        print(f"  approved by {cr['approved_by']}")
    if cr.get("rejected_by"):
        print(f"  rejected by {cr['rejected_by']}: {cr.get('rejection_reason')}")
    if cr["status"] == "PENDING_APPROVAL":
        print(f"\n  ⏸  waiting for human review:  approve {cr['id']} --by <name>  |  reject {cr['id']} --by <name> --reason ...")


def main(argv=None):
    p = argparse.ArgumentParser(prog="netagent", description="PS-008 reviewed network change agent")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("propose").add_argument("file")
    sub.add_parser("show").add_argument("id")
    a = sub.add_parser("approve"); a.add_argument("id"); a.add_argument("--by", required=True); a.add_argument("--comment", default="")
    r = sub.add_parser("reject"); r.add_argument("id"); r.add_argument("--by", required=True); r.add_argument("--reason", required=True)
    sub.add_parser("deploy").add_argument("id")
    sub.add_parser("rollback").add_argument("id")
    sub.add_parser("status"); sub.add_parser("history"); sub.add_parser("audit"); sub.add_parser("reset")
    f = sub.add_parser("fault"); f.add_argument("router"); f.add_argument("kind", choices=["apply_error", "silent_drop"])
    args = p.parse_args(argv)

    agent, driver = make_agent()
    try:
        if args.cmd == "propose":
            print_cr(agent.propose(args.file))
        elif args.cmd == "show":
            print_cr(agent.store.load_change(args.id))
        elif args.cmd == "approve":
            cr = agent.approve(args.id, args.by, args.comment)
            print(f"✅ {cr['id']} approved by {args.by} — ready to deploy")
        elif args.cmd == "reject":
            cr = agent.reject(args.id, args.by, args.reason)
            print(f"🚫 {cr['id']} rejected by {args.by}: {args.reason} — nothing was sent to any router")
        elif args.cmd == "deploy":
            print_cr(agent.deploy(args.id))
        elif args.cmd == "rollback":
            print_cr(agent.rollback(args.id))
        elif args.cmd == "status":
            for rname, lines in agent.show_running().items():
                print(f"--- {rname} running config")
                print("\n".join(f"  {l}" for l in lines) or "  (no managed config)")
            rib, _ = build_rib(agent.topo, agent.running_configs())
            print("\nLAN reachability:")
            for pair, v in reachability(agent.topo, rib).items():
                mark = "✓" if v["outcome"] == "delivered" else "✗"
                print(f"  {mark} {pair:8} {v['outcome']:10} {' -> '.join(v['path'])}")
        elif args.cmd == "history":
            for cr in agent.store.list_changes():
                print(f"{cr['id']}  {cr['status']:18} {cr.get('summary') or '; '.join(cr.get('errors', []))[:70]}")
        elif args.cmd == "audit":
            print(agent.store.verify_audit()[1])
        elif args.cmd == "reset":
            if isinstance(driver, SimulatedLab):
                driver.reset()
                print("simulated lab reset to empty configs")
        elif args.cmd == "fault":
            driver.inject_fault(args.router, args.kind)
            print(f"next commit on {args.router} will hit: {args.kind}")
    except (GateError, KeyError) as e:
        print(f"⛔ {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
