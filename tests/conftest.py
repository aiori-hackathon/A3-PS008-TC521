import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netagent.agent import NetAgent  # noqa: E402
from netagent.lab import SimulatedLab  # noqa: E402
from netagent.topology import Topology  # noqa: E402


@pytest.fixture
def topo():
    return Topology.load(ROOT / "topology.yaml")


@pytest.fixture
def lab(topo, tmp_path):
    return SimulatedLab(topo, tmp_path / "lab")


@pytest.fixture
def agent(topo, lab, tmp_path):
    return NetAgent(topo, lab, tmp_path / "state")


def req(intent: dict, by="alice", reason="lab test change"):
    return {"requested_by": by, "reason": reason, "intent": intent}


def ship(agent, intent, approver="bob"):
    """propose -> approve -> deploy, asserting each step succeeds."""
    cr = agent.propose(req(intent))
    assert cr["status"] == "PENDING_APPROVAL", cr["errors"]
    agent.approve(cr["id"], approver)
    cr = agent.deploy(cr["id"])
    assert cr["status"] == "DEPLOYED", cr.get("deploy_log")
    return cr


OSPF_12 = {"kind": "ospf_link", "routers": ["R1", "R2"], "cost": 10}
OSPF_23 = {"kind": "ospf_link", "routers": ["R2", "R3"], "cost": 10}
OSPF_13 = {"kind": "ospf_link", "routers": ["R1", "R3"], "cost": 5}


# ---- write a Markdown results table for the technical report ----------------
_results = []


def pytest_runtest_logreport(report):
    if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
        doc = ""
        item = _items.get(report.nodeid)
        if item is not None and item.obj.__doc__:
            doc = " ".join(item.obj.__doc__.split())
        _results.append((report.nodeid.split("::")[-1], doc, report.outcome))


_items = {}


def pytest_collection_modifyitems(items):
    for it in items:
        _items[it.nodeid] = it


def pytest_sessionfinish(session, exitstatus):
    if not _results:
        return
    passed = sum(1 for *_, o in _results if o == "passed")
    lines = [
        "# PS-008 test results",
        "",
        f"Run: {time.strftime('%Y-%m-%d %H:%M')} — **{passed}/{len(_results)} passed**",
        "",
        "| # | Scenario | Test | Result |",
        "|---|---|---|---|",
    ]
    for n, (name, doc, outcome) in enumerate(_results, 1):
        mark = "✅ pass" if outcome == "passed" else f"❌ {outcome}"
        lines.append(f"| {n} | {doc} | `{name}` | {mark} |")
    (ROOT / "TEST_RESULTS.md").write_text("\n".join(lines) + "\n")
