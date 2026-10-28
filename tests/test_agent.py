import json

import pytest

from conftest import OSPF_12, OSPF_13, OSPF_23, req, ship
from netagent.agent import GateError, NetAgent
from netagent.config import CommandError, RouterConfig, apply_lines
from netagent.lab import DeploymentError


# =========================================================================
# A. Intent schema & invalid configurations
# =========================================================================
def test_valid_ospf_intent_passes(agent):
    """[Schema] A well-formed OSPF intent is accepted and reaches the approval gate."""
    cr = agent.propose(req(OSPF_12))
    assert cr["status"] == "PENDING_APPROVAL"
    assert set(cr["commands"]) == {"R1", "R2"}


def test_malformed_prefix_rejected(agent):
    """[Invalid config] A prefix with host bits set (10.0.3.5/24) is rejected by the schema."""
    cr = agent.propose(req({"kind": "static_route", "router": "R1",
                            "destination": "10.0.3.5/24", "next_hop_router": "R2"}))
    assert cr["status"] == "INVALID"
    assert any("destination" in e for e in cr["errors"])


def test_raw_cli_smuggling_rejected(agent):
    """[Security] Extra fields such as raw_commands are rejected — no unrestricted commands."""
    cr = agent.propose(req({"kind": "static_route", "router": "R1", "destination": "10.9.0.0/24",
                            "next_hop_router": "R2", "raw_commands": ["write erase"]}))
    assert cr["status"] == "INVALID"
    assert any("raw_commands" in e for e in cr["errors"])


def test_unknown_intent_kind_rejected(agent):
    """[Schema] An intent type outside the two supported kinds is rejected."""
    cr = agent.propose(req({"kind": "bgp_peer", "routers": ["R1", "R2"]}))
    assert cr["status"] == "INVALID"


def test_out_of_range_ospf_cost_rejected(agent):
    """[Invalid config] OSPF cost 70000 (> 65535) is rejected."""
    cr = agent.propose(req({**OSPF_12, "cost": 70000}))
    assert cr["status"] == "INVALID"


def test_default_route_blocked_by_policy(agent):
    """[Policy] A default route 0.0.0.0/0 is refused by the intent policy."""
    cr = agent.propose(req({"kind": "static_route", "router": "R1",
                            "destination": "0.0.0.0/0", "next_hop_router": "R2"}))
    assert cr["status"] == "INVALID"


def test_unknown_router_rejected(agent):
    """[Invalid config] An intent referencing router R9 (not in the lab) is rejected."""
    cr = agent.propose(req({"kind": "ospf_link", "routers": ["R1", "R9"]}))
    assert cr["status"] == "INVALID"
    assert "unknown router" in cr["errors"][0]


def test_removing_missing_route_rejected(agent):
    """[Invalid config] Removing a static route that does not exist is rejected."""
    cr = agent.propose(req({"kind": "static_route", "action": "remove", "router": "R1",
                            "destination": "172.16.50.0/24", "next_hop_router": "R2"}))
    assert cr["status"] == "INVALID"


def test_noop_intent_rejected(agent):
    """[Invalid config] Re-applying an already-deployed intent is detected as a no-op."""
    ship(agent, OSPF_12)
    cr = agent.propose(req(OSPF_12))
    assert cr["status"] == "INVALID" and "no-op" in cr["errors"][0]


# =========================================================================
# B. Digital twin: conflicting routes, loops, regressions
# =========================================================================
def test_twin_computes_full_reachability(agent):
    """[Twin] After OSPF on R1-R2 and R2-R3, all six LAN pairs are reachable in the twin."""
    ship(agent, OSPF_12)
    cr = agent.propose(req(OSPF_23))
    reach = cr["report"]["reach_after"]
    assert all(v["outcome"] == "delivered" for v in reach.values())
    assert reach["R1->R3"]["path"] == ["R1", "R2", "R3"]


def test_conflicting_static_routes_detected(agent):
    """[Conflicting routes] Same prefix with two different next hops on R1 fails validation."""
    ship(agent, {"kind": "static_route", "router": "R1", "destination": "172.16.50.0/24", "next_hop_router": "R2"})
    cr = agent.propose(req({"kind": "static_route", "router": "R1",
                            "destination": "172.16.50.0/24", "next_hop_router": "R3"}))
    assert cr["status"] == "VALIDATION_FAILED"
    assert any("CONFLICTING_ROUTES" in e for e in cr["errors"])


def test_routing_loop_detected(agent):
    """[Conflicting routes] R1->R2 and R2->R1 for the same prefix is caught as a routing loop."""
    ship(agent, {"kind": "static_route", "router": "R1", "destination": "172.16.50.0/24", "next_hop_router": "R2"})
    cr = agent.propose(req({"kind": "static_route", "router": "R2",
                            "destination": "172.16.50.0/24", "next_hop_router": "R1"}))
    assert cr["status"] == "VALIDATION_FAILED"
    assert any("ROUTING_LOOP" in e for e in cr["errors"])


def test_static_overlapping_connected_detected(agent):
    """[Conflicting routes] A static route for R1's own LAN (10.0.1.0/24) is flagged as overlapping."""
    cr = agent.propose(req({"kind": "static_route", "router": "R1",
                            "destination": "10.0.1.0/24", "next_hop_router": "R2"}))
    assert cr["status"] == "VALIDATION_FAILED"
    assert any("OVERLAPS_CONNECTED" in e for e in cr["errors"])


def test_reachability_regression_detected(agent):
    """[Twin] Disabling the only OSPF path to R3 is blocked as a reachability regression."""
    ship(agent, OSPF_12)
    ship(agent, OSPF_23)
    cr = agent.propose(req({"kind": "ospf_link", "action": "disable", "routers": ["R2", "R3"]}))
    assert cr["status"] == "VALIDATION_FAILED"
    assert any("REACHABILITY_REGRESSION" in e for e in cr["errors"])


def test_redundant_path_allows_safe_disable(agent):
    """[Twin] With R1-R3 also in OSPF, disabling R2-R3 is safe (traffic reroutes) and passes."""
    ship(agent, OSPF_12); ship(agent, OSPF_23); ship(agent, OSPF_13)
    cr = agent.propose(req({"kind": "ospf_link", "action": "disable", "routers": ["R2", "R3"]}))
    assert cr["status"] == "PENDING_APPROVAL"
    assert cr["report"]["reach_after"]["R2->R3"]["path"] == ["R2", "R1", "R3"]


# =========================================================================
# C. Human approval gate
# =========================================================================
def test_deploy_without_approval_blocked(agent, lab):
    """[Approval gate] Deploying a change that is still pending approval is refused."""
    cr = agent.propose(req(OSPF_12))
    with pytest.raises(GateError):
        agent.deploy(cr["id"])
    assert lab.get_config("R1") == RouterConfig()


def test_rejected_change_never_deployed(agent, lab):
    """[Rejected approval] A rejected change cannot be deployed and the lab is untouched."""
    cr = agent.propose(req(OSPF_12))
    agent.reject(cr["id"], "bob", "outside change window")
    with pytest.raises(GateError):
        agent.deploy(cr["id"])
    assert all(lab.get_config(r) == RouterConfig() for r in ("R1", "R2", "R3"))
    assert agent.store.load_change(cr["id"])["status"] == "REJECTED"


def test_self_approval_blocked(agent):
    """[Approval gate] Four-eyes rule: the requester cannot approve their own change."""
    cr = agent.propose(req(OSPF_12, by="alice"))
    with pytest.raises(GateError):
        agent.approve(cr["id"], "Alice")


def test_failed_validation_cannot_be_approved(agent):
    """[Approval gate] A change that failed the twin can never be approved."""
    cr = agent.propose(req({"kind": "static_route", "router": "R1",
                            "destination": "10.0.1.0/24", "next_hop_router": "R2"}))
    with pytest.raises(GateError):
        agent.approve(cr["id"], "bob")


def test_stale_change_blocked_after_drift(agent, lab):
    """[Approval gate] If the network changes after approval, the stale change is refused."""
    cr = agent.propose(req(OSPF_12))
    agent.approve(cr["id"], "bob")
    lab.apply("R3", ["ip route 192.168.9.0/24 10.0.23.1"])  # out-of-band change
    cr = agent.deploy(cr["id"])
    assert cr["status"] == "STALE"
    assert lab.get_config("R1") == RouterConfig()


# =========================================================================
# D. Deployment, failed deployment & rollback
# =========================================================================
def test_successful_deploy_matches_candidate(agent, lab):
    """[Deploy] An approved change is applied and the running config equals the candidate."""
    cr = ship(agent, OSPF_12)
    assert lab.get_config("R1") == RouterConfig.from_dict(cr["candidate"]["R1"])
    assert ("10.0.12.0/30", 0) in lab.get_config("R2").ospf_networks


def test_failed_deployment_rolls_back_all_routers(agent, lab):
    """[Failed deployment] R3 fails mid-commit; R1 and the partial R3 change are both rolled back."""
    ship(agent, OSPF_12); ship(agent, OSPF_23)
    before = {r: lab.get_config(r) for r in ("R1", "R2", "R3")}
    cr = agent.propose(req(OSPF_13)); agent.approve(cr["id"], "bob")
    lab.inject_fault("R3", "apply_error")
    cr = agent.deploy(cr["id"])
    assert cr["status"] == "ROLLED_BACK"
    assert {r: lab.get_config(r) for r in ("R1", "R2", "R3")} == before


def test_silent_failure_caught_by_verification(agent, lab):
    """[Failed deployment] Device acks but silently drops the commit; verification triggers rollback."""
    cr = agent.propose(req(OSPF_12)); agent.approve(cr["id"], "bob")
    lab.inject_fault("R2", "silent_drop")
    cr = agent.deploy(cr["id"])
    assert cr["status"] == "ROLLED_BACK"
    assert "verification failed" in cr["errors"][0]
    assert lab.get_config("R1") == RouterConfig()


def test_manual_rollback_restores_snapshot(agent, lab):
    """[Rollback] A deployed change can be reverted to its saved pre-deploy snapshot."""
    cr = ship(agent, OSPF_12)
    agent.rollback(cr["id"])
    assert all(lab.get_config(r) == RouterConfig() for r in ("R1", "R2", "R3"))


def test_snapshot_is_durable_across_restart(agent, lab, topo, tmp_path):
    """[Rollback] Snapshots live on disk: a brand-new agent process can still roll back."""
    cr = ship(agent, OSPF_12)
    fresh = NetAgent(topo, lab, tmp_path / "state")  # simulates agent restart
    fresh.rollback(cr["id"])
    assert lab.get_config("R1") == RouterConfig()


# =========================================================================
# E. Command allowlist & audit trail
# =========================================================================
def test_driver_refuses_non_allowlisted_command(lab):
    """[Security] The device driver refuses any command outside the allowlist (e.g. 'write erase')."""
    with pytest.raises(DeploymentError):
        lab.apply("R1", ["write erase"])
    with pytest.raises(CommandError):
        apply_lines(RouterConfig(), ["no router ospf"])


def test_audit_log_tamper_evident(agent):
    """[Audit] Every action is hash-chained in the audit log; editing an entry is detected."""
    ship(agent, OSPF_12)
    ok, _ = agent.store.verify_audit()
    assert ok
    lines = agent.store.audit_path.read_text().splitlines()
    e = json.loads(lines[1]); e["status"] = "DEPLOYED-BY-HACKER"
    lines[1] = json.dumps(e)
    agent.store.audit_path.write_text("\n".join(lines) + "\n")
    ok, msg = agent.store.verify_audit()
    assert not ok and "tampered" in msg
