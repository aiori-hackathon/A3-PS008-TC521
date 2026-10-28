"""Candidate configuration generator: intent -> target configs -> FRR commands."""
from __future__ import annotations

from dataclasses import dataclass

from .config import RouterConfig, diff_lines, is_allowed
from .schema import OspfLinkIntent, StaticRouteIntent
from .topology import Topology


class IntentError(Exception):
    """The intent is well-formed but cannot be realised on this topology/state."""


@dataclass
class Candidate:
    configs: dict[str, RouterConfig]   # full candidate config of every router
    commands: dict[str, list[str]]     # per-router command list (only changed routers)
    summary: str


def generate(topo: Topology, baseline: dict[str, RouterConfig], intent) -> Candidate:
    target = {r: c.copy() for r, c in baseline.items()}

    if isinstance(intent, StaticRouteIntent):
        summary = _static(topo, target, intent)
    elif isinstance(intent, OspfLinkIntent):
        summary = _ospf(topo, target, intent)
    else:  # pragma: no cover - schema prevents this
        raise IntentError(f"unsupported intent {type(intent).__name__}")

    commands = {r: diff_lines(baseline[r], target[r]) for r in topo.router_names}
    commands = {r: c for r, c in commands.items() if c}
    if not commands:
        raise IntentError("no-op: the network is already in the requested state")
    for r, lines in commands.items():
        bad = [l for l in lines if not is_allowed(l)]
        if bad:  # should be impossible — guard anyway
            raise IntentError(f"generator produced non-allowlisted commands for {r}: {bad}")
    return Candidate(target, commands, summary)


def _require(topo: Topology, *routers: str):
    for r in routers:
        if r not in topo.routers:
            raise IntentError(f"unknown router {r!r} (lab has {', '.join(topo.router_names)})")


def _static(topo: Topology, target: dict[str, RouterConfig], it: StaticRouteIntent) -> str:
    _require(topo, it.router, it.next_hop_router)
    link = topo.link(it.router, it.next_hop_router)
    if not link:
        raise IntentError(f"{it.next_hop_router} is not a directly connected neighbour of {it.router}")
    nh_ip = str(link[1].ip)
    key = (str(it.destination), nh_ip)
    cfg = target[it.router]
    if it.action == "add":
        if key in cfg.static_routes:
            raise IntentError(f"route {key[0]} via {nh_ip} already exists on {it.router}")
        cfg.static_routes.add(key)
        return f"{it.router}: route {it.destination} via {it.next_hop_router} ({nh_ip})"
    if key not in cfg.static_routes:
        raise IntentError(f"cannot remove: {it.router} has no route {key[0]} via {nh_ip}")
    cfg.static_routes.discard(key)
    return f"{it.router}: remove route {it.destination} via {it.next_hop_router}"


def _ospf(topo: Topology, target: dict[str, RouterConfig], it: OspfLinkIntent) -> str:
    a, b = it.routers
    _require(topo, a, b)
    link = topo.link(a, b)
    if not link:
        raise IntentError(f"there is no link between {a} and {b}")
    for r, iface in ((a, link[0]), (b, link[1])):
        cfg = target[r]
        net = (str(iface.network), it.area)
        lan = (str(topo.lan(r).network), it.area)
        if it.action == "enable":
            cfg.ospf_networks.add(net)
            cfg.ospf_costs[iface.name] = it.cost
            if it.advertise_lans:
                cfg.ospf_networks.add(lan)
        else:
            cfg.ospf_networks.discard(net)
            cfg.ospf_costs.pop(iface.name, None)
            other_links = [
                i for i in topo.interfaces(r)
                if i.peer and (str(i.network), it.area) in cfg.ospf_networks
            ]
            if not other_links:
                cfg.ospf_networks.discard(lan)
    verb = "enable" if it.action == "enable" else "disable"
    return f"{verb} OSPF on link {a}<->{b}" + (f" (cost {it.cost})" if verb == "enable" else "")
