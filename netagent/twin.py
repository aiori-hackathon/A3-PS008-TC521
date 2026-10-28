"""Digital twin: simulates the 3-router network from structured configs.

It builds each router's RIB (connected + static + OSPF via Dijkstra), then traces
packets hop-by-hop with longest-prefix match to detect routing loops, blackholes
and reachability regressions *before* anything touches a real router.
"""
from __future__ import annotations

import heapq
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

from .config import RouterConfig
from .topology import Topology

AD = {"connected": 0, "static": 1, "ospf": 110}
DEFAULT_OSPF_COST = 10


@dataclass
class Finding:
    severity: str  # error | warning | info
    code: str
    message: str
    router: str | None = None

    def to_dict(self):
        return {"severity": self.severity, "code": self.code, "message": self.message, "router": self.router}


@dataclass
class Route:
    prefix: ipaddress.IPv4Network
    proto: str
    next_hops: tuple[str, ...]  # neighbour router names (empty for connected)
    metric: int = 0

    @property
    def ad(self) -> int:
        return AD[self.proto]

    def __str__(self):
        via = f" via {','.join(self.next_hops)}" if self.next_hops else " directly connected"
        return f"{self.prefix} [{self.proto} {self.ad}/{self.metric}]{via}"


@dataclass
class TwinReport:
    findings: list[Finding] = field(default_factory=list)
    reach_before: dict = field(default_factory=dict)
    reach_after: dict = field(default_factory=dict)
    rib_after: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not any(f.severity == "error" for f in self.findings)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    def to_dict(self):
        return {
            "ok": self.ok,
            "findings": [f.to_dict() for f in self.findings],
            "reach_before": self.reach_before,
            "reach_after": self.reach_after,
            "rib_after": {r: [str(x) for x in routes] for r, routes in self.rib_after.items()},
        }


# ----------------------------------------------------------------------------
# RIB construction
# ----------------------------------------------------------------------------
def _ospf_enabled(topo: Topology, r: str, cfg: RouterConfig):
    nets = [ipaddress.IPv4Network(p) for p, _ in cfg.ospf_networks]
    return [i for i in topo.interfaces(r) if any(i.network.subnet_of(n) for n in nets)]


def build_rib(topo: Topology, configs: dict[str, RouterConfig]):
    findings: list[Finding] = []
    candidates: dict[str, list[Route]] = defaultdict(list)

    for r in topo.router_names:
        for i in topo.interfaces(r):
            candidates[r].append(Route(i.network, "connected", ()))

        # static routes, grouped by prefix (multiple next hops = ECMP)
        by_prefix: dict[str, list[str]] = defaultdict(list)
        for prefix, nh_ip in sorted(configs[r].static_routes):
            iface = topo.connected_iface(r, nh_ip)
            nbr = topo.router_with_ip(nh_ip)
            if iface is None or nbr is None or nbr == r:
                findings.append(Finding("error", "NEXTHOP_UNREACHABLE",
                                        f"next hop {nh_ip} for {prefix} is not a reachable neighbour", r))
                continue
            by_prefix[prefix].append(nbr)
        for prefix, nbrs in by_prefix.items():
            candidates[r].append(Route(ipaddress.IPv4Network(prefix), "static", tuple(sorted(set(nbrs)))))

    # OSPF: adjacency graph + Dijkstra from every router
    enabled = {r: _ospf_enabled(topo, r, configs[r]) for r in topo.router_names}
    graph: dict[str, dict[str, int]] = defaultdict(dict)
    for ia, ib in topo.links():
        if ia in enabled[ia.router] and ib in enabled[ib.router]:
            graph[ia.router][ib.router] = configs[ia.router].ospf_costs.get(ia.name, DEFAULT_OSPF_COST)
            graph[ib.router][ia.router] = configs[ib.router].ospf_costs.get(ib.name, DEFAULT_OSPF_COST)
    advertised = {r: {i.network for i in enabled[r]} for r in topo.router_names}

    for src in topo.router_names:
        if src not in graph:
            continue
        dist, first = {src: 0}, {src: None}
        pq = [(0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist[u]:
                continue
            for v, w in sorted(graph[u].items()):
                nd = d + w
                if nd < dist.get(v, 1 << 30):
                    dist[v] = nd
                    first[v] = v if u == src else first[u]
                    heapq.heappush(pq, (nd, v))
        connected = {i.network for i in topo.interfaces(src)}
        best: dict = {}
        for dst, d in dist.items():
            if dst == src:
                continue
            for net in advertised[dst]:
                if net in connected:
                    continue
                if net not in best or d < best[net].metric:
                    best[net] = Route(net, "ospf", (first[dst],), d)
        candidates[src].extend(best.values())

    # route selection: per prefix keep lowest administrative distance
    rib: dict[str, list[Route]] = {}
    for r in topo.router_names:
        chosen: dict = {}
        for route in candidates[r]:
            cur = chosen.get(route.prefix)
            if cur is None or (route.ad, route.metric) < (cur.ad, cur.metric):
                chosen[route.prefix] = route
        rib[r] = sorted(chosen.values(), key=lambda x: (x.prefix.prefixlen, int(x.prefix.network_address)),
                        reverse=True)
    return rib, findings


def lookup(routes: list[Route], ip) -> Route | None:
    ip = ipaddress.IPv4Address(str(ip))
    matches = [r for r in routes if ip in r.prefix]
    return max(matches, key=lambda r: r.prefix.prefixlen) if matches else None


def trace(rib: dict, src: str, dst_ip, max_hops: int = 16) -> tuple[str, list[str]]:
    path, cur, seen = [src], src, {src}
    for _ in range(max_hops):
        route = lookup(rib[cur], dst_ip)
        if route is None:
            return "blackhole", path
        if route.proto == "connected":
            return "delivered", path
        nxt = route.next_hops[0]
        path.append(nxt)
        if nxt in seen:
            return "loop", path
        seen.add(nxt)
        cur = nxt
    return "loop", path


def reachability(topo: Topology, rib: dict) -> dict:
    """LAN-to-LAN reachability matrix, e.g. {'R1->R3': {'outcome':..., 'path':[...]}}."""
    out = {}
    for s in topo.router_names:
        for d in topo.router_names:
            if s == d:
                continue
            host = topo.lan(d).network.network_address + 10  # a host on the destination LAN
            outcome, path = trace(rib, s, host)
            out[f"{s}->{d}"] = {"outcome": outcome, "path": path}
    return out


# ----------------------------------------------------------------------------
# Validation
# ----------------------------------------------------------------------------
def validate(topo: Topology, baseline: dict[str, RouterConfig], candidate: dict[str, RouterConfig]) -> TwinReport:
    rep = TwinReport()

    # 1. semantic checks on static routes
    for r in topo.router_names:
        by_prefix = defaultdict(set)
        for p, nh in candidate[r].static_routes:
            by_prefix[p].add(nh)
        for p, nhs in by_prefix.items():
            if len(nhs) > 1:
                rep.findings.append(Finding("error", "CONFLICTING_ROUTES",
                    f"{p} has {len(nhs)} different static next hops ({', '.join(sorted(nhs))})", r))
            net = ipaddress.IPv4Network(p)
            for i in topo.interfaces(r):
                if net.overlaps(i.network):
                    rep.findings.append(Finding("error", "OVERLAPS_CONNECTED",
                        f"static {p} overlaps directly connected {i.network} on {i.name}", r))

    # 2. build RIBs before/after
    rib_before, _ = build_rib(topo, baseline)
    rib_after, f = build_rib(topo, candidate)
    rep.findings += f
    rep.rib_after = rib_after

    # static overriding a dynamically learned route -> warning
    for r in topo.router_names:
        ospf_prefixes = {x.prefix for x in build_rib_ospf_only(rib_before, r)}
        for x in rib_after[r]:
            if x.proto == "static" and x.prefix in ospf_prefixes:
                rep.findings.append(Finding("warning", "STATIC_OVERRIDES_OSPF",
                    f"static {x.prefix} will override the OSPF-learned route", r))

    # 3. loop detection for every destination present anywhere
    dests = {topo.lan(r).network for r in topo.router_names}
    for r in topo.router_names:
        dests |= {ipaddress.IPv4Network(p) for p, _ in candidate[r].static_routes}
    reported = set()
    for d in sorted(dests):
        probe = d.network_address + (10 if d.num_addresses > 16 else 1)
        for s in topo.router_names:
            outcome, path = trace(rib_after, s, probe)
            if outcome == "loop":
                cyc = frozenset(path[path.index(path[-1]):])
                if (d, cyc) not in reported:
                    reported.add((d, cyc))
                    rep.findings.append(Finding("error", "ROUTING_LOOP",
                        f"traffic to {d} loops: {' -> '.join(path)}", s))

    # 4. reachability regression
    rep.reach_before = reachability(topo, rib_before)
    rep.reach_after = reachability(topo, rib_after)
    for pair, after in rep.reach_after.items():
        before = rep.reach_before[pair]
        if before["outcome"] == "delivered" and after["outcome"] != "delivered":
            rep.findings.append(Finding("error", "REACHABILITY_REGRESSION",
                f"{pair} was reachable but would become {after['outcome']}"))
        elif before["outcome"] != "delivered" and after["outcome"] == "delivered":
            rep.findings.append(Finding("info", "REACHABILITY_GAINED",
                f"{pair} becomes reachable via {' -> '.join(after['path'])}"))
        elif before["path"] != after["path"] and after["outcome"] == "delivered":
            rep.findings.append(Finding("info", "PATH_CHANGED",
                f"{pair} path {' -> '.join(before['path'])}  =>  {' -> '.join(after['path'])}"))
    return rep


def build_rib_ospf_only(rib: dict, r: str) -> list[Route]:
    return [x for x in rib[r] if x.proto == "ospf"]
