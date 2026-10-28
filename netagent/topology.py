"""Lab topology model: routers, interfaces, point-to-point links and LANs."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Interface:
    router: str
    name: str
    address: ipaddress.IPv4Interface
    peer: str | None  # neighbouring router on a p2p link, None for a LAN

    @property
    def network(self) -> ipaddress.IPv4Network:
        return self.address.network

    @property
    def ip(self) -> ipaddress.IPv4Address:
        return self.address.ip


class Topology:
    def __init__(self, data: dict):
        self.name: str = data.get("name", "lab")
        self.platform: str = data.get("platform", "frr")
        self.routers: dict[str, dict[str, Interface]] = {}
        for rname, rdata in data["routers"].items():
            ifaces = {}
            for iname, idata in rdata["interfaces"].items():
                ifaces[iname] = Interface(
                    router=rname,
                    name=iname,
                    address=ipaddress.IPv4Interface(idata["ip"]),
                    peer=idata.get("peer"),
                )
            self.routers[rname] = ifaces

    @classmethod
    def load(cls, path: str | Path) -> "Topology":
        with open(path) as f:
            return cls(yaml.safe_load(f))

    # ---- queries -------------------------------------------------------
    @property
    def router_names(self) -> list[str]:
        return sorted(self.routers)

    def interfaces(self, router: str) -> list[Interface]:
        return list(self.routers[router].values())

    def link(self, a: str, b: str) -> tuple[Interface, Interface] | None:
        """Return (interface on a, interface on b) for the a<->b link."""
        ia = next((i for i in self.interfaces(a) if i.peer == b), None)
        ib = next((i for i in self.interfaces(b) if i.peer == a), None)
        if ia and ib:
            return ia, ib
        return None

    def links(self) -> list[tuple[Interface, Interface]]:
        out = []
        names = self.router_names
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                l = self.link(a, b)
                if l:
                    out.append(l)
        return out

    def lan(self, router: str) -> Interface:
        return next(i for i in self.interfaces(router) if i.peer is None)

    def connected_iface(self, router: str, ip) -> Interface | None:
        ip = ipaddress.IPv4Address(str(ip))
        return next((i for i in self.interfaces(router) if ip in i.network), None)

    def router_with_ip(self, ip) -> str | None:
        ip = ipaddress.IPv4Address(str(ip))
        for r in self.router_names:
            for i in self.interfaces(r):
                if i.ip == ip:
                    return r
        return None
