"""Structured router configuration + a tiny FRR (vtysh) command interpreter.

The agent never stores free-form CLI text as its source of truth. Every router's
running config is reduced to a small structured model (RouterConfig). Commands
are *derived* from diffs of that model, and every command must pass a strict
allowlist before it can reach a device.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field


class CommandError(Exception):
    """Raised when a command is not allowed, malformed or cannot be applied."""


# Only these command shapes can ever be sent to a router (defence in depth:
# even a buggy generator or a malicious intent cannot emit anything else).
_IP = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
ALLOWED_PATTERNS = [
    rf"^(no )?ip route {_IP}/\d{{1,2}} {_IP}$",
    r"^router ospf$",
    rf"^ (no )?network {_IP}/\d{{1,2}} area 0$",
    r"^interface eth[0-9]{1,2}$",
    r"^ ip ospf cost \d{1,5}$",
    r"^ no ip ospf cost$",
    r"^exit$",
]
_ALLOWED = [re.compile(p) for p in ALLOWED_PATTERNS]


def is_allowed(line: str) -> bool:
    return any(p.match(line) for p in _ALLOWED)


def _net(text: str) -> str:
    try:
        return str(ipaddress.IPv4Network(text, strict=False))
    except ValueError as e:
        raise CommandError(f"bad prefix {text!r}: {e}") from None


def _ip(text: str) -> str:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError as e:
        raise CommandError(f"bad address {text!r}: {e}") from None


@dataclass
class RouterConfig:
    static_routes: set[tuple[str, str]] = field(default_factory=set)  # (prefix, next-hop ip)
    ospf_networks: set[tuple[str, int]] = field(default_factory=set)  # (prefix, area)
    ospf_costs: dict[str, int] = field(default_factory=dict)          # iface -> cost

    def copy(self) -> "RouterConfig":
        return RouterConfig(set(self.static_routes), set(self.ospf_networks), dict(self.ospf_costs))

    def to_dict(self) -> dict:
        return {
            "static_routes": [{"prefix": p, "next_hop": n} for p, n in sorted(self.static_routes)],
            "ospf": {
                "networks": [{"prefix": p, "area": a} for p, a in sorted(self.ospf_networks)],
                "costs": dict(sorted(self.ospf_costs.items())),
            },
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RouterConfig":
        ospf = d.get("ospf", {})
        return cls(
            {(r["prefix"], r["next_hop"]) for r in d.get("static_routes", [])},
            {(n["prefix"], int(n["area"])) for n in ospf.get("networks", [])},
            {k: int(v) for k, v in ospf.get("costs", {}).items()},
        )


def fingerprint(configs: dict[str, RouterConfig]) -> str:
    blob = json.dumps({r: c.to_dict() for r, c in sorted(configs.items())}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def render(cfg: RouterConfig) -> list[str]:
    """Render the full managed config as FRR commands (for display/export)."""
    lines = [f"ip route {p} {n}" for p, n in sorted(cfg.static_routes)]
    if cfg.ospf_networks:
        lines.append("router ospf")
        lines += [f" network {p} area {a}" for p, a in sorted(cfg.ospf_networks)]
        lines.append("exit")
    for iface, cost in sorted(cfg.ospf_costs.items()):
        lines += [f"interface {iface}", f" ip ospf cost {cost}", "exit"]
    return lines


def diff_lines(cur: RouterConfig, tgt: RouterConfig) -> list[str]:
    """Minimal FRR command sequence that turns `cur` into `tgt`."""
    lines: list[str] = []
    for p, n in sorted(cur.static_routes - tgt.static_routes):
        lines.append(f"no ip route {p} {n}")
    for p, n in sorted(tgt.static_routes - cur.static_routes):
        lines.append(f"ip route {p} {n}")
    rm = cur.ospf_networks - tgt.ospf_networks
    add = tgt.ospf_networks - cur.ospf_networks
    if rm or add:
        lines.append("router ospf")
        lines += [f" no network {p} area {a}" for p, a in sorted(rm)]
        lines += [f" network {p} area {a}" for p, a in sorted(add)]
        lines.append("exit")
    for iface in sorted(set(cur.ospf_costs) | set(tgt.ospf_costs)):
        c, t = cur.ospf_costs.get(iface), tgt.ospf_costs.get(iface)
        if c == t:
            continue
        lines.append(f"interface {iface}")
        lines.append(f" ip ospf cost {t}" if t is not None else " no ip ospf cost")
        lines.append("exit")
    return lines


def apply_lines(cfg: RouterConfig, lines: list[str], strict: bool = True) -> RouterConfig:
    """Interpret FRR commands against a config, returning the new config.

    strict=True  -> used for deployments: every line must be allowlisted and valid.
    strict=False -> used to parse `show running-config`: unknown lines are ignored.
    """
    new = cfg.copy()
    ctx: tuple | None = None
    for raw in lines:
        line = raw.rstrip("\n").rstrip()
        s = line.strip()
        if not s or s.startswith("!"):
            continue
        if strict and not is_allowed(line):
            raise CommandError(f"command not in allowlist: {line!r}")
        neg = s.startswith("no ")
        toks = (s[3:] if neg else s).split()
        indented = line.startswith(" ")

        if not indented and toks[:2] == ["ip", "route"] and len(toks) == 4:
            ctx = None
            key = (_net(toks[2]), _ip(toks[3]))
            if neg:
                if key not in new.static_routes and strict:
                    raise CommandError(f"no such route: {key}")
                new.static_routes.discard(key)
            else:
                new.static_routes.add(key)
        elif s == "router ospf":
            ctx = ("ospf",)
        elif not indented and toks[0] == "interface" and len(toks) >= 2:
            ctx = ("iface", toks[1])
        elif s in ("exit", "exit-vrf", "end"):
            ctx = None
        elif ctx == ("ospf",) and toks[0] == "network" and len(toks) == 4 and toks[2] == "area":
            area = 0 if toks[3] in ("0", "0.0.0.0") else int(toks[3])
            key = (_net(toks[1]), area)
            if neg:
                if key not in new.ospf_networks and strict:
                    raise CommandError(f"no such ospf network: {key}")
                new.ospf_networks.discard(key)
            else:
                new.ospf_networks.add(key)
        elif ctx and ctx[0] == "iface" and toks[:3] == ["ip", "ospf", "cost"]:
            if neg:
                new.ospf_costs.pop(ctx[1], None)
            else:
                cost = int(toks[3])
                if not 1 <= cost <= 65535:
                    raise CommandError(f"ospf cost out of range: {cost}")
                new.ospf_costs[ctx[1]] = cost
        elif not indented and not strict:
            ctx = None  # some other top-level block we don't manage
        elif strict:
            raise CommandError(f"unsupported command: {line!r}")
    return new
