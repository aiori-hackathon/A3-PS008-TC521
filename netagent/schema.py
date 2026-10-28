"""Structured intent schema for operator requests.

Two intent types are supported (placeholders for the 2 mentor-defined intents):
  * static_route : add/remove a static route on one router towards a neighbour
  * ospf_link    : enable/disable OSPF on the link between two routers

Anything outside this schema (extra fields, raw CLI, unknown kinds) is rejected.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Annotated, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RouterName = Annotated[str, Field(pattern=r"^R[0-9]{1,2}$")]


class StaticRouteIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["static_route"]
    action: Literal["add", "remove"] = "add"
    router: RouterName
    destination: ipaddress.IPv4Network  # host bits must be zero, e.g. 10.0.3.0/24
    next_hop_router: RouterName

    @field_validator("destination")
    @classmethod
    def no_default_or_host(cls, v: ipaddress.IPv4Network):
        if v.prefixlen < 8:
            raise ValueError("default/very broad routes (< /8) are not allowed by policy")
        if v.prefixlen > 30:
            raise ValueError("host routes (> /30) are not allowed by policy")
        return v

    @model_validator(mode="after")
    def distinct(self):
        if self.router == self.next_hop_router:
            raise ValueError("next_hop_router must differ from router")
        return self


class OspfLinkIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["ospf_link"]
    action: Literal["enable", "disable"] = "enable"
    routers: tuple[RouterName, RouterName]
    cost: int = Field(10, ge=1, le=65535)
    area: Literal[0] = 0  # single-area (backbone) only
    advertise_lans: bool = True

    @model_validator(mode="after")
    def distinct(self):
        if self.routers[0] == self.routers[1]:
            raise ValueError("an OSPF link needs two different routers")
        return self


Intent = Annotated[Union[StaticRouteIntent, OspfLinkIntent], Field(discriminator="kind")]


class IntentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requested_by: Annotated[str, Field(min_length=1, max_length=64)]
    reason: Annotated[str, Field(min_length=3, max_length=500)]
    intent: Intent


def load_request(source: str | Path | dict) -> IntentRequest:
    """Parse a request from a dict or YAML/JSON file. Raises pydantic.ValidationError."""
    if isinstance(source, dict):
        data = source
    else:
        with open(source) as f:
            data = yaml.safe_load(f)
    return IntentRequest.model_validate(data)
