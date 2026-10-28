# AIORI-3-HACKATHON-PROJECTS
This repository will contain the code and resources for the AIORI-3 hackathon that will be developed during the AIORI-3

Youtube Video Link: https://youtu.be/F01deyZpbHU

Presentation: [A3-PS008-TC521-NegativeLatency.pdf](A3-PS008-TC521-NegativeLatency.pdf)

# PS-008 — Network Management Agent for Reviewed Configuration Changes

An intent-based agent for a 3-router FRRouting lab. Operators describe **what** they want
(a structured intent); the agent generates the router commands, proves them safe in a
**digital twin**, stops at a **human approval gate**, deploys, verifies, and **rolls back
automatically** if anything goes wrong.

> Think of it as a pull-request + CI/CD pipeline, but for routers:
> intent = PR description · generator = the diff · twin = CI tests · approval = code review ·
> deploy = merge · rollback = `git revert`.

## Pipeline

```
 intent.yaml ──► [1] Schema ──► [2] Generator ──► [3] Digital twin ──► [4] Human gate ──► [5] Deploy ──► [6] Verify
   (operator)    pydantic        intent → FRR      RIB + Dijkstra       approve / reject    snapshot →    running ==
                 extra=forbid    commands from     loop / conflict /    four-eyes rule      apply per     candidate?
                 policy limits   a config diff     regression checks    drift check         router        twin clean?
                     │               │                  │                    │                   │            │
                  INVALID         INVALID        VALIDATION_FAILED        REJECTED          fail ──────────┴──► [7] ROLLBACK
                                                                                                             restore snapshot
                                                                                                             on ALL routers
```

## Lab topology (topology.yaml)

```
            LAN1 10.0.1.0/24
                 |
                [R1]
       eth1 .1 /    \ eth2 .1
   10.0.12.0/30      10.0.13.0/30
            [R2]------[R3]
         10.0.23.0/30
             |          |
     LAN2 10.0.2.0/24   LAN3 10.0.3.0/24
```

## The two supported intents

| kind | fields | example |
|---|---|---|
| `ospf_link` | `routers: [A, B]`, `action: enable/disable`, `cost` (1–65535), `area: 0`, `advertise_lans` | `intents/01_ospf_r1_r2.yaml` |
| `static_route` | `router`, `destination` (/8–/30), `next_hop_router` (must be a neighbour), `action: add/remove` | `intents/04_static_r1_partner.yaml` |

Operators name **routers**, never IPs or CLI. The generator resolves next-hop IPs and
interfaces from the topology. *(Swap these two for the mentor-defined intents if they differ —
each intent is one schema class + one generator function.)*

## Safety guarantees

* **Strict schema** — unknown fields (e.g. `raw_commands`), malformed prefixes, default routes,
  out-of-range costs and unknown routers are rejected before anything else runs.
* **Command allowlist** — only 7 FRR command shapes can ever reach a device (checked in the
  generator *and* again in the driver).
* **Digital twin** — rebuilds every router's routing table (connected / static / OSPF with
  Dijkstra, administrative distance, longest-prefix match), traces packets hop-by-hop, and blocks:
  `ROUTING_LOOP`, `CONFLICTING_ROUTES`, `OVERLAPS_CONNECTED`, `NEXTHOP_UNREACHABLE`,
  `REACHABILITY_REGRESSION`; warns on `STATIC_OVERRIDES_OSPF`; reports `PATH_CHANGED` / `REACHABILITY_GAINED`.
* **Human gate** — nothing deploys unless `APPROVED`; requester can't approve their own change;
  failed/rejected changes can never be approved/deployed.
* **Drift check** — if the network changed after validation, the change is marked `STALE`.
* **Durable, atomic rollback** — a snapshot of all 3 routers is written to disk before deploying.
  On a device error *or* a failed post-deploy verification, every router is restored and verified.
* **Tamper-evident audit log** — every action is hash-chained in `.netagent/audit.jsonl`.

## Run it

```bash
pip install -r requirements.txt
python3 -m pytest -q tests          # 27 scenarios, writes TEST_RESULTS.md
./demo.sh                           # step-by-step mentor demo (press enter between steps)
```

Manual use:

```bash
python3 -m netagent propose intents/01_ospf_r1_r2.yaml
python3 -m netagent approve CR-0001 --by bob     # or: reject CR-0001 --by bob --reason "..."
python3 -m netagent deploy CR-0001
python3 -m netagent status                       # running configs + LAN reachability
python3 -m netagent fault R3 apply_error         # make the next commit on R3 fail
python3 -m netagent rollback CR-0001 | history | audit | reset
```

## Real routers (containerlab + FRR)

The default driver is a simulated FRR lab (same commands, state persisted as JSON, with fault
injection). To drive real FRR containers instead (Linux + Docker + containerlab):

```bash
sudo containerlab deploy -t lab/ps008.clab.yml
NETAGENT_DRIVER=frr python3 -m netagent status
```

`FrrDockerLab` reads `show running-config` and applies commands via `docker exec … vtysh`.

## Layout

```
netagent/
  schema.py      structured intent schema (pydantic)
  generator.py   intent -> candidate configs -> FRR commands
  config.py      structured router config, FRR command interpreter, allowlist, diffs
  twin.py        digital twin: RIB, OSPF SPF, packet tracing, validation
  agent.py       orchestrator: propose / approve / reject / deploy / verify / rollback
  lab.py         SimulatedLab + FrrDockerLab drivers
  store.py       change requests, snapshots, hash-chained audit log
  cli.py         command-line interface
intents/         example intents (good and bad)
lab/             containerlab topology + FRR configs
tests/           27 test scenarios
```
