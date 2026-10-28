# NetOps Copilot

> An AI agent that turns plain-language network change requests into validated, multi-vendor configs, with a deterministic safety gate, a lab dry-run and human approval before anything touches production.

Built for the **Meta Global AI Developer Hackathon** (Indie track, theme: *Build for Your World*), Oct 26 – Nov 4, 2026.

## The problem

In network operations, writing the automation is rarely the bottleneck. The hard part is turning a ticket ("add VLAN 30 on sites A and B", "check ACL compliance") into correct vendor-specific config, then proving it is safe before it reaches production. LLMs can draft configs, but nobody should push LLM output to a router without guarantees.

## How it works

```
change request ──► [1] parse intent ──► [2] generate config ──► [3] safety gate ──► [4] lab dry-run ──► [5] explain + approve ──► push
  (plain text)       Muse Spark          Muse Spark               deterministic        Containerlab         human in the loop
                                              ▲                         │                    │
                                              └──── retry with errors ◄─┴────────────────────┘
```

1. **Parse**: Muse Spark turns the request and current device configs into a structured intent (JSON schema).
2. **Generate**: vendor-specific config (Cisco IOS, Huawei VRP) and an Ansible playbook.
3. **Safety gate**: deterministic, rule-based checks, no LLM involved. Blast radius, forbidden commands, syntax, scope vs intent. Returns `PASS` or `REJECT`.
4. **Dry-run**: the change is applied to a Containerlab replica, with pre/post checks.
5. **Explain + approve**: plain-language diff and risk level, then an explicit human approval.

On failure at step 3 or 4, the agent loops back to step 2 with the errors in context, up to a fixed retry budget.

## Use cases (hackathon scope)

- [x] VLAN provisioning (Cisco IOS + Huawei VRP), end to end
- [x] ACL compliance audit (Cisco IOS + Huawei VRP), read-only
- [ ] QoS policy check

## Demo

```bash
netops-copilot "Create VLAN 30 named users on site-a and site-b"          # real run on Muse Spark
netops-copilot "Create VLAN 30 named users on site-a and site-b" --mock   # offline, no API key
netops-copilot "Create VLAN 30 named users on site-a" --mock-faulty       # shows the retry loop
```

`--mock-faulty` makes the model first propose a change that silently deletes VLAN 20. The dry-run post-checks catch it, the errors go back to the model, and the second attempt is clean:

```
Attempt 1: gate PASS, dry-run FAILED -> FAILED
  site-a (cisco_ios): vlan 30 | name USERS | no vlan 20
  ! site-a: post-check failed, existing VLAN 20 removed

Attempt 2: gate PASS, dry-run OK -> OK
  site-a (cisco_ios): vlan 30 | name USERS
```

### ACL compliance audit

```bash
netops-copilot "Telnet and SMB must be blocked and HTTPS allowed on all edge ACLs" --mock
```

Muse Spark only translates the policy into test flows (`telnet` → `tcp/23 deny`). The verdict comes from a deterministic first-match engine that knows each vendor's default action:

```
ACL audit: NON-COMPLIANT (4 of 9 checks failed)
OK   site-a GigabitEthernet0/0 acl=EDGE-IN telnet (tcp/23): expected deny, actual deny <- 20 deny tcp any any eq telnet
FAIL site-a GigabitEthernet0/0 acl=EDGE-IN smb (tcp/445): expected deny, actual permit <- 40 permit ip any any
FAIL site-b GigabitEthernet0/0/0 acl=3000 telnet (tcp/23): expected deny, actual permit <- no rule matched: Huawei traffic-filter default permit
FAIL core (all) acl=(none) telnet (tcp/23): expected deny, actual permit <- no inbound ACL applied on any interface
...
```

The site-b finding is the kind that slips through manual reviews: Cisco ACLs end with an implicit deny, but a Huawei `traffic-filter` **permits** packets that match no rule. The engine also treats a rule restricted to one host as not blocking the service for everyone, and flags ACLs that are applied but never defined. Exit code is `0` when compliant and `3` when not, so the audit can run in CI.

### Safety layers

The safety layers are independent:

| Layer | Catches | LLM involved |
|---|---|---|
| Intent validation | unknown devices, invalid VLAN id or name | no |
| Safety gate | out-of-scope devices, forbidden commands (`reload`, `no router`, `undo local-user`…), VLAN 1 and reserved ranges | no |
| Dry-run post-checks | wrong-vendor syntax, missing VLAN, existing VLAN removed or renamed, collateral VLANs | no |
| Human approval | everything else | no |

## Current status

- The dry-run currently runs on an **offline config simulator** (`lab/simulator.py`) that applies commands to a model of each device's VLAN table with vendor-specific grammar. A Containerlab-backed runner is the next milestone.
- Nothing is pushed to devices yet: the approval step is the end of the pipeline.

## Stack

- **Models**: Muse Spark (`muse-spark-1.3`) via Meta Model API, OpenAI-compatible endpoint (Muse Spark Open via partner inference, if available)
- **Agent**: Python 3.11+, Pydantic for every LLM output
- **Lab**: Containerlab + FRRouting
- **Automation**: Ansible
- **UI**: TBD

## Quickstart

```bash
git clone https://github.com/gokunguru/netops-copilot.git
cd netops-copilot
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # add your Meta Model API key
pytest                 # 21 tests, no API key needed
```

## Built during the hackathon

Everything in this repository was written during the event (Oct 26 – Nov 4, 2026). The commit history is the record.

**Prior work and third-party resources**, not counted as hackathon work:

- My background in network automation (Ansible/Python on multi-vendor WAN) shaped the problem and use cases. No code or configuration from previous work is reused.

## License

MIT
