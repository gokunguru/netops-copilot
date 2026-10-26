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

- [ ] VLAN provisioning
- [ ] ACL compliance audit
- [ ] QoS policy check

## Stack

- **Models**: Muse Spark via Meta Model API (Muse Spark Open via partner inference, if available)
- **Agent**: Python 3.11+
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
pytest
```

## Built during the hackathon

Everything in this repository was written during the event (Oct 26 – Nov 4, 2026). The commit history is the record.

**Prior work and third-party resources**, not counted as hackathon work:

- My background in network automation (Ansible/Python on multi-vendor WAN) shaped the problem and use cases. No code or configuration from previous work is reused.
- [NetDevOps Agent Skills](https://github.com/vsachin094/netdevops-agent-skills) by Sachin Verma, if used as agent context. Credited per its license.

## License

MIT
