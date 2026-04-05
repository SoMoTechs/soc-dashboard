# SomoShield SOC Dashboard

Built by a solo MSP who got tired of paying for tools that don't actually fit how small MSPs work.

I run about 14 clients — city halls, small businesses, a food distributor — and the tools out there are either $500/mo SaaS platforms built for enterprise, or open-source projects that take a full-time engineer to maintain. Neither works when you're one person.

So I built this.

---

## What It Does

Single-pane view of everything that matters for a small MSP:

- **Live agent status** — custom beacon agents checking in from client endpoints
- **Wazuh SIEM** — real alerts, not noise. Dismiss and silence rules that matter
- **CrowdSec** — community threat intel, live ban list, who's hitting your infrastructure
- **MeshCentral** — one-click remote desktop/terminal/files from the agent list. Free for Windows, Linux, Mac
- **Backup monitoring** — Restic per-client, knows if the last backup ran or failed
- **Client health scoring** — green/yellow/red at a glance for each site
- **AI triage** — flags logins that look wrong before you even look at the dashboard
- **Client portal** — token-gated read-only view so clients can see their own security posture
- **2FA + rate limiting** — this thing is exposed to the internet, it's locked down

---

## Stack

- Python / Flask backend
- Self-hosted Wazuh (SIEM/EDR)
- MeshCentral (remote access)
- CrowdSec (IPS)
- Suricata (IDS)
- Restic (backups)
- Docker, Nginx Proxy Manager
- SQLite (client config, credentials stored encrypted)

No cloud dependencies. Runs on a single server.

---

## Why Self-Hosted

Because I don't want my client data sitting in someone else's SaaS. Because I want to control the stack. Because when something breaks at 2am I need to be able to fix it, not wait for a ticket.

Also because it's a fraction of the cost.

---

## Status

Active development. Running in production for my own clients.

Not open source — proprietary. See LICENSE.

---

## Contact

Anthony Gormley  
Somo Technologies LLC — Missouri  
anthony@somotechs.com  
https://somotechs.com
