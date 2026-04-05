# SomoShield SOC Dashboard — Code Map
**Current size: ~17,000 lines | Goal: 80,000 lines**
Last updated: 2026-04-05

---

## Quick Numbers
| File | Lines | What it is |
|---|---|---|
| `app.py` | 6,084 | The entire backend — all routes, APIs, logic |
| `templates/agents.html` | 2,333 | Agent list page — biggest template |
| `templates/index.html` | 2,272 | Main dashboard (home) |
| `templates/backups.html` | 701 | Backup status page |
| `templates/blocked.html` | 677 | CrowdSec blocked IPs |
| `templates/alerts.html` | 647 | Wazuh alerts feed |
| `templates/clients.html` | 595 | Client management |
| `templates/threatmap.html` | 569 | Live threat map |
| `templates/ids.html` | 531 | Suricata/Zeek IDS |
| `templates/policies.html` | 453 | RMM automation policies |
| `templates/disk.html` | 419 | Disk health |
| `templates/tools.html` | 391 | Sysadmin tools |

---

## app.py — Section Map (line numbers)

### Setup & Config (lines 1–570)
| Lines | What |
|---|---|
| 1–19 | Imports, copyright header |
| 21–29 | Flask app init, WebSocket registry for live agents |
| 35–68 | IP trust/allowlist logic (Cloudflare, Docker, LAN) |
| 69–200 | `subnet_guard()` — blocks outside IPs from dashboard |
| 200–450 | DB init — SQLite tables (clients, policies, alerts, portal tokens, etc.) |
| 450–575 | Crypto helpers — Fernet encryption for client credentials |

### Auth (lines 579–884)
| Lines | What |
|---|---|
| 579 | `POST /login` — bcrypt password check |
| 604 | `GET/POST /mfa` — TOTP 2FA verify |
| 623 | `GET/POST /mfa/setup` — QR code setup |
| 661 | `GET /logout` |
| 700–884 | `login_required` decorator, rate limiting, session management |

### Main Dashboard (lines 885–923)
| Lines | What |
|---|---|
| 885 | `GET /` — renders index.html |
| 890 | `GET /api/data` — main data feed (Wazuh stats, CrowdSec counts, agent counts) |

### CrowdSec (lines 924–1350)
| Lines | What |
|---|---|
| 924 | `GET /api/crowdsec/decisions` — full ban list |
| 953 | `GET /api/crowdsec/live` — live stream of new bans |
| 972 | `POST /api/crowdsec/unblock` — remove a ban |
| 989 | `POST /api/crowdsec/ban` — add a ban manually |
| 1015 | `POST /api/crowdsec/make-permanent` — flag as permanent |
| 1054 | `POST /api/crowdsec/unblock-all` — bulk clear |
| 1336 | `GET /api/crowdsec/search` — search bans by IP |
| 3312 | `GET /api/crowdsec/value` — CrowdSec threat score for an IP |

### Beacon RMM / SomoAgent (lines 1067–1470)
| Lines | What |
|---|---|
| 1067 | `GET /api/status` — server status |
| 1102 | `POST /api/rmm/poll` — agent polls for commands |
| 1122 | `POST /api/rmm/beacon` — agent sends telemetry (CPU, RAM, disk, processes) |
| 1166 | `POST /api/rmm/result` — agent returns command output |
| 1230 | `GET /api/rmm/agents` — list all beacon agents |
| 1252 | `POST /api/rmm/agents/assign-client` — tag agent to client |
| 1279 | `POST /api/rmm/command` — push a command to agent |
| 1310 | `GET /api/rmm/commands/<agent_id>` — pending command queue |
| 1321 | `POST /api/rmm/cancel/<agent_id>` — cancel pending command |
| 1352 | `DELETE /api/rmm/delete/<agent_id>` — remove agent record |
| 1362 | `POST /api/rmm/tool` — run sysadmin tool on agent |
| 1472 | `GET /api/rmm/cmd/<cmd_id>` — check command result |

### Wazuh SIEM (lines 1485–1613)
| Lines | What |
|---|---|
| 1485 | `GET /api/wazuh/geoalerts` — geo-tagged alerts for threat map |
| 1564 | `GET /api/wazuh/logon_events` — login events (AI triage uses this) |
| 1614 | `GET /alerts` — renders alerts.html |
| 1619 | `GET /threatmap` — renders threatmap.html |
| 1624 | `GET /api/wazuh/alerts` — alert feed with filter/search |
| 1690 | `GET /api/wazuh/alert/<doc_id>` — single alert detail |
| 1705 | `GET /api/wazuh/related/<doc_id>` — related alerts (same source IP) |

### Pages (lines 1744–1800)
| Lines | What |
|---|---|
| 1744 | `GET /agents` — renders agents.html |
| 1749 | `GET /policies` — renders policies.html |
| 1754 | `GET /somoagent` — renders somoagent.html (agent install) |
| 1759 | `GET /agent.ps1` — serves live PowerShell install script |
| 1771 | `GET /scripts/<filename>` — serves deploy scripts/binaries |
| 1799 | `GET /api/ticker` — scrolling news ticker data |

### Stats & Onboarding (lines 1903–2246)
| Lines | What |
|---|---|
| 1903 | `GET /api/stats` — dashboard stat cards (alerts, agents, bans, etc.) |
| 2029 | `POST /api/onboard/provision` — provision new client (creates restic repo, creds) |
| 2103 | `POST /api/restic/register` — agent self-registers for backup |
| 2172 | `POST /api/restic/mycreds` — agent fetches its own backup creds |

### Backup / Restic (lines 2247–2618)
| Lines | What |
|---|---|
| 2247 | `GET /backups` — renders backups.html |
| 2252 | `GET /api/restic/clients` — backup status for all clients |
| 2307 | `GET /api/restic/snapshots/<hostname>` — snapshot list |
| 2322 | `DELETE /api/restic/clients/<hostname>` — remove client backup |
| 2344 | `GET /api/restic/ls/<hostname>/<snap_id>` — browse snapshot files |
| 2397 | `POST /api/restic/restore/<hostname>/<snap_id>` — trigger restore |
| 2436 | `GET /api/restic/download/<token>` — download restored file |
| 2460 | `GET/POST /api/backup/extrapaths/<hostname>` — extra backup paths |
| 2489 | `POST /api/backup/trigger/<hostname>` — force backup now |

### AI Features (lines 2620–3170)
| Lines | What |
|---|---|
| 2620 | `GET /api/ai/evaluate` — AI evaluates recent alerts (Claude Haiku) |
| 2715 | `GET /api/wazuh/malware` — malware event feed |
| 2898 | `GET /api/malware/virustotal/<hash>` — VT lookup |
| 2948 | `GET /api/malware/detail/<doc_id>` — full malware event |
| 3011 | `POST /api/malware/dismiss/<doc_id>` — dismiss a malware alert |
| 3026 | `POST /api/malware/silence` — silence rule for X days |
| 3085 | `GET /api/ai/login_investigation` — AI investigates suspicious logins |
| 3173 | `GET/POST /api/agent/check` — agent beacon health check |

### Client Management (lines 3217–3865)
| Lines | What |
|---|---|
| 3217 | `GET /api/health/clients` — per-client health scores |
| 3349 | `POST /api/rmm/isolate/<hostname>` — network isolate endpoint |
| 3384 | `POST /api/rmm/unisolate/<hostname>` — restore network |
| 3476 | `POST /api/av/scan/<hostname>` — trigger AV scan |
| 3508 | `GET /api/av/results` — AV scan results |
| 3584 | `GET/POST /api/clients/meta` — client metadata (name, logo, settings) |
| 3623 | `GET/POST /api/portal/tokens` — manage client portal tokens |
| 3660 | `GET /portal/<token>` — client-facing read-only portal |
| 3683 | `GET /blocked` — renders blocked.html |

### Tools & IDS (lines 3865–4315)
| Lines | What |
|---|---|
| 3865 | `GET /tools` — renders tools.html |
| 3873 | `GET /ids` — renders ids.html |
| 3882 | `GET /api/ids/summary` — Suricata/Zeek alert summary |
| 4063 | `POST /api/ids/block` — block IP from IDS alert |
| 4088 | `GET /api/ids/suppress` — suppression rules |
| 4098 | `POST /api/ids/suppress` — add suppression |
| 4139 | `POST /api/ids/sensor/enroll` — enroll remote IDS sensor |
| 4317 | `POST /api/tools/run` — run sysadmin tool (ping, nslookup, etc.) |
| 4351 | `GET /api/tools/status/<cmd_id>` — tool run result |

### Policies & Automation (lines 4368–5005)
| Lines | What |
|---|---|
| 4368 | `GET /clients` — renders clients.html |
| 4376 | `GET /api/reports/weekly` — weekly security report data |
| 4486 | `POST /api/reports/email` — email report to client |
| 4579 | `POST /api/ai/triage_alert` — AI triage a specific alert |
| 4825 | `GET/POST /api/rmm/policies` — automation policies (cron-like) |
| 4859 | `PUT /api/rmm/policies/<pid>` — update policy |
| 4887 | `POST /api/rmm/policies/<pid>/run-now` — force run policy |

### Advanced RMM (lines 5007–5700)
| Lines | What |
|---|---|
| 5007 | `GET /api/rmm/alerts` — RMM alert feed |
| 5050 | `POST /api/rmm/upload` — upload file to agent |
| 5074 | `GET /api/rmm/file/<token>/<filename>` — download file from agent |
| 5124 | `POST /api/rmm/screenshot/<agent_id>` — take screenshot |
| 5163 | `GET /api/rmm/screenshot/<agent_id>/latest` — get latest screenshot |
| 5397 | `GET /api/rmm/enroll-cmd` — get agent enrollment command |
| 5417 | `GET /api/rmm/ws-agents` — live WebSocket agents |
| 5460 | `POST /api/rmm/ws-cmd/<agent_id>` — send command via WebSocket |

### Disk Health (lines 5699–5854)
| Lines | What |
|---|---|
| 5699 | `GET /disk` — renders disk.html |
| 5705 | `GET /api/disk/health` — SMART data, temps, disk usage |

### Marketing Tracker (lines 5855–5978)
| Lines | What |
|---|---|
| 5855 | `GET /t/<slug>` — tracking link redirect |
| 5875 | `GET /t/<slug>/land` — landing page for tracked link |
| 5895 | `GET /api/tracker/stats` — link click stats |
| 5918 | `POST /api/tracker/conversion` — record conversion |

### MeshCentral & USB (lines 5980–6084)
| Lines | What |
|---|---|
| 5980 | `GET /api/mesh/remote/<hostname>` — get MeshCentral remote URL |
| 5991 | `GET /api/mesh/groups` — list device groups + install commands |
| 6021 | `POST /api/mesh/groups` — create new device group |
| 6062 | `GET /api/usb/status` — USB backup status (for toast) |
| 6073 | `POST /api/usb/clear` — clear USB backup status |

---

## What's Next to Hit 80k Lines

Currently at ~17k. To get to 80k, areas to build out:

| Feature | Est. Lines | What it adds |
|---|---|---|
| Firewalla API integration | +2,000 | Home network alerts in SOC, bidirectional IP blocking |
| Storage/RAID manager panel | +1,500 | mergerfs disk health, SnapRAID sync, swap guidance |
| Full RMM PowerShell policy editor | +3,000 | Write/edit/schedule scripts from browser |
| MeshCentral full embed (remote desktop in SOC) | +2,000 | Iframe remote session inside dashboard |
| Multi-tenant (per-MSP isolation) | +5,000 | Each client sees only their data |
| Billing / MRR tracker | +2,500 | Track what each client owes, invoice gen |
| Patch management panel | +3,000 | Windows Update status per endpoint |
| Hardware inventory | +2,000 | CPU/RAM/disk/model per agent |
| Mobile-responsive UI overhaul | +4,000 | Works on phone/tablet |
| Firewalla rules editor | +2,000 | Push firewall rules from SOC |
| Automated incident response playbooks | +5,000 | Alert → auto-isolate → notify → ticket |
| Helpdesk / ticket integration (Chatwoot) | +3,000 | Create ticket from alert, view open tickets |
| Threat intelligence feeds | +2,000 | IOC matching against live alerts |
| Client report PDF generator | +2,500 | Branded PDF reports for client meetings |

That puts you well past 80k lines.
