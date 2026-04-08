# SomoTechs SOC Dashboard — Copyright (c) 2024-2026 Somo Technologies LLC. All rights reserved.
# Author: Anthony Gormley | anthony@somotechs.com | https://somotechs.com
# Unauthorized copying, distribution, or use is strictly prohibited.
from flask import Flask, render_template, jsonify, request, redirect, session, url_for, send_from_directory
import requests
import json
import os
import time
import ipaddress
from datetime import datetime
from functools import wraps
import urllib3
import urllib.parse
import sqlite3
import hashlib
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
from flask_sock import Sock
urllib3.disable_warnings()

app = Flask(__name__)
sock = Sock(app)

# ── SomoAgent WebSocket registry ──────────────────────────────────────────────
# Maps agent_id → {'ws': <websocket>, 'hostname': str, 'connected_at': str}
_ws_agents = {}           # agent_id -> {ws, hostname, connected_at, last_seen, telemetry}
_ws_agents_ghost = {}     # agent_id -> {hostname, connected_at, last_seen, telemetry, disconnected_at}
_WS_GHOST_TTL = 120       # seconds to keep disconnected agents visible as "reconnecting"
_ws_agents_lock = __import__('threading').Lock()

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.svg', mimetype='image/svg+xml')

_TRUSTED_PROXY_NETS = [
    ipaddress.ip_network('172.16.0.0/12'),  # Docker bridge networks
    ipaddress.ip_network('127.0.0.0/8'),
]
# Cloudflare IPv4 ranges (used to validate CF-Connecting-IP is trustworthy)
_CF_NETS = [
    ipaddress.ip_network('103.21.244.0/22'),
    ipaddress.ip_network('103.22.200.0/22'),
    ipaddress.ip_network('103.31.4.0/22'),
    ipaddress.ip_network('104.16.0.0/13'),
    ipaddress.ip_network('104.24.0.0/14'),
    ipaddress.ip_network('108.162.192.0/18'),
    ipaddress.ip_network('131.0.72.0/22'),
    ipaddress.ip_network('141.101.64.0/18'),
    ipaddress.ip_network('162.158.0.0/15'),
    ipaddress.ip_network('172.64.0.0/13'),
    ipaddress.ip_network('173.245.48.0/20'),
    ipaddress.ip_network('188.114.96.0/20'),
    ipaddress.ip_network('190.93.240.0/20'),
    ipaddress.ip_network('197.234.240.0/22'),
    ipaddress.ip_network('198.41.128.0/17'),
]

# Parse optional extra allowed IPs (e.g. home public IP) from env
# ALLOWED_IPS=1.2.3.4,5.6.7.8
_extra_allowed = set()
for _ip in os.environ.get('ALLOWED_IPS', '').split(','):
    _ip = _ip.strip()
    if _ip:
        try:
            _extra_allowed.add(ipaddress.ip_address(_ip))
        except ValueError:
            pass

@app.before_request
def subnet_guard():
    """Block dashboard access from outside the allowed subnet/IPs. Exempt agent endpoints."""
    if ALLOWED_SUBNET is None:
        return
    path = request.path
    if path in _SUBNET_EXEMPT or path.startswith('/scripts/') or path.startswith('/static/scripts/') or path.startswith('/portal/') or path.startswith('/ws/'):
        return

    # Allow read-only API calls that carry a valid portal token (for client-facing portal page)
    _PORTAL_API_PATHS = {'/api/health/clients', '/api/reports/weekly', '/api/crowdsec/value'}
    if path in _PORTAL_API_PATHS:
        portal_token = (request.args.get('pt') or '').strip()
        if portal_token:
            try:
                _conn = db_conn()
                _row = _conn.execute("SELECT token FROM portal_tokens WHERE token=?", (portal_token,)).fetchone()
                _conn.close()
                if _row:
                    return  # valid portal token — allow
            except Exception:
                pass

    # Determine real client IP — handle Cloudflare, NPM, and direct connections
    try:
        remote_ip = ipaddress.ip_address(request.remote_addr or '0.0.0.0')
    except ValueError:
        return ('Bad request', 400, {'Content-Type': 'text/plain'})

    from_cf = any(remote_ip in net for net in _CF_NETS)
    from_proxy = any(remote_ip in net for net in _TRUSTED_PROXY_NETS)

    if from_cf:
        # Cloudflare is proxying — CF-Connecting-IP is the real client IP
        real_ip_str = request.headers.get('Cf-Connecting-Ip', '')
    elif from_proxy:
        # NPM/Docker internal — trust X-Forwarded-For
        real_ip_str = (
            (request.headers.get('X-Forwarded-For') or '').split(',')[0].strip() or
            request.headers.get('X-Real-Ip', '')
        )
    else:
        real_ip_str = str(remote_ip)

    if not real_ip_str:
        return  # internal traffic with no identifiable source IP, allow

    try:
        real_ip = ipaddress.ip_address(real_ip_str)
    except ValueError:
        return ('Bad request', 400, {'Content-Type': 'text/plain'})

    # Allow if in local subnet, explicitly allowed IPs, or Docker-internal
    if (real_ip in ALLOWED_SUBNET or
            real_ip in _extra_allowed or
            any(real_ip in net for net in _TRUSTED_PROXY_NETS)):
        return

    return render_template('banned.html'), 403

@app.after_request
def no_cache_api(response):
    """Prevent CloudFlare / browsers from caching any /api/* response."""
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    # Security headers on every response
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    if request.headers.get('X-Forwarded-Proto') == 'https':
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response
_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    raise RuntimeError('SECRET_KEY environment variable is required')
app.secret_key = _secret_key
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=43200,  # 12 hours
)

DB_PATH = '/app/data/agents.db'

def init_db():
    Path('/app/data').mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        hostname TEXT,
        ip TEXT,
        os TEXT,
        cpu REAL,
        ram REAL,
        disk REAL,
        uptime TEXT,
        logged_user TEXT,
        last_seen TEXT,
        first_seen TEXT,
        version TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT,
        command TEXT,
        status TEXT DEFAULT 'pending',
        output TEXT,
        created TEXT,
        completed TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS restic_clients (
        hostname TEXT PRIMARY KEY,
        rest_password_enc TEXT NOT NULL,
        repo_password_enc TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )''')
    conn.commit()
    for col in ['cmd_type TEXT', 'client TEXT']:
        try:
            conn.execute(f'ALTER TABLE agents ADD COLUMN {col}')
            conn.commit()
        except:
            pass
    try:
        conn.execute('ALTER TABLE commands ADD COLUMN cmd_type TEXT')
        conn.commit()
    except:
        pass
    try:
        conn.execute('ALTER TABLE restic_clients ADD COLUMN extra_paths TEXT DEFAULT ""')
        conn.commit()
    except:
        pass
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
            ip TEXT NOT NULL, ts REAL NOT NULL
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_rl_ip_ts ON rate_limits(ip, ts)')
        conn.commit()
    except:
        pass
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS dismissed_alerts (
            doc_id TEXT PRIMARY KEY,
            dismissed_at TEXT DEFAULT (datetime('now')),
            note TEXT
        )''')
        conn.commit()
    except:
        pass
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS silenced_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            host TEXT,
            expires_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            note TEXT
        )''')
        conn.commit()
    except:
        pass
    # ── New RMM tables ────────────────────────────────────────────────────────
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            command TEXT NOT NULL,
            schedule TEXT NOT NULL DEFAULT 'on_checkin',
            target_type TEXT NOT NULL DEFAULT 'all',
            target_value TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            run_count INTEGER DEFAULT 0,
            created TEXT DEFAULT (datetime('now')),
            note TEXT
        )''')
        conn.commit()
    except:
        pass
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS policy_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER,
            agent_id TEXT,
            hostname TEXT,
            cmd_id INTEGER,
            started TEXT DEFAULT (datetime('now')),
            status TEXT DEFAULT 'queued'
        )''')
        conn.commit()
    except:
        pass
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS rmm_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            hostname TEXT,
            client TEXT DEFAULT '',
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT DEFAULT 'warning',
            created TEXT DEFAULT (datetime('now')),
            acknowledged INTEGER DEFAULT 0,
            acknowledged_at TEXT,
            acknowledged_by TEXT
        )''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_rmm_alerts_agent ON rmm_alerts(agent_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_rmm_alerts_ack ON rmm_alerts(acknowledged)')
        conn.commit()
    except:
        pass
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS agent_files (
            token TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            path TEXT NOT NULL,
            size INTEGER DEFAULT 0,
            created TEXT DEFAULT (datetime('now')),
            expires TEXT,
            downloaded INTEGER DEFAULT 0
        )''')
        conn.commit()
    except:
        pass
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS agent_screenshots (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            image_b64 TEXT,
            taken_at TEXT
        )''')
        conn.commit()
    except:
        pass
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS ids_suppress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL CHECK(type IN ('ip','rule')),
            value TEXT NOT NULL,
            note TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(type, value)
        )''')
        conn.commit()
    except:
        pass
    # ── Extra hardware columns on agents ─────────────────────────────────────
    for col in [
        'model TEXT', 'manufacturer TEXT', 'serial TEXT',
        'ram_gb REAL', 'cpu_model TEXT', 'domain TEXT',
        'win_build TEXT', 'disk_model TEXT', 'bios TEXT',
        'alert_level TEXT DEFAULT ""',
    ]:
        try:
            conn.execute(f'ALTER TABLE agents ADD COLUMN {col}')
            conn.commit()
        except:
            pass
    # ── SMS Chat tables ───────────────────────────────────────────────────────
    conn.execute('''CREATE TABLE IF NOT EXISTS sms_messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        direction   TEXT NOT NULL,
        from_num    TEXT NOT NULL,
        to_num      TEXT NOT NULL,
        body        TEXT NOT NULL,
        contact_name TEXT DEFAULT "",
        client      TEXT DEFAULT "",
        status      TEXT DEFAULT "received",
        read        INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS sms_contacts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        phone       TEXT NOT NULL UNIQUE,
        name        TEXT NOT NULL,
        client      TEXT DEFAULT "",
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    # ── Billing / PSA tables ──────────────────────────────────────────────────
    conn.execute('''CREATE TABLE IF NOT EXISTS client_rates (
        client      TEXT PRIMARY KEY,
        hourly_rate REAL DEFAULT 125.0,
        monthly_fee REAL DEFAULT 0.0,
        per_seat    REAL DEFAULT 0.0,
        currency    TEXT DEFAULT "USD",
        notes       TEXT DEFAULT ""
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS time_entries (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        client      TEXT NOT NULL,
        date        TEXT NOT NULL,
        description TEXT NOT NULL,
        hours       REAL NOT NULL,
        rate        REAL NOT NULL,
        billable    INTEGER DEFAULT 1,
        invoiced    INTEGER DEFAULT 0,
        invoice_id  TEXT DEFAULT "",
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS invoices (
        id          TEXT PRIMARY KEY,
        client      TEXT NOT NULL,
        issued_date TEXT NOT NULL,
        due_date    TEXT NOT NULL,
        subtotal    REAL NOT NULL,
        tax_rate    REAL DEFAULT 0.0,
        total       REAL NOT NULL,
        status      TEXT DEFAULT "draft",
        notes       TEXT DEFAULT "",
        pdf_path    TEXT DEFAULT "",
        emailed_at  TEXT DEFAULT "",
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    # ── Client Email Automation tables ────────────────────────────────────────
    conn.execute('''CREATE TABLE IF NOT EXISTS client_contacts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        client      TEXT NOT NULL,
        name        TEXT NOT NULL,
        email       TEXT NOT NULL UNIQUE,
        subscribed  INTEGER DEFAULT 1,
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS email_templates (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        subject     TEXT NOT NULL,
        body_html   TEXT NOT NULL,
        body_text   TEXT NOT NULL,
        category    TEXT DEFAULT "general",
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS email_sequences (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        description TEXT DEFAULT "",
        active      INTEGER DEFAULT 1,
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS email_sequence_steps (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        sequence_id INTEGER NOT NULL,
        step_order  INTEGER NOT NULL,
        delay_days  INTEGER DEFAULT 0,
        template_id INTEGER NOT NULL,
        subject_override TEXT DEFAULT ""
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS email_queue (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        contact_id   INTEGER NOT NULL,
        template_id  INTEGER NOT NULL,
        subject      TEXT NOT NULL,
        scheduled_at TEXT NOT NULL,
        sent_at      TEXT DEFAULT "",
        status       TEXT DEFAULT "pending",
        sequence_id  INTEGER DEFAULT 0,
        step_id      INTEGER DEFAULT 0
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS email_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        contact_id  INTEGER NOT NULL,
        email       TEXT NOT NULL,
        subject     TEXT NOT NULL,
        sent_at     TEXT DEFAULT CURRENT_TIMESTAMP,
        status      TEXT DEFAULT "sent",
        error       TEXT DEFAULT ""
    )''')
    conn.commit()
    # Seed default templates if empty
    count = conn.execute('SELECT COUNT(*) FROM email_templates').fetchone()[0]
    if count == 0:
        _seed_email_templates(conn)
    conn.close()

def _seed_email_templates(conn):
    templates = [
        ("Welcome to Somo Technologies", "Welcome to Somo Technologies — We've Got You Covered",
         """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1f2937;">
<div style="background:#1D6FFF;padding:24px;border-radius:8px 8px 0 0;">
  <h1 style="color:white;margin:0;font-size:22px;">Welcome to Somo Technologies</h1>
  <p style="color:#bfdbfe;margin:6px 0 0;">Your IT security is in good hands.</p>
</div>
<div style="background:#f9fafb;padding:24px;border-radius:0 0 8px 8px;border:1px solid #e5e7eb;">
  <p>Hi {contact_name},</p>
  <p>Welcome aboard! I'm Anthony from Somo Technologies. I'm your dedicated IT partner and I take that seriously — especially when it comes to keeping your business safe.</p>
  <p>Here's what's running in the background protecting you right now:</p>
  <ul>
    <li>🛡️ <b>24/7 threat monitoring</b> — we watch for attacks so you don't have to</li>
    <li>💾 <b>Automated backups</b> — your data is protected and recoverable</li>
    <li>🔒 <b>Endpoint security</b> — every device is monitored for threats</li>
    <li>🚨 <b>Intrusion detection</b> — we block malicious IPs before they reach you</li>
  </ul>
  <p>You'll hear from me regularly with updates on your security posture. If you ever have questions or anything feels off — just reply to this email.</p>
  <p style="margin-top:24px;">— Anthony Gormley<br><b>Somo Technologies LLC</b><br>(417) 390-5129 | anthony@somotechs.com</p>
</div></div>""",
         "Hi {contact_name},\n\nWelcome to Somo Technologies! I'm Anthony, your dedicated IT partner.\n\nHere's what's protecting you right now:\n- 24/7 threat monitoring\n- Automated backups\n- Endpoint security\n- Intrusion detection\n\nQuestions? Just reply.\n\n— Anthony Gormley\nSomo Technologies LLC\n(417) 390-5129", "onboarding"),

        ("Security Tip: Strong Passwords", "⚠️ The #1 Way Hackers Get In — And How to Stop Them",
         """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1f2937;">
<div style="background:#dc2626;padding:24px;border-radius:8px 8px 0 0;">
  <h1 style="color:white;margin:0;font-size:20px;">⚠️ Security Alert: Password Safety</h1>
</div>
<div style="background:#f9fafb;padding:24px;border-radius:0 0 8px 8px;border:1px solid #e5e7eb;">
  <p>Hi {contact_name},</p>
  <p>Did you know that <b>81% of data breaches</b> are caused by weak or stolen passwords? It's the #1 way attackers get into business systems — and it's 100% preventable.</p>
  <h3 style="color:#dc2626;">What a good password looks like:</h3>
  <ul>
    <li>At least <b>14 characters</b></li>
    <li>Mix of letters, numbers, symbols</li>
    <li><b>Never reused</b> across sites</li>
    <li>Not your name, birthday, or company name</li>
  </ul>
  <h3 style="color:#1D6FFF;">Our recommendation: Use a Password Manager</h3>
  <p>Bitwarden (free), 1Password, or Dashlane. One strong master password, everything else is auto-generated and unique. We can help you set this up for your whole team.</p>
  <p style="background:#fef3c7;padding:12px;border-radius:6px;border-left:3px solid #f59e0b;"><b>Quick action:</b> If you're reusing any password, change it today. Reply to this email and I'll help you get set up with a password manager — no charge.</p>
  <p style="margin-top:24px;">— Anthony<br><b>Somo Technologies LLC</b></p>
</div></div>""",
         "Hi {contact_name},\n\n81% of breaches come from weak or reused passwords.\n\nWhat makes a good password:\n- 14+ characters\n- Mix of letters, numbers, symbols  \n- Never reused\n\nOur recommendation: Use Bitwarden (free password manager). I can help you set it up — just reply.\n\n— Anthony\nSomo Technologies LLC", "security_tip"),

        ("Security Tip: Phishing Awareness", "🎣 How to Spot a Phishing Email Before It's Too Late",
         """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1f2937;">
<div style="background:#7c3aed;padding:24px;border-radius:8px 8px 0 0;">
  <h1 style="color:white;margin:0;font-size:20px;">🎣 Phishing: The Trap Most People Fall For</h1>
</div>
<div style="background:#f9fafb;padding:24px;border-radius:0 0 8px 8px;border:1px solid #e5e7eb;">
  <p>Hi {contact_name},</p>
  <p>Phishing emails are the #1 way ransomware gets deployed. They look real. They're designed to trick even smart people. Here's how to spot them:</p>
  <h3>🚩 Red flags in any email:</h3>
  <ul>
    <li><b>Urgency:</b> "Act now or your account will be closed!"</li>
    <li><b>Weird sender:</b> support@amaz0n-security.net (not amazon.com)</li>
    <li><b>Hover before you click:</b> the link URL doesn't match what it says</li>
    <li><b>Attachments you didn't expect</b> — even from people you know</li>
    <li><b>Requests for passwords or wire transfers</b> — never legitimate</li>
  </ul>
  <p style="background:#fef2f2;padding:12px;border-radius:6px;border-left:3px solid #dc2626;"><b>Rule of thumb:</b> When in doubt, don't click. Pick up the phone and call the sender directly using a number you already know.</p>
  <p>Forward any suspicious emails to me before you click anything — I'll check it for free.</p>
  <p style="margin-top:24px;">— Anthony<br><b>Somo Technologies LLC</b></p>
</div></div>""",
         "Hi {contact_name},\n\nPhishing emails are the #1 way ransomware gets in.\n\nRed flags:\n- Urgency (act now!)\n- Weird sender addresses\n- Links that don't match what they say\n- Unexpected attachments\n- Requests for passwords or wire transfers\n\nRule: When in doubt, don't click. Call me first.\n\n— Anthony\nSomo Technologies LLC", "security_tip"),

        ("Monthly Security Summary", "📊 Your {month} Security Report — {client}",
         """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1f2937;">
<div style="background:#0f172a;padding:24px;border-radius:8px 8px 0 0;">
  <h1 style="color:white;margin:0;font-size:20px;">📊 Monthly Security Report</h1>
  <p style="color:#94a3b8;margin:4px 0 0;">{month} — {client}</p>
</div>
<div style="background:#f9fafb;padding:24px;border-radius:0 0 8px 8px;border:1px solid #e5e7eb;">
  <p>Hi {contact_name},</p>
  <p>Here's what Somo Technologies monitored and blocked for your business last month:</p>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:16px 0;">
    <div style="background:white;padding:16px;border-radius:6px;border:1px solid #e5e7eb;text-align:center;">
      <div style="font-size:28px;font-weight:700;color:#1D6FFF;">{threats_blocked}</div>
      <div style="font-size:12px;color:#6b7280;">Threats Blocked</div>
    </div>
    <div style="background:white;padding:16px;border-radius:6px;border:1px solid #e5e7eb;text-align:center;">
      <div style="font-size:28px;font-weight:700;color:#10b981;">{backups_ok}</div>
      <div style="font-size:12px;color:#6b7280;">Backups Completed</div>
    </div>
  </div>
  <p>Your systems remained secure throughout the month. All endpoints checked in as healthy and backups completed successfully.</p>
  <p>Questions about your security posture? Just reply — I'm always available.</p>
  <p style="margin-top:24px;">— Anthony<br><b>Somo Technologies LLC</b><br>(417) 390-5129</p>
</div></div>""",
         "Hi {contact_name},\n\nYour {month} security report for {client}:\n\n- Threats blocked: {threats_blocked}\n- Backups completed: {backups_ok}\n\nAll systems healthy. Questions? Just reply.\n\n— Anthony\nSomo Technologies LLC", "monthly"),

        ("Security Tip: Backup Strategy", "💾 What Happens to Your Business if Your Computer Dies Tomorrow?",
         """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1f2937;">
<div style="background:#059669;padding:24px;border-radius:8px 8px 0 0;">
  <h1 style="color:white;margin:0;font-size:20px;">💾 Your Business Data: Are You Protected?</h1>
</div>
<div style="background:#f9fafb;padding:24px;border-radius:0 0 8px 8px;border:1px solid #e5e7eb;">
  <p>Hi {contact_name},</p>
  <p>60% of small businesses that suffer a major data loss <b>shut down within 6 months</b>. Hard drives fail. Ransomware encrypts files. Laptops get stolen.</p>
  <p>The question isn't IF something will happen — it's WHEN. And when it does, the only thing standing between you and catastrophe is your backup.</p>
  <h3 style="color:#059669;">The 3-2-1 Backup Rule:</h3>
  <ul>
    <li><b>3</b> copies of your data</li>
    <li><b>2</b> different storage types (local + cloud)</li>
    <li><b>1</b> offsite copy (so a fire/flood doesn't wipe everything)</li>
  </ul>
  <p style="background:#ecfdf5;padding:12px;border-radius:6px;border-left:3px solid #059669;"><b>Good news:</b> We already have automated backups running for your systems. Want a report of your last backup status? Reply and I'll send it over.</p>
  <p style="margin-top:24px;">— Anthony<br><b>Somo Technologies LLC</b></p>
</div></div>""",
         "Hi {contact_name},\n\n60% of businesses that lose data shut down within 6 months.\n\nThe 3-2-1 backup rule:\n- 3 copies of data\n- 2 different storage types\n- 1 offsite\n\nWe have automated backups running for you. Want a status report? Just reply.\n\n— Anthony\nSomo Technologies LLC", "security_tip"),

        ("Security Tip: Multi-Factor Authentication", "🔐 One Simple Step That Blocks 99% of Account Hacks",
         """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1f2937;">
<div style="background:#1D6FFF;padding:24px;border-radius:8px 8px 0 0;">
  <h1 style="color:white;margin:0;font-size:20px;">🔐 Turn On This Setting Right Now</h1>
</div>
<div style="background:#f9fafb;padding:24px;border-radius:0 0 8px 8px;border:1px solid #e5e7eb;">
  <p>Hi {contact_name},</p>
  <p>Microsoft says that enabling Multi-Factor Authentication (MFA) blocks <b>99.9% of automated account attacks</b>. That's not a typo.</p>
  <p>MFA means even if someone steals your password, they still can't get in without your phone.</p>
  <h3>Enable it on these first:</h3>
  <ol>
    <li><b>Email</b> (Microsoft 365 / Gmail) — most critical</li>
    <li><b>Banking</b> — non-negotiable</li>
    <li><b>Any cloud software</b> your business uses</li>
    <li><b>Social media</b> accounts</li>
  </ol>
  <p>Use Microsoft Authenticator or Google Authenticator (free apps).</p>
  <p style="background:#eff6ff;padding:12px;border-radius:6px;border-left:3px solid #1D6FFF;"><b>We can enable this for your whole team remotely.</b> Reply and we'll schedule a 15-minute setup — at no charge for existing clients.</p>
  <p style="margin-top:24px;">— Anthony<br><b>Somo Technologies LLC</b></p>
</div></div>""",
         "Hi {contact_name},\n\nMFA blocks 99.9% of automated account attacks.\n\nTurn it on for:\n1. Email (Microsoft 365/Gmail)\n2. Banking\n3. Any cloud software\n4. Social media\n\nUse Microsoft Authenticator (free). We can set this up for your whole team remotely — reply to schedule.\n\n— Anthony\nSomo Technologies LLC", "security_tip"),
    ]
    conn.executemany(
        'INSERT INTO email_templates (name,subject,body_html,body_text,category) VALUES (?,?,?,?,?)',
        templates)
    # Create default welcome sequence
    conn.execute("INSERT INTO email_sequences (id,name,description) VALUES (1,'Welcome Sequence','Automatic sequence for new clients')")
    # Steps: welcome day 0, password tip day 3, phishing day 7, backup day 14, MFA day 21
    steps = [(1,1,0,1,''),(1,2,3,2,''),(1,3,7,3,''),(1,4,14,5,''),(1,5,21,6,'')]
    conn.executemany('INSERT INTO email_sequence_steps (sequence_id,step_order,delay_days,template_id,subject_override) VALUES (?,?,?,?,?)', steps)
    conn.commit()

init_db()

def _require_env(name):
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f'{name} environment variable is required')
    return val

AGENT_SECRET     = _require_env('AGENT_SECRET')
DASHBOARD_USER   = _require_env('DASHBOARD_USER')
DASHBOARD_PASS   = _require_env('DASHBOARD_PASS')
WAZUH_URL        = _require_env('WAZUH_URL')
WAZUH_USER       = _require_env('WAZUH_USER')
WAZUH_PASS       = _require_env('WAZUH_PASS')
WAZUH_API_URL    = _require_env('WAZUH_API_URL')
WAZUH_API_USER   = _require_env('WAZUH_API_USER')
WAZUH_API_PASS   = _require_env('WAZUH_API_PASS')
NETDATA_URL      = _require_env('NETDATA_URL')
CROWDSEC_URL     = _require_env('CROWDSEC_URL')

# Wazuh uses an internal self-signed CA (/etc/wazuh-indexer/certs/root-ca.pem).
# Copy that file to secrets/wazuh-ca.pem and it will be used automatically.
# Until then, falls back to False (verify disabled) only for these internal loopback calls.
_wazuh_ca    = '/app/secrets/wazuh-ca.pem'
WAZUH_CA     = _wazuh_ca if os.path.exists(_wazuh_ca) else False
WAZUH_API_CA = WAZUH_CA
CROWDSEC_API_KEY = _require_env('CROWDSEC_API_KEY')

# Optional email config (SMTP_HOST required to enable; uses helpdesk@somotechs.com)
SMTP_HOST  = os.environ.get('SMTP_HOST', '')
SMTP_PORT  = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER  = os.environ.get('SMTP_USER', '')
SMTP_PASS  = os.environ.get('SMTP_PASS', '')
SMTP_FROM  = os.environ.get('SMTP_FROM', 'helpdesk@somotechs.com')
SMTP_TO    = os.environ.get('SMTP_TO',   'helpdesk@somotechs.com')

# ── Telnyx SMS notifications ──────────────────────────────────────────────────
TELNYX_API_KEY  = os.environ.get('TELNYX_API_KEY',  '')   # API v2 key from telnyx.com
TELNYX_FROM     = os.environ.get('TELNYX_FROM',     '')   # +1XXXXXXXXXX your Telnyx number
TELNYX_TO       = os.environ.get('TELNYX_TO',       '')   # +1XXXXXXXXXX your cell

def _send_sms(body):
    """Fire-and-forget SMS via Telnyx REST API."""
    if not (TELNYX_API_KEY and TELNYX_FROM and TELNYX_TO):
        return
    import threading
    def _send():
        try:
            requests.post(
                'https://api.telnyx.com/v2/messages',
                headers={
                    'Authorization': f'Bearer {TELNYX_API_KEY}',
                    'Content-Type':  'application/json',
                },
                json={
                    'from': TELNYX_FROM,
                    'to':   TELNYX_TO,
                    'text': body[:160],   # standard SMS limit
                },
                timeout=8
            )
        except Exception as e:
            app.logger.warning(f'SMS failed: {e}')
    threading.Thread(target=_send, daemon=True).start()

def _send_email_notify(subject, body, attach_path=None, html=None):
    """Send a notification email to SMTP_TO. Non-blocking.
    If html= is provided, sends a multipart email with both HTML and plain-text fallback.
    If html= is None but body looks like HTML, it's sent as HTML automatically."""
    if not SMTP_HOST:
        return
    import threading, smtplib, ssl, re as _re
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText as _MIMEText
    # Auto-detect HTML if not explicitly specified
    if html is None:
        html = bool(_re.search(r'<[a-zA-Z]', body))
    def _send():
        try:
            msg = MIMEMultipart('alternative') if html else MIMEMultipart()
            msg['Subject'] = subject
            msg['From']    = SMTP_FROM
            msg['To']      = SMTP_TO
            if html:
                plain = _re.sub(r'<[^>]+>', '', body).strip()
                msg.attach(_MIMEText(plain, 'plain'))
                msg.attach(_MIMEText(body, 'html'))
            else:
                msg.attach(_MIMEText(body, 'plain'))
            ctx = ssl.create_default_context()
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls(context=ctx)
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_FROM, SMTP_TO, msg.as_string())
        except Exception as e:
            app.logger.warning(f'Email notify failed: {e}')
    threading.Thread(target=_send, daemon=True).start()

def _notify(subject, body, sms=None):
    """Send both email + SMS. sms= short version for text, defaults to first 155 chars."""
    _send_email_notify(subject, body)
    _send_sms(sms or (subject + ' — ' + body[:100]))

def _notify_login(ip):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    _notify(
        f'🔑 SOC Login — {ip}',
        f'Successful login to SomoShield SOC.\n\nIP: {ip}\nTime: {now}\n\nIf this was not you, change your password immediately.\n\n-- Somo Technologies',
        sms=f'SomoShield: Login from {ip} at {now}'
    )

# ─── CrowdSec geo cache ────────────────────────────────────────────────────────
_crowdsec_geo_cache = {'points': None, 'ts': 0}
_CROWDSEC_GEO_TTL = 900  # 15 minutes

def _get_crowdsec_geopoints():
    """Fetch CrowdSec banned IPs, geolocate via ip-api.com, cache 15 min."""
    global _crowdsec_geo_cache
    now = time.time()
    if _crowdsec_geo_cache['points'] is not None and now - _crowdsec_geo_cache['ts'] < _CROWDSEC_GEO_TTL:
        return _crowdsec_geo_cache['points']
    try:
        # Try active decisions first; fall back to recent alerts if empty
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions?type=ban&limit=500",
                         headers={'X-Api-Key': CROWDSEC_API_KEY}, timeout=5)
        decisions = r.json() if r.status_code == 200 else None
        if not decisions:
            # No active bans — pull from alerts history instead
            ra = requests.get(f"{CROWDSEC_URL}/v1/alerts?limit=500",
                              headers={'X-Api-Key': CROWDSEC_API_KEY}, timeout=5)
            alerts = ra.json() if ra.status_code == 200 else []
            decisions = []
            for alert in (alerts or []):
                for dec in (alert.get('decisions') or []):
                    dec['scenario'] = alert.get('scenario', dec.get('scenario', ''))
                    decisions.append(dec)
        decisions = decisions or []
        seen = {}
        for d in decisions:
            ip = d.get('value', '')
            if ip and d.get('scope', 'Ip') == 'Ip' and ip not in seen:
                seen[ip] = d
        ips = list(seen.keys())[:150]
        if not ips:
            return []
        points = []
        for i in range(0, len(ips), 100):
            batch = ips[i:i+100]
            geo_r = requests.post('http://ip-api.com/batch',
                json=[{'query': ip, 'fields': 'query,country,regionName,lat,lon,status'} for ip in batch],
                timeout=10)
            if geo_r.status_code != 200:
                continue
            for geo in geo_r.json():
                if geo.get('status') != 'success':
                    continue
                ip = geo['query']
                dec = seen.get(ip, {})
                scenario = dec.get('scenario', 'unknown')
                if 'bruteforce' in scenario:
                    level = 10
                elif 'dos' in scenario:
                    level = 8
                elif 'scan' in scenario:
                    level = 6
                else:
                    level = 5
                points.append({
                    'ip':      ip,
                    'lat':     geo['lat'],
                    'lon':     geo['lon'],
                    'country': geo.get('country', '?'),
                    'region':  geo.get('regionName', ''),
                    'count':   1,
                    'level':   level,
                    'rule':    f"CrowdSec blocked: {scenario}",
                    'agent':   'crowdsec',
                    'time':    '',
                    'us':      geo.get('country', '') == 'United States',
                })
        _crowdsec_geo_cache = {'points': points, 'ts': now}
        return points
    except Exception:
        return []

TRMM_API_URL       = os.environ.get('TRMM_API_URL',  'https://api.somotechs.com')
TRMM_API_TOKEN     = os.environ.get('TRMM_API_TOKEN', '')
ANTHROPIC_API_KEY  = os.environ.get('ANTHROPIC_API_KEY', '')

# Action1 RMM (cloud)
ACTION1_CLIENT_ID     = os.environ.get('ACTION1_CLIENT_ID', '')
ACTION1_CLIENT_SECRET = os.environ.get('ACTION1_CLIENT_SECRET', '')
ACTION1_ORG_ID        = os.environ.get('ACTION1_ORG_ID', '')  # blank = all orgs
_A1_BASE              = 'https://app.action1.com/api/3.0'
_a1_token_cache       = {'token': None, 'expires': 0}

def _a1_token():
    """Return a valid Action1 OAuth2 bearer token (cached)."""
    now = time.time()
    if _a1_token_cache['token'] and now < _a1_token_cache['expires'] - 30:
        return _a1_token_cache['token']
    if not ACTION1_CLIENT_ID or not ACTION1_CLIENT_SECRET:
        return None
    try:
        r = requests.post(
            'https://app.action1.com/api/3.0/oauth2/token',
            data={'grant_type': 'client_credentials',
                  'client_id': ACTION1_CLIENT_ID,
                  'client_secret': ACTION1_CLIENT_SECRET},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            _a1_token_cache['token']   = data.get('access_token')
            _a1_token_cache['expires'] = now + data.get('expires_in', 3600)
            return _a1_token_cache['token']
    except Exception as e:
        app.logger.error(f'Action1 token error: {e}')
    return None

def _a1_orgs():
    """Return list of Action1 org dicts, filtered by ACTION1_ORG_ID if set."""
    tok = _a1_token()
    if not tok:
        return []
    try:
        r = requests.get(f'{_A1_BASE}/organizations',
                         headers={'Authorization': f'Bearer {tok}'}, timeout=10)
        if r.status_code != 200:
            return []
        body = r.json()
        # API returns {"items": [...], "type": "ResultPage", ...}
        orgs = body.get('items', body) if isinstance(body, dict) else body
        if ACTION1_ORG_ID:
            orgs = [o for o in orgs if o.get('id') == ACTION1_ORG_ID]
        return orgs
    except Exception as e:
        app.logger.error(f'Action1 orgs error: {e}')
        return []

# Subnet lockdown — only these CIDRs can access the dashboard UI
_raw_subnet = os.environ.get('ALLOWED_SUBNET', '10.10.0.0/24')
try:
    ALLOWED_SUBNET = ipaddress.ip_network(_raw_subnet, strict=False)
except ValueError:
    ALLOWED_SUBNET = None

# Agent-facing endpoints exempt from subnet check (phones home from client sites)
_SUBNET_EXEMPT = {
    '/api/rmm/poll', '/api/rmm/beacon', '/api/rmm/result',
    '/api/restic/register', '/api/restic/mycreds',
    '/api/onboard/provision', '/api/agent/check',
    '/agent.ps1',
    '/api/sms/inbound',  # Telnyx webhook — comes from Telnyx servers, not LAN
    '/api/support/request',  # clients submit support requests from outside LAN
}

# In-memory cache for AI evaluation (avoid hammering the API)
_ai_eval_cache = {'ts': 0, 'data': None}
_AI_CACHE_TTL  = 180  # 3 minutes

# Simple in-memory rate limiter for agent endpoints
import collections
_rl_lock   = __import__('threading').Lock()
_rl_counts = collections.defaultdict(list)  # key -> [timestamps]
_RL_WINDOW = 60    # seconds
_RL_LIMIT  = 120   # max requests per window per agent (agents poll every 5s = 12/min; leave room for retries)

def _real_client_ip():
    """Extract true client IP, respecting Cloudflare and NPM proxy headers."""
    try:
        remote = ipaddress.ip_address(request.remote_addr or '0.0.0.0')
    except ValueError:
        return request.remote_addr or '0.0.0.0'
    if any(remote in net for net in _CF_NETS):
        return request.headers.get('Cf-Connecting-Ip', str(remote)) or str(remote)
    if any(remote in net for net in _TRUSTED_PROXY_NETS):
        xff = (request.headers.get('X-Forwarded-For') or '').split(',')[0].strip()
        return xff or request.headers.get('X-Real-Ip', str(remote)) or str(remote)
    return str(remote)

def _agent_rate_limit(agent_id: str = '') -> bool:
    """Return True if this agent has exceeded the rate limit.

    Key is the agent_id when provided (beacon/poll), otherwise falls back to IP.
    This avoids false-positives when many agents share the Docker bridge IP.
    """
    key = agent_id if agent_id else _real_client_ip()
    now = time.time()
    with _rl_lock:
        ts = _rl_counts[key]
        ts[:] = [t for t in ts if now - t < _RL_WINDOW]
        if len(ts) >= _RL_LIMIT:
            return True
        ts.append(now)
    return False

MFA_SECRET_FILE = '/app/secrets/mfa.key'

def _mfa_secret():
    """Return stored TOTP secret, or None if not configured."""
    try:
        with open(MFA_SECRET_FILE, 'r') as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None

def _mfa_enabled():
    return _mfa_secret() is not None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── Error sanitization ────────────────────────────────────────────────────────
def _sanitize_err(e):
    """Log exception detail server-side and return a safe generic string for API responses."""
    app.logger.error(f'API error: {e}')
    return 'Internal server error'

# ── CSRF protection ───────────────────────────────────────────────────────────
def _csrf_token():
    """Return per-session CSRF token, creating one if needed."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def _validate_csrf():
    """Validate CSRF token on a POST form submission. Returns (msg, 400) or None."""
    submitted = request.form.get('csrf_token', '')
    expected  = session.get('csrf_token', '')
    if not submitted or not expected or not secrets.compare_digest(submitted, expected):
        app.logger.warning(f'CSRF validation failed from {request.remote_addr}')
        return 'Invalid request — please try again', 400
    return None

app.jinja_env.globals['csrf_token'] = _csrf_token

# ── Persistent rate limiting (SQLite-backed, survives restarts) ───────────────
_RL_MAX    = 10   # max failed attempts
_RL_WINDOW = 900  # sliding window in seconds (15 min)

def _rate_limit_is_blocked(ip: str) -> bool:
    """Return True if this IP has hit the failed-attempt ceiling."""
    now    = time.time()
    cutoff = now - _RL_WINDOW
    conn   = sqlite3.connect(DB_PATH)
    try:
        conn.execute('DELETE FROM rate_limits WHERE ts < ?', (cutoff,))
        count = conn.execute(
            'SELECT COUNT(*) FROM rate_limits WHERE ip=? AND ts>=?', (ip, cutoff)
        ).fetchone()[0]
        conn.commit()
        return count >= _RL_MAX
    finally:
        conn.close()

def _rate_limit_increment(ip: str):
    """Record one failed attempt for the given IP."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('INSERT INTO rate_limits (ip, ts) VALUES (?,?)', (ip, time.time()))
        conn.commit()
    finally:
        conn.close()

def _rate_limit_clear(ip: str):
    """Remove all rate-limit records for an IP (call on successful auth)."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('DELETE FROM rate_limits WHERE ip=?', (ip,))
        conn.commit()
    finally:
        conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        csrf_err = _validate_csrf()
        if csrf_err:
            return render_template('login.html', error=csrf_err[0]), csrf_err[1]
        ip = (request.headers.get('Cf-Connecting-Ip') or
              (request.headers.get('X-Forwarded-For') or '').split(',')[0].strip() or
              request.remote_addr or '0.0.0.0')
        if _rate_limit_is_blocked(ip):
            return render_template('login.html', error='Too many failed attempts — try again in 15 minutes')
        if request.form.get('username') == DASHBOARD_USER and request.form.get('password') == DASHBOARD_PASS:
            _rate_limit_clear(ip)
            if _mfa_enabled():
                session['mfa_pending'] = True
                session.pop('logged_in', None)
                return redirect(url_for('mfa_verify'))
            else:
                session['logged_in'] = True
                return redirect(url_for('mfa_setup'))  # first run — force setup
        _rate_limit_increment(ip)
        error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/mfa', methods=['GET', 'POST'])
def mfa_verify():
    if not session.get('mfa_pending'):
        return redirect(url_for('login'))
    error = None
    if request.method == 'POST':
        csrf_err = _validate_csrf()
        if csrf_err:
            return render_template('mfa.html', error=csrf_err[0]), csrf_err[1]
        import pyotp
        code = (request.form.get('token') or request.form.get('code') or '').replace(' ', '')
        secret = _mfa_secret()
        if secret and pyotp.TOTP(secret).verify(code, valid_window=2):
            session.pop('mfa_pending', None)
            session['logged_in'] = True
            _notify_login(_real_client_ip())
            return redirect(url_for('index'))
        error = 'Invalid code — try again'
    return render_template('mfa.html', error=error)

@app.route('/mfa/setup', methods=['GET', 'POST'])
def mfa_setup():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    import pyotp, qrcode, io, base64
    error = None

    # Auto-generate a secret on first visit
    if not session.get('mfa_new_secret'):
        session['mfa_new_secret'] = pyotp.random_base32()

    if request.method == 'POST':
        csrf_err = _validate_csrf()
        if csrf_err:
            error = csrf_err[0]
        else:
            secret = session.get('mfa_new_secret')
            code = request.form.get('token', '').replace(' ', '')
            if secret and pyotp.TOTP(secret).verify(code, valid_window=2):
                with open(MFA_SECRET_FILE, 'w') as f:
                    f.write(secret)
                import os
                os.chmod(MFA_SECRET_FILE, 0o600)
                session.pop('mfa_new_secret', None)
                session['logged_in'] = True
                return redirect(url_for('index'))
            error = 'Code did not match — try again'

    secret = session['mfa_new_secret']
    uri = pyotp.TOTP(secret).provisioning_uri(name=DASHBOARD_USER, issuer_name='SomoTechs SOC')
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_img = 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()

    return render_template('mfa_setup.html', secret=secret, qr_img=qr_img,
                           error=error, mfa_already_set=_mfa_enabled())

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ── Wazuh ─────────────────────────────────────────────────────────────────────

def get_wazuh_token():
    try:
        r = requests.post(f"{WAZUH_API_URL}/security/user/authenticate",
            auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=WAZUH_API_CA, timeout=5)
        if r.status_code == 200:
            return r.json().get('data', {}).get('token')
    except:
        pass
    return None

def get_wazuh_agents():
    try:
        token = get_wazuh_token()
        if not token:
            return []
        r = requests.get(f"{WAZUH_API_URL}/agents?limit=500&sort=-lastKeepAlive",
            headers={'Authorization': f'Bearer {token}'}, verify=WAZUH_API_CA, timeout=8)
        if r.status_code == 200:
            items = r.json().get('data', {}).get('affected_items', [])
            # Exclude the manager itself (id 000)
            return [a for a in items if a.get('id') != '000']
    except:
        pass
    return []

def get_wazuh_alerts():
    try:
        query = {
            "size": 15,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"range": {"@timestamp": {"gte": "now-24h"}}}
        }
        r = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=5)
        if r.status_code == 200:
            hits = r.json().get('hits', {}).get('hits', [])
            return [{
                'time':  h['_source'].get('@timestamp', ''),
                'agent': h['_source'].get('agent', {}).get('name', 'Unknown'),
                'rule':  h['_source'].get('rule', {}).get('description', 'Unknown'),
                'level': h['_source'].get('rule', {}).get('level', 0),
                'id':    h['_source'].get('rule', {}).get('id', '')
            } for h in hits]
    except:
        pass
    return []

def get_alert_counts():
    try:
        query = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
            "aggs": {
                "by_level": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low",    "from": 0,  "to": 7},
                            {"key": "medium", "from": 7,  "to": 12},
                            {"key": "high",   "from": 12, "to": 16}
                        ]
                    }
                }
            }
        }
        r = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=5)
        if r.status_code == 200:
            buckets = r.json().get('aggregations', {}).get('by_level', {}).get('buckets', [])
            counts = {'low': 0, 'medium': 0, 'high': 0, 'total': 0}
            for b in buckets:
                counts[b['key']] = b['doc_count']
                counts['total'] += b['doc_count']
            return counts
    except:
        pass
    return {'low': 0, 'medium': 0, 'high': 0, 'total': 0}

# ── CrowdSec ──────────────────────────────────────────────────────────────────

def _cs_headers():
    return {'X-Api-Key': CROWDSEC_API_KEY}

def get_crowdsec_decisions():
    try:
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions?limit=20",
            headers=_cs_headers(), timeout=5)
        if r.status_code == 200:
            return r.json() or []
    except:
        pass
    return []

def get_crowdsec_total():
    """Return total count of active decisions via stream startup."""
    try:
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions/stream?startup=true",
            headers=_cs_headers(), timeout=8)
        if r.status_code == 200:
            d = r.json()
            return len(d.get('new') or [])
    except:
        pass
    # Fallback: count decisions directly
    try:
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions?limit=1",
            headers=_cs_headers(), timeout=5)
        if r.status_code == 200:
            body = r.json()
            if body is None:
                return 0
            return len(body) if isinstance(body, list) else 0
    except:
        pass
    return 0

def get_crowdsec_alerts():
    try:
        r = requests.get(f"{CROWDSEC_URL}/v1/alerts?limit=10",
            headers=_cs_headers(), timeout=5)
        if r.status_code == 200:
            return r.json() or []
    except:
        pass
    return []

# ── TacticalRMM ───────────────────────────────────────────────────────────────

def get_trmm_data():
    if not TRMM_API_TOKEN:
        return {'total': 0, 'online': 0, 'offline': 0, 'overdue': 0,
                'needs_reboot': 0, 'patches_pending': 0, 'failing_checks': 0,
                'agents': [], 'error': 'No API token configured'}
    try:
        r = requests.get(f"{TRMM_API_URL}/agents/",
            headers={'Authorization': f'Token {TRMM_API_TOKEN}'},
            verify=True, timeout=8)
        if r.status_code == 200:
            agents = r.json()
            return {
                'total':           len(agents),
                'online':          sum(1 for a in agents if a.get('status') == 'online'),
                'offline':         sum(1 for a in agents if a.get('status') == 'offline'),
                'overdue':         sum(1 for a in agents if a.get('status') == 'overdue'),
                'needs_reboot':    sum(1 for a in agents if a.get('needs_reboot')),
                'patches_pending': sum(1 for a in agents if a.get('has_patches_pending')),
                'failing_checks':  sum(1 for a in agents if a.get('checks', {}).get('has_failing_checks')),
                'agents': [{
                    'hostname':       a.get('hostname', '?'),
                    'status':         a.get('status', 'unknown'),
                    'client':         a.get('client_name', '?'),
                    'site':           a.get('site_name', '?'),
                    'os':             (a.get('operating_system') or 'Windows')[:35],
                    'last_seen':      a.get('last_seen', ''),
                    'needs_reboot':   a.get('needs_reboot', False),
                    'has_patches':    a.get('has_patches_pending', False),
                    'failing_checks': a.get('checks', {}).get('has_failing_checks', False),
                } for a in agents]
            }
        return {'total': 0, 'online': 0, 'offline': 0, 'overdue': 0,
                'needs_reboot': 0, 'patches_pending': 0, 'failing_checks': 0,
                'agents': [], 'error': f'API returned {r.status_code}'}
    except Exception as e:
        pass
    return {'total': 0, 'online': 0, 'offline': 0, 'overdue': 0,
            'needs_reboot': 0, 'patches_pending': 0, 'failing_checks': 0,
            'agents': [], 'error': 'Connection failed'}

# ── Netdata ───────────────────────────────────────────────────────────────────

def get_netdata_summary():
    result = {'cpu': 0, 'ram': 0, 'net_in': 0, 'net_out': 0}
    try:
        r = requests.get(f"{NETDATA_URL}/api/v1/data?chart=system.cpu&points=1&format=json", timeout=3)
        if r.status_code == 200:
            d = r.json()
            result['cpu'] = round(sum(d['data'][0][1:]), 1) if d.get('data') else 0
    except:
        pass
    try:
        r = requests.get(f"{NETDATA_URL}/api/v1/data?chart=system.ram&points=1&format=json", timeout=3)
        if r.status_code == 200:
            d = r.json()
            if d.get('data') and d.get('dimension_names'):
                dims = {name: val for name, val in zip(d['dimension_names'], d['data'][0][1:])}
                used = dims.get('used', 0) + dims.get('buffers', 0) + dims.get('active', 0)
                total = sum(v for v in dims.values() if v > 0)
                result['ram'] = round((used / total * 100) if total else 0, 1)
    except:
        pass
    return result

# ── Custom RMM summary ────────────────────────────────────────────────────────

def get_rmm_summary():
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute('SELECT id, hostname, ip, os, cpu, ram, disk, uptime, logged_user, last_seen FROM agents ORDER BY last_seen DESC')
        cols = [d[0] for d in c.description]
        rows = [dict(zip(cols, row)) for row in c.fetchall()]
        conn.close()
        cutoff = datetime.utcnow().timestamp() - 180
        online, offline = 0, 0
        agents_out = []
        for a in rows:
            try:
                ts = datetime.fromisoformat(a['last_seen']).timestamp()
                a['online'] = ts > cutoff
            except:
                a['online'] = False
            if a['online']:
                online += 1
            else:
                offline += 1
            agents_out.append(a)
        return {
            'total': len(rows),
            'online': online,
            'offline': offline,
            'agents': agents_out[:10]
        }
    except:
        return {'total': 0, 'online': 0, 'offline': 0, 'agents': []}

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/data')
@login_required
def api_data():
    agents       = get_wazuh_agents()
    alert_counts = get_alert_counts()
    recent       = get_wazuh_alerts()
    decisions    = get_crowdsec_decisions()
    netdata      = get_netdata_summary()
    rmm          = get_rmm_summary()

    active  = [a for a in agents if a.get('status') == 'active']
    disconn = [a for a in agents if a.get('status') == 'disconnected']
    never   = [a for a in agents if a.get('status') == 'never_connected']

    return jsonify({
        'agents': {
            'total':       len(agents),
            'online':      len(active),
            'offline':     len(disconn),
            'never':       len(never),
            'list':        agents[:25]
        },
        'alerts':        alert_counts,
        'recent_alerts': recent,
        'rmm':           rmm,
        'crowdsec': {
            'blocked':   len(decisions) if decisions else 0,
            'decisions': decisions[:10] if decisions else [],
            'total':     None  # fetched separately via /api/crowdsec/live
        },
        'system':  netdata,
        'updated': datetime.utcnow().strftime('%H:%M:%S UTC')
    })

@app.route('/api/crowdsec/decisions')
@login_required
def api_crowdsec_decisions():
    return jsonify(get_crowdsec_decisions())

def _geo_country_batch(ips):
    """Server-side batch geo lookup. Returns {ip: {country, cc}}."""
    result = {}
    if not ips:
        return result
    unique = list(dict.fromkeys(ips))[:300]  # dedupe, cap at 300
    batches = [unique[i:i+100] for i in range(0, len(unique), 100)]
    for batch in batches:
        try:
            r = requests.post(
                'http://ip-api.com/batch?fields=query,country,countryCode,status',
                json=batch, timeout=5
            )
            if r.status_code == 200:
                for d in r.json():
                    if d.get('status') == 'success':
                        result[d['query']] = {
                            'country': d.get('country', '?'),
                            'cc': d.get('countryCode', ''),
                        }
        except Exception:
            pass
    return result

@app.route('/api/crowdsec/live')
@login_required
def api_crowdsec_live():
    """Returns latest 500 decisions plus total active count and server-side geo data."""
    try:
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions?limit=500",
            headers=_cs_headers(), timeout=6)
        decisions = r.json() if r.status_code == 200 else []
    except:
        decisions = []
    total = get_crowdsec_total() or 0
    decisions = decisions or []
    ips = list({d['value'] for d in decisions if d.get('value')})
    geo = _geo_country_batch(ips)
    return jsonify({
        'decisions': decisions,
        'total': total,
        'geo': geo,
    })

@app.route('/api/crowdsec/unblock', methods=['POST'])
@login_required
def api_crowdsec_unblock():
    """Unblock an IP from CrowdSec. POST {ip: "1.2.3.4"}"""
    ip = request.json.get('ip', '').strip() if request.is_json else ''
    if not ip:
        return jsonify({'success': False, 'error': 'No IP provided'}), 400
    try:
        r = requests.delete(f"{CROWDSEC_URL}/v1/decisions",
            headers=_cs_headers(),
            params={'ip': ip}, timeout=5)
        if r.status_code in (200, 204):
            return jsonify({'success': True, 'ip': ip})
        return jsonify({'success': False, 'error': f'CrowdSec returned {r.status_code}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': _sanitize_err(e)}), 500

@app.route('/api/crowdsec/ban', methods=['POST'])
@login_required
def api_crowdsec_ban():
    """Permanently ban an IP via cscli inside the crowdsec container."""
    import re, docker as _docker
    data   = request.json or {}
    ip     = data.get('ip', '').strip()
    reason = data.get('reason', 'Manual SOC ban').strip() or 'Manual SOC ban'
    if not ip or not re.match(r'^[\d.:/a-fA-F]+$', ip):
        return jsonify({'success': False, 'error': 'Invalid IP'}), 400
    try:
        client    = _docker.DockerClient(base_url='unix:///var/run/docker.sock')
        container = client.containers.get('crowdsec')
        result    = container.exec_run(
            ['cscli', 'decisions', 'add', '--ip', ip,
             '--duration', '-1s', '--reason', reason],
            demux=False
        )
        output = (result.output or b'').decode('utf-8', errors='replace').strip()
        if result.exit_code == 0:
            return jsonify({'success': True, 'ip': ip})
        return jsonify({'success': False, 'error': output or 'cscli returned non-zero'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': _sanitize_err(e)}), 500


@app.route('/api/crowdsec/make-permanent', methods=['POST'])
@login_required
def api_crowdsec_make_permanent():
    """Convert all finite-duration bans to permanent (-1s) via cscli."""
    import docker as _docker
    try:
        # Fetch all current decisions
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions?type=ban&limit=500",
                         headers=_cs_headers(), timeout=10)
        decisions = r.json() if r.status_code == 200 else []
        if not decisions:
            return jsonify({'success': True, 'converted': 0})

        client    = _docker.DockerClient(base_url='unix:///var/run/docker.sock')
        container = client.containers.get('crowdsec')
        converted = 0
        for dec in decisions:
            dur = dec.get('duration', '')
            # Skip already permanent (negative duration)
            if dur.startswith('-'):
                continue
            ip = dec.get('value', '')
            if not ip:
                continue
            # Delete existing decision then re-add as permanent
            requests.delete(f"{CROWDSEC_URL}/v1/decisions",
                            headers=_cs_headers(), params={'ip': ip}, timeout=5)
            res = container.exec_run(
                ['cscli', 'decisions', 'add', '--ip', ip,
                 '--duration', '-1s', '--reason', dec.get('scenario', 'auto-ban')],
                demux=False
            )
            if res.exit_code == 0:
                converted += 1
        return jsonify({'success': True, 'converted': converted})
    except Exception as e:
        return jsonify({'success': False, 'error': _sanitize_err(e)}), 500


@app.route('/api/crowdsec/unblock-all', methods=['POST'])
@login_required
def api_crowdsec_unblock_all():
    """Delete all active CrowdSec decisions."""
    try:
        r = requests.delete(f"{CROWDSEC_URL}/v1/decisions",
            headers=_cs_headers(), timeout=5)
        if r.status_code in (200, 204):
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': f'Status {r.status_code}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': _sanitize_err(e)}), 500

@app.route('/api/status')
@login_required
def api_status():
    """Quick health check of all connected services."""
    def probe(fn):
        try:
            result = fn()
            return {'ok': True,  'count': len(result) if isinstance(result, list) else None}
        except:
            return {'ok': False}

    wazuh_token = get_wazuh_token()
    return jsonify({
        'wazuh_api':   {'ok': wazuh_token is not None},
        'wazuh_index': probe(get_wazuh_alerts),
        'trmm':        {'ok': bool(TRMM_API_TOKEN)},
        'crowdsec':    probe(get_crowdsec_decisions),
        'netdata':     probe(get_netdata_summary),
        'timestamp':   datetime.utcnow().isoformat()
    })

# ── Agent RMM ─────────────────────────────────────────────────────────────────

def agent_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-Agent-Key', '')
        if key != AGENT_SECRET:
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def db_conn():
    return sqlite3.connect(DB_PATH)

@app.route('/api/rmm/poll', methods=['POST'])
@agent_auth
def rmm_poll():
    """Lightweight command check — updates last_seen without touching telemetry."""
    d = request.get_json(force=True, silent=True) or {}
    agent_id = d.get('id', '')
    if _agent_rate_limit(agent_id):
        return jsonify({'error': 'rate limit'}), 429
    if not agent_id:
        return jsonify({'error': 'no id'}), 400
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    conn.execute('UPDATE agents SET last_seen=? WHERE id=?', (now, agent_id))
    conn.commit()
    c = conn.cursor()
    c.execute("SELECT id,command FROM commands WHERE agent_id=? AND status='pending' ORDER BY id LIMIT 5", (agent_id,))
    cmds = [{'id': r[0], 'command': r[1]} for r in c.fetchall()]
    conn.close()
    return jsonify({'commands': cmds})

@app.route('/api/rmm/beacon', methods=['POST'])
@agent_auth
def rmm_beacon():
    d = request.get_json(force=True, silent=True) or {}
    agent_id = d.get('id', '')
    if _agent_rate_limit(agent_id):
        return jsonify({'error': 'rate limit'}), 429
    if not agent_id:
        return jsonify({'error': 'no id'}), 400
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT first_seen FROM agents WHERE id=?', (agent_id,))
    row = c.fetchone()
    first_seen = row[0] if row else now
    c.execute('''INSERT OR REPLACE INTO agents
        (id,hostname,ip,os,cpu,ram,disk,uptime,logged_user,last_seen,first_seen,version,client,
         model,manufacturer,serial,ram_gb,cpu_model,domain,win_build,disk_model,bios)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        agent_id, d.get('hostname','?'), d.get('ip','?'), d.get('os','?'),
        d.get('cpu',0), d.get('ram',0), d.get('disk',0),
        d.get('uptime','?'), d.get('user','?'), now, first_seen,
        d.get('version','1.0'), d.get('client',''),
        d.get('model',''), d.get('manufacturer',''), d.get('serial',''),
        d.get('ram_gb',0), d.get('cpu_model',''), d.get('domain',''),
        d.get('win_build',''), d.get('disk_model',''), d.get('bios',''),
    ))
    conn.commit()
    # Health checks (disk/cpu alerts)
    try:
        _check_agent_health(d, conn)
    except Exception:
        pass
    # on_checkin policies
    try:
        _check_on_checkin_policies(agent_id)
    except Exception:
        pass
    # Return pending commands
    c.execute("SELECT id,command FROM commands WHERE agent_id=? AND status='pending' ORDER BY id LIMIT 5", (agent_id,))
    cmds = [{'id': r[0], 'command': r[1]} for r in c.fetchall()]
    conn.close()
    return jsonify({'commands': cmds})

@app.route('/api/rmm/result', methods=['POST'])
@agent_auth
def rmm_result():
    d = request.get_json(force=True, silent=True) or {}
    if _agent_rate_limit(d.get('id', '')):
        return jsonify({'error': 'rate limit'}), 429
    cmd_id = d.get('cmd_id')
    output = d.get('output', '')
    if not cmd_id:
        return jsonify({'ok': True}), 200  # ignore stale results with no cmd_id
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    conn.execute("UPDATE commands SET status='done', output=?, completed=? WHERE id=?", (output, now, cmd_id))
    conn.commit()
    row = conn.execute("SELECT agent_id, cmd_type FROM commands WHERE id=?", (cmd_id,)).fetchone()
    if row:
        agent_id, cmd_type = row
        if cmd_type == 'av_scan':
            _process_av_result(conn, cmd_id, output, now)
        elif cmd_type == 'screenshot' and output:
            # Strip whitespace — PS sometimes adds trailing newlines that break base64
            clean = output.strip().replace('\r','').replace('\n','')
            hostname = (conn.execute("SELECT hostname FROM agents WHERE id=?", (agent_id,)).fetchone() or ('',))[0]
            conn.execute(
                "INSERT OR REPLACE INTO agent_screenshots (agent_id,hostname,image_b64,taken_at) VALUES (?,?,?,?)",
                (agent_id, hostname, clean[:2_000_000], now)
            )
            conn.commit()
        elif cmd_type == 'policy':
            conn.execute(
                "UPDATE policy_runs SET status=? WHERE cmd_id=?",
                ('done' if output else 'empty', cmd_id)
            )
            conn.commit()
    conn.close()
    return jsonify({'ok': True})


def _process_av_result(conn, cmd_id, output, completed_at):
    """Parse beacon AV scan JSON output and store in av_scans table."""
    try:
        data = json.loads(output)
        av   = data.get('av', {}) or {}
        threats = data.get('threats') or []
        if isinstance(threats, str):
            threats = json.loads(threats) if threats else []
        if not isinstance(threats, list):
            threats = [threats] if threats else []
        threat_count   = len(threats)
        av_enabled     = 1 if av.get('AntivirusEnabled', True) else 0
        rt_enabled     = 1 if av.get('RealTimeProtectionEnabled', True) else 0
        last_scan_time = av.get('LastScan', '')
        status = 'threats' if threat_count > 0 else 'clean'
        conn.execute(
            "UPDATE av_scans SET status=?, completed_at=?, threat_count=?, "
            "av_enabled=?, realtime_enabled=?, last_scan_time=?, threats_json=?, raw_output=? "
            "WHERE cmd_id=?",
            (status, completed_at, threat_count, av_enabled, rt_enabled,
             last_scan_time, json.dumps(threats), output[:4000], cmd_id)
        )
        conn.commit()
    except Exception as e:
        app.logger.warning(f'AV result parse error cmd_id={cmd_id}: {e}')

@app.route('/api/rmm/agents')
@login_required
def rmm_agents():
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM agents ORDER BY last_seen DESC')
    cols = [d[0] for d in c.description]
    agents = [dict(zip(cols, row)) for row in c.fetchall()]
    conn.close()
    # Mark online if seen in last 3 minutes; mark ws_connected if currently WS-live
    cutoff = datetime.utcnow().timestamp() - 180
    with _ws_agents_lock:
        live_ids = set(_ws_agents.keys())
    for a in agents:
        try:
            ts = datetime.fromisoformat(a['last_seen']).timestamp()
            a['online'] = ts > cutoff
        except:
            a['online'] = False
        a['ws_connected'] = a.get('id', '') in live_ids
    return jsonify(agents)

@app.route('/api/rmm/agents/assign-client', methods=['POST'])
@login_required
def rmm_assign_client():
    """Assign (or clear) the client name for one or more agents by hostname."""
    data = request.get_json(silent=True) or {}
    client = data.get('client', '').strip()
    hostnames = data.get('hostnames', [])
    if not isinstance(hostnames, list) or not hostnames:
        return jsonify({'error': 'hostnames list required'}), 400
    conn = db_conn()
    updated = 0
    for h in hostnames:
        if not isinstance(h, str):
            continue
        result = conn.execute(
            "UPDATE agents SET client=? WHERE lower(hostname)=lower(?)",
            (client, h)
        )
        updated += result.rowcount
    conn.commit()
    conn.close()
    # Invalidate client health cache so next request is fresh
    global _client_health_cache
    _client_health_cache = {'ts': 0, 'data': None}
    return jsonify({'ok': True, 'updated': updated, 'client': client})


@app.route('/api/rmm/command', methods=['POST'])
@login_required
def rmm_command():
    d = request.json or {}
    agent_id = d.get('agent_id', '')
    command = d.get('command', '').strip()
    if not agent_id or not command:
        return jsonify({'error': 'missing fields'}), 400

    # Require TOTP verification for every shell command
    if _mfa_enabled():
        import pyotp
        totp_code = str(d.get('totp', '')).strip()
        secret = _mfa_secret()
        if not totp_code:
            return jsonify({'error': 'totp_required', 'msg': 'Enter your 2FA code to run commands'}), 403
        if not (secret and pyotp.TOTP(secret).verify(totp_code, valid_window=1)):
            return jsonify({'error': 'totp_invalid', 'msg': 'Invalid 2FA code'}), 403

    now = datetime.utcnow().isoformat()
    conn = db_conn()
    c = conn.cursor()
    c.execute("INSERT INTO commands (agent_id,command,status,created) VALUES (?,?,'pending',?)",
              (agent_id, command, now))
    cmd_id = c.lastrowid
    conn.commit()
    conn.close()
    # Push instantly via WebSocket if SomoAgent is connected
    _ws_agent_push_cmd(agent_id, cmd_id, command)
    return jsonify({'ok': True, 'cmd_id': cmd_id})

@app.route('/api/rmm/commands/<agent_id>')
@login_required
def rmm_commands(agent_id):
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM commands WHERE agent_id=? ORDER BY id DESC LIMIT 20', (agent_id,))
    cols = [d[0] for d in c.description]
    cmds = [dict(zip(cols, row)) for row in c.fetchall()]
    conn.close()
    return jsonify(cmds)

@app.route('/api/rmm/cancel/<agent_id>', methods=['POST'])
@login_required
def rmm_cancel_pending(agent_id):
    """Cancel all pending commands for an agent."""
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM commands WHERE agent_id=? AND status='pending'", (agent_id,))
    count = c.fetchone()[0]
    conn.execute("UPDATE commands SET status='done', output='[cancelled by operator]', completed=? WHERE agent_id=? AND status='pending'",
                 (now, agent_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'cancelled': count})

@app.route('/api/crowdsec/search')
@login_required
def api_crowdsec_search():
    """Search CrowdSec decisions by IP or range."""
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'no ip'}), 400
    try:
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions?ip={ip}&limit=20",
            headers=_cs_headers(), timeout=5)
        if r.status_code == 200:
            return jsonify(r.json() or [])
    except Exception as e:
        return jsonify({'error': _sanitize_err(e)}), 500
    return jsonify([])

@app.route('/api/rmm/assign/<agent_id>', methods=['POST'])
@login_required
def rmm_assign_agent(agent_id):
    """Reassign an agent to a different client."""
    d = request.get_json(silent=True) or {}
    client = str(d.get('client', '')).strip()[:60]
    conn = db_conn()
    conn.execute('UPDATE agents SET client=? WHERE id=?', (client, agent_id))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/rmm/delete/<agent_id>', methods=['DELETE'])
@login_required
def rmm_delete_agent(agent_id):
    conn = db_conn()
    conn.execute('DELETE FROM agents WHERE id=?', (agent_id,))
    conn.execute('DELETE FROM commands WHERE agent_id=?', (agent_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/rmm/tool', methods=['POST'])
@login_required
def rmm_tool():
    """Queue a structured RMM tool command. Returns cmd_id to poll."""
    d = request.json or {}
    agent_id = d.get('agent_id', '')
    tool = d.get('tool', '')
    if not agent_id or not tool:
        return jsonify({'error': 'missing fields'}), 400

    TOOL_COMMANDS = {
        'processes': (
            "Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 "
            "Name,Id,"
            "@{N='CPU';E={[math]::Round($_.CPU,1)}},"
            "@{N='RAM';E={[math]::Round($_.WorkingSet64/1MB,1)}} "
            "| ConvertTo-Json -Compress"
        ),
        'services': (
            "Get-Service | Sort-Object Status -Descending "
            "| Select-Object Name,DisplayName,"
            "@{N='Status';E={$_.Status.ToString()}},"
            "@{N='Start';E={$_.StartType.ToString()}} "
            "| ConvertTo-Json -Compress"
        ),
        'network': (
            "Get-NetIPConfiguration | Where-Object {$_.IPv4Address} "
            "| ForEach-Object { [pscustomobject]@{"
            "Iface=$_.InterfaceAlias;"
            "IP=($_.IPv4Address.IPAddress -join ',');"
            "GW=($_.IPv4DefaultGateway.NextHop);"
            "DNS=($_.DNSServer.ServerAddresses -join ',')"
            "} } | ConvertTo-Json -Compress"
        ),
        'software': (
            "$a=@();"
            "@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*') "
            "| ForEach-Object { Get-ItemProperty $_ -EA SilentlyContinue "
            "| Where-Object DisplayName "
            "| ForEach-Object { $a += [pscustomobject]@{N=$_.DisplayName;V=$_.DisplayVersion;P=$_.Publisher} } };"
            "$a | Sort-Object N | Select-Object -First 100 | ConvertTo-Json -Compress"
        ),
        'events': (
            "Get-WinEvent -LogName System -MaxEvents 30 -EA SilentlyContinue "
            "| Select-Object "
            "@{N='T';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}},"
            "@{N='L';E={$_.LevelDisplayName}},"
            "@{N='S';E={$_.ProviderName}},"
            "@{N='M';E={$_.Message.Substring(0,[Math]::Min(120,$_.Message.Length))}} "
            "| ConvertTo-Json -Compress"
        ),
        'sysinfo': (
            "[pscustomobject]@{"
            "OS=(Get-WmiObject Win32_OperatingSystem).Caption;"
            "Build=(Get-WmiObject Win32_OperatingSystem).BuildNumber;"
            "CPU=(Get-WmiObject Win32_Processor | Select-Object -First 1).Name;"
            "RAM_GB=[math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB,1);"
            "Disks=(Get-WmiObject Win32_LogicalDisk | Where-Object{$_.DriveType -eq 3} "
            "| Select-Object DeviceID,"
            "@{N='Size_GB';E={[math]::Round($_.Size/1GB,1)}},"
            "@{N='Free_GB';E={[math]::Round($_.FreeSpace/1GB,1)}} "
            "| ConvertTo-Json -Compress -Depth 3)"
            "} | ConvertTo-Json -Compress"
        ),
        'patches': (
            "try{"
            "$sess=New-Object -ComObject Microsoft.Update.Session;"
            "$srch=$sess.CreateUpdateSearcher();"
            "$res=$srch.Search('IsInstalled=0 and Type=''Software''');"
            "$out=$res.Updates|ForEach-Object{"
            "[pscustomobject]@{"
            "Title=$_.Title;"
            "Severity=$(if($_.MsrcSeverity){$_.MsrcSeverity}else{'Low'});"
            "KB=$(($_.KBArticleIDs|ForEach-Object{\"KB$_\"})-join',');"
            "Size_MB=[math]::Round($_.MaxDownloadSize/1MB,1)"
            "}};"
            "$out|Sort-Object Severity|ConvertTo-Json -Compress"
            "}catch{"
            "[pscustomobject]@{error=$_.Exception.Message}|ConvertTo-Json -Compress"
            "}"
        ),
        'reboot_status': (
            "$r=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired' -EA SilentlyContinue);"
            "$cbs=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending' -EA SilentlyContinue);"
            "$uptime=[math]::Round((New-TimeSpan -Start (Get-Date).AddSeconds(-[System.Environment]::TickCount64/1000)).TotalDays,1);"
            "[pscustomobject]@{"
            "RebootRequired=[bool]($r -or $cbs);"
            "UptimeDays=$uptime;"
            "LastBoot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm')"
            "}|ConvertTo-Json -Compress"
        ),
    }

    cmd = TOOL_COMMANDS.get(tool)
    if not cmd:
        return jsonify({'error': f'unknown tool: {tool}'}), 400

    now = datetime.utcnow().isoformat()
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "INSERT INTO commands (agent_id,command,status,created,cmd_type) VALUES (?,?,'pending',?,?)",
        (agent_id, cmd, now, tool)
    )
    cmd_id = c.lastrowid
    conn.commit()
    conn.close()
    # Push instantly via WebSocket if agent is live — no waiting for next HTTP poll
    _ws_agent_push_cmd(agent_id, cmd_id, cmd)
    return jsonify({'ok': True, 'cmd_id': cmd_id, 'tool': tool})

@app.route('/api/rmm/cmd/<int:cmd_id>')
@login_required
def rmm_cmd_result(cmd_id):
    """Get a single command result by ID."""
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT id,status,output,cmd_type,completed FROM commands WHERE id=?', (cmd_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'id': row[0], 'status': row[1], 'output': row[2], 'cmd_type': row[3], 'completed': row[4]})

@app.route('/api/wazuh/geoalerts')
@login_required
def api_wazuh_geoalerts():
    """Return top attack sources with geo data + US-focused recent alerts for the threat map."""
    try:
        hours = max(1, min(8760, int(request.args.get('hours', 336))))
    except (ValueError, TypeError):
        hours = 336
    try:
        query = {
            "size": 0,
            "query": {"bool": {"must": [
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                {"exists": {"field": "GeoLocation"}},
                {"exists": {"field": "data.srcip"}},
                {"range": {"rule.level": {"gte": 3}}}
            ]}},
            "aggs": {
                "top_sources": {
                    "terms": {"field": "data.srcip", "size": 150},
                    "aggs": {
                        "geo": {"top_hits": {"size": 1, "_source": [
                            "GeoLocation", "data.srcip", "rule.level",
                            "rule.description", "agent.name", "@timestamp"
                        ]}}
                    }
                },
                "by_country": {
                    "terms": {"field": "GeoLocation.country_name", "size": 20}
                }
            }
        }
        r = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=10)
        if r.status_code == 200:
            data = r.json()
            buckets = data.get('aggregations', {}).get('top_sources', {}).get('buckets', [])
            countries = data.get('aggregations', {}).get('by_country', {}).get('buckets', [])
            points = []
            for b in buckets:
                hit = b['geo']['hits']['hits'][0]['_source']
                geo = hit.get('GeoLocation', {})
                loc = geo.get('location', {})
                if not loc:
                    continue
                points.append({
                    'ip':       hit.get('data', {}).get('srcip', ''),
                    'lat':      loc.get('lat'),
                    'lon':      loc.get('lon'),
                    'country':  geo.get('country_name', '?'),
                    'region':   geo.get('region_name', ''),
                    'count':    b['doc_count'],
                    'level':    hit.get('rule', {}).get('level', 0),
                    'rule':     hit.get('rule', {}).get('description', ''),
                    'agent':    hit.get('agent', {}).get('name', ''),
                    'time':     hit.get('@timestamp', ''),
                    'us':       geo.get('country_name', '') == 'United States',
                })
            # If few geo-tagged alerts, query for external IPs without GeoLocation field
            # Use max(hours, 720) so we always find real attack IPs even if quiet lately
            if len(points) < 10:
                try:
                    _ip_hours = max(hours, 720)
                    ip_query = {
                        "size": 0,
                        "query": {"bool": {"must": [
                            {"range": {"@timestamp": {"gte": f"now-{_ip_hours}h"}}},
                            {"exists": {"field": "data.srcip"}}
                        ], "must_not": [
                            {"prefix": {"data.srcip": "10."}},
                            {"prefix": {"data.srcip": "192.168."}},
                            {"prefix": {"data.srcip": "172.16."}},
                            {"prefix": {"data.srcip": "172.17."}},
                            {"prefix": {"data.srcip": "172.18."}},
                            {"prefix": {"data.srcip": "172.19."}},
                            {"prefix": {"data.srcip": "172.20."}},
                            {"prefix": {"data.srcip": "172.31."}},
                            {"term":   {"data.srcip": "127.0.0.1"}},
                            {"term":   {"data.srcip": "::1"}}
                        ]}},
                        "aggs": {
                            "top_ips": {
                                "terms": {"field": "data.srcip", "size": 150},
                                "aggs": {"latest": {"top_hits": {"size": 1, "_source": [
                                    "data.srcip", "rule.level", "rule.description",
                                    "agent.name", "@timestamp"
                                ]}}}
                            }
                        }
                    }
                    r2 = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
                        auth=(WAZUH_USER, WAZUH_PASS), json=ip_query, verify=WAZUH_CA, timeout=10)
                    if r2.status_code == 200:
                        ip_buckets = r2.json().get('aggregations', {}).get('top_ips', {}).get('buckets', [])
                        existing_ips = {p['ip'] for p in points}
                        ips_to_geo = [b['key'] for b in ip_buckets if b['key'] not in existing_ips]
                        ip_meta = {b['key']: b for b in ip_buckets}
                        if ips_to_geo:
                            for i in range(0, len(ips_to_geo[:150]), 100):
                                batch = ips_to_geo[i:i+100]
                                geo_r = requests.post('http://ip-api.com/batch',
                                    json=[{'query': ip, 'fields': 'query,country,regionName,lat,lon,status'} for ip in batch],
                                    timeout=10)
                                if geo_r.status_code == 200:
                                    for geo in geo_r.json():
                                        if geo.get('status') != 'success':
                                            continue
                                        ip = geo['query']
                                        bkt = ip_meta.get(ip, {})
                                        hit = (bkt.get('latest', {}).get('hits', {}).get('hits') or [{}])[0].get('_source', {})
                                        points.append({
                                            'ip':      ip,
                                            'lat':     geo['lat'],
                                            'lon':     geo['lon'],
                                            'country': geo.get('country', '?'),
                                            'region':  geo.get('regionName', ''),
                                            'count':   bkt.get('doc_count', 1),
                                            'level':   hit.get('rule', {}).get('level', 5),
                                            'rule':    hit.get('rule', {}).get('description', 'External connection'),
                                            'agent':   hit.get('agent', {}).get('name', ''),
                                            'time':    hit.get('@timestamp', ''),
                                            'us':      geo.get('country', '') == 'United States',
                                        })
                except Exception:
                    pass
            # Supplement with CrowdSec ban data when still few points
            if len(points) < 10:
                cs_points = _get_crowdsec_geopoints()
                existing_ips = {p['ip'] for p in points}
                for p in cs_points:
                    if p['ip'] not in existing_ips:
                        points.append(p)
            if not countries and points:
                from collections import Counter
                cc = Counter(p['country'] for p in points)
                countries = [{'key': k, 'doc_count': v} for k, v in cc.most_common(15)]
            return jsonify({
                'points': points,
                'total': data['hits']['total']['value'] or len(points),
                'countries': countries[:15]
            })
    except Exception as e:
        return jsonify({'points': [], 'total': 0, 'error': _sanitize_err(e)})
    return jsonify({'points': [], 'total': 0})


@app.route('/api/wazuh/logon_events')
@login_required
def api_wazuh_logon_events():
    """Recent Windows logon events: 4624 (types 2/3/10), 4625, 4672, 4648."""
    try:
        hours = max(1, min(720, int(request.args.get('hours', 24))))
    except (ValueError, TypeError):
        hours = 24
    try:
        query = {
            "size": 100,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": [
                {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                {"terms": {"rule.id": ["100300","100301","100302","100303",
                                       "100304","100305","100306","100307",
                                       "100308","100309","100310"]}}
            ]}}
        }
        r = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=8)
        if r.status_code == 200:
            hits = r.json().get('hits', {}).get('hits', [])
            events = []
            for h in hits:
                s = h['_source']
                wd = s.get('data', {}).get('win', {}).get('eventdata', {}) or {}
                ws = s.get('data', {}).get('win', {}).get('system', {}) or {}
                events.append({
                    'id':           h['_id'],
                    'index':        h['_index'],
                    'time':         s.get('@timestamp', ''),
                    'agent':        s.get('agent', {}).get('name', '?'),
                    'rule_id':      s.get('rule', {}).get('id', ''),
                    'rule':         s.get('rule', {}).get('description', ''),
                    'level':        s.get('rule', {}).get('level', 0),
                    'event_id':     ws.get('eventID', ''),
                    'logon_type':   wd.get('logonType', ''),
                    'target_user':  wd.get('targetUserName', ''),
                    'subject_user': wd.get('subjectUserName', ''),
                    'src_ip':       wd.get('ipAddress', ''),
                    'workstation':  wd.get('workstationName', ''),
                    'logon_process':wd.get('logonProcessName', ''),
                })
            return jsonify({'events': events, 'total': len(events)})
    except Exception as e:
        return jsonify({'events': [], 'error': _sanitize_err(e)})
    return jsonify({'events': []})


@app.route('/alerts')
@login_required
def alerts_page():
    return render_template('alerts.html')

@app.route('/threatmap')
@login_required
def threatmap_page():
    return render_template('threatmap.html')

@app.route('/api/wazuh/alerts')
@login_required
def api_wazuh_alerts():
    """Paginated alert list with filters: agent, level_min, hours, q (text search), from."""
    agent    = request.args.get('agent', '').strip()
    try:
        level = max(0, min(15, int(request.args.get('level_min', 0))))
    except (ValueError, TypeError):
        level = 0
    try:
        hours = max(1, min(720, int(request.args.get('hours', 24))))
    except (ValueError, TypeError):
        hours = 24
    q        = request.args.get('q', '').strip()
    try:
        from_idx = max(0, int(request.args.get('from', 0)))
    except (ValueError, TypeError):
        from_idx = 0
    try:
        size = max(1, min(500, int(request.args.get('size', 50))))
    except (ValueError, TypeError):
        size = 50

    must = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]
    if level > 0:
        must.append({"range": {"rule.level": {"gte": level}}})
    if agent:
        must.append({"term": {"agent.name": agent}})
    if q:
        must.append({"multi_match": {"query": q, "fields": ["rule.description", "agent.name", "data.srcip", "full_log"]}})

    query = {
        "from": from_idx,
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}}
    }
    try:
        r = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=8)
        if r.status_code == 200:
            data = r.json()
            hits = data.get('hits', {}).get('hits', [])
            total = data.get('hits', {}).get('total', {}).get('value', 0)
            alerts = []
            for h in hits:
                s = h['_source']
                alerts.append({
                    'id':       h['_id'],
                    'index':    h['_index'],
                    'time':     s.get('@timestamp', ''),
                    'agent':    s.get('agent', {}).get('name', '?'),
                    'agent_id': s.get('agent', {}).get('id', '?'),
                    'rule_id':  s.get('rule', {}).get('id', ''),
                    'rule':     s.get('rule', {}).get('description', '?'),
                    'level':    s.get('rule', {}).get('level', 0),
                    'groups':   s.get('rule', {}).get('groups', []),
                    'mitre':    s.get('rule', {}).get('mitre', {}),
                    'srcip':    s.get('data', {}).get('srcip', ''),
                    'manager':  s.get('manager', {}).get('name', ''),
                })
            return jsonify({'alerts': alerts, 'total': total, 'from': from_idx})
    except Exception as e:
        return jsonify({'alerts': [], 'total': 0, 'error': _sanitize_err(e)})
    return jsonify({'alerts': [], 'total': 0})

@app.route('/api/wazuh/alert/<doc_id>')
@login_required
def api_wazuh_alert_detail(doc_id):
    """Full alert detail by document ID."""
    index = request.args.get('index', 'wazuh-alerts-4.x-*')
    try:
        r = requests.get(f"{WAZUH_URL}/{index}/_doc/{doc_id}",
            auth=(WAZUH_USER, WAZUH_PASS), verify=WAZUH_CA, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return jsonify({'alert': data.get('_source', {}), 'id': doc_id})
        return jsonify({'error': f'Not found ({r.status_code})'}), 404
    except Exception as e:
        return jsonify({'error': _sanitize_err(e)}), 500

@app.route('/api/wazuh/related/<doc_id>')
@login_required
def api_wazuh_related(doc_id):
    """Fetch related alerts: same agent, ±10 min window around given alert."""
    index = request.args.get('index', 'wazuh-alerts-4.x-*')
    try:
        # Get the alert first to find its timestamp and agent
        r = requests.get(f"{WAZUH_URL}/{index}/_doc/{doc_id}",
            auth=(WAZUH_USER, WAZUH_PASS), verify=WAZUH_CA, timeout=5)
        if r.status_code != 200:
            return jsonify({'alerts': []})
        src = r.json().get('_source', {})
        ts      = src.get('@timestamp', '')
        agent   = src.get('agent', {}).get('name', '')
        rule_id = src.get('rule', {}).get('id', '')

        query = {
            "size": 20,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": [
                {"term": {"agent.name": agent}},
                {"range": {"@timestamp": {"gte": f"{ts}||-10m", "lte": f"{ts}||+10m"}}}
            ], "must_not": [{"ids": {"values": [doc_id]}}]}}
        }
        r2 = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=5)
        if r2.status_code == 200:
            hits = r2.json().get('hits', {}).get('hits', [])
            return jsonify({'alerts': [{
                'id':    h['_id'],
                'index': h['_index'],
                'time':  h['_source'].get('@timestamp', ''),
                'rule':  h['_source'].get('rule', {}).get('description', '?'),
                'level': h['_source'].get('rule', {}).get('level', 0),
            } for h in hits]})
    except Exception as e:
        return jsonify({'alerts': [], 'error': _sanitize_err(e)})
    return jsonify({'alerts': []})

@app.route('/agents')
@login_required
def agents_page():
    return render_template('agents.html')

@app.route('/policies')
@login_required
def policies_page():
    return render_template('policies.html')

@app.route('/somoagent')
@login_required
def somoagent_page():
    return render_template('somoagent.html')

@app.route('/agent.ps1')
def download_agent():
    """Serve the PowerShell agent script for easy deployment."""
    try:
        with open('/app/SomTechs-Agent.ps1', 'r') as f:
            content = f.read()
    except:
        return "# Agent script not found", 404
    resp = app.response_class(content, mimetype='text/plain')
    resp.headers['Content-Disposition'] = 'attachment; filename=SomTechs-Agent.ps1'
    return resp

@app.route('/scripts/<path:filename>')
def download_script(filename):
    """Serve deployment scripts. No auth required so endpoints can pull during setup."""
    safe_names = {
        'GCF-Deploy-Endpoint.ps1':        ('/app/GCF-Deploy-Endpoint.ps1',            'text/plain'),
        'SomTechs-Agent.ps1':             ('/app/SomTechs-Agent.ps1',                 'text/plain'),
        'GCF-Deploy-NewMachine.ps1':      ('/app/GCF-Deploy-NewMachine.ps1',          'text/plain'),
        'orbit-windows.msi':              ('/app/orbit-windows.msi',                  'application/octet-stream'),
        'SomTechs-Deploy.ps1':            ('/app/static/scripts/SomTechs-Deploy.ps1', 'text/plain'),
        'OpenUEM-Deploy.ps1':             ('/app/static/scripts/OpenUEM-Deploy.ps1',  'text/plain'),
        'openuem/ca.cer':                 ('/app/static/scripts/openuem/ca.cer',      'application/x-x509-ca-cert'),
        'openuem/agent.cer':              ('/app/static/scripts/openuem/agent.cer',   'application/x-x509-user-cert'),
        'openuem/agent.key':              ('/app/static/scripts/openuem/agent.key',   'application/octet-stream'),
        'openuem/sftp.cer':               ('/app/static/scripts/openuem/sftp.cer',    'application/x-x509-user-cert'),
    }
    entry = safe_names.get(filename)
    if not entry:
        return "# Script not found", 404
    filepath, mimetype = entry
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
    except:
        return "# Script not found", 404
    resp = app.response_class(content, mimetype=mimetype)
    resp.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return resp

@app.route('/api/ticker')
@login_required
def ticker():
    """
    Returns a list of ticker items for the SOC front page strip.
    Pulls from: Wazuh alerts (level 10+), offline agents, CrowdSec bans, RMM dark agents.
    """
    items = []

    # --- Wazuh recent critical/high alerts (last 2 hours, via indexer) ---
    try:
        query = {
            'size': 10,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {'bool': {'must': [
                {'range': {'rule.level': {'gte': 10}}},
                {'range': {'@timestamp': {'gte': 'now-2h'}}}
            ]}}
        }
        r = requests.post(f'{WAZUH_URL}/wazuh-alerts-4.x-*/_search',
                          auth=(WAZUH_USER, WAZUH_PASS), json=query,
                          verify=WAZUH_CA, timeout=8)
        hits = r.json().get('hits', {}).get('hits', [])
        for h in hits:
            s = h['_source']
            level = s.get('rule', {}).get('level', 0)
            desc  = s.get('rule', {}).get('description', 'Unknown rule')
            agent = s.get('agent', {}).get('name', '?')
            sev   = 'CRITICAL' if level >= 12 else 'HIGH'
            color = 'red' if level >= 12 else 'amber'
            items.append({'type': 'alert', 'sev': sev, 'color': color,
                          'text': f'{desc} | {agent}', 'level': level})
    except Exception as e:
        items.append({'type': 'sys', 'color': 'muted', 'text': f'Wazuh: {e}', 'sev': 'INFO'})

    # --- Wazuh disconnected agents ---
    try:
        token = _wazuh_token()
        headers = {'Authorization': f'Bearer {token}'}
        r = requests.get(f'{WAZUH_API_URL}/agents',
                         params={'status': 'disconnected', 'limit': 10},
                         headers=headers, verify=WAZUH_API_CA, timeout=8)
        disc = r.json().get('data', {}).get('affected_items', [])
        for a in disc:
            items.append({'type': 'agent', 'sev': 'WARN', 'color': 'amber',
                          'text': f'AGENT OFFLINE: {a["name"]} | last seen {a.get("lastKeepAlive","?")}',
                          'level': 0})
    except:
        pass

    # --- CrowdSec active decisions (bans) ---
    try:
        r = requests.get(f'{CROWDSEC_URL}/v1/decisions',
                         headers={'X-Api-Key': CROWDSEC_API_KEY}, timeout=6)
        decisions = r.json() or []
        if isinstance(decisions, list) and decisions:
            ban_count = len(decisions)
            recent = decisions[:3]
            for d in recent:
                items.append({'type': 'crowdsec', 'sev': 'BLOCK', 'color': 'red',
                              'text': f'BLOCKED: {d.get("value","?")} ({d.get("scenario","?")})',
                              'level': 0})
            if ban_count > 3:
                items.append({'type': 'crowdsec', 'sev': 'BLOCK', 'color': 'blue',
                              'text': f'CROWDSEC: {ban_count} total IPs currently blocked', 'level': 0})
    except:
        pass

    # --- RMM agents gone dark (no beacon > 10 min) ---
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute("SELECT hostname, last_seen, client FROM agents")
        rows = c.fetchall()
        conn.close()
        from datetime import timezone
        now = datetime.utcnow()
        for hostname, last_seen, client in rows:
            if not last_seen:
                continue
            try:
                ls = datetime.fromisoformat(last_seen)
                age_min = (now - ls).total_seconds() / 60
                if age_min > 10:
                    client_tag = f' [{client}]' if client else ''
                    items.append({'type': 'rmm', 'sev': 'WARN', 'color': 'amber',
                                  'text': f'RMM DARK: {hostname}{client_tag} | {int(age_min)}m since last beacon',
                                  'level': 0})
            except:
                pass
    except:
        pass

    # Sort: critical first, then high, then warn
    order = {'CRITICAL': 0, 'BLOCK': 1, 'HIGH': 2, 'WARN': 3, 'INFO': 4}
    items.sort(key=lambda x: (order.get(x['sev'], 5), -x.get('level', 0)))

    # Always add a "system healthy" item if nothing critical
    if not any(i['color'] == 'red' for i in items):
        items.append({'type': 'sys', 'sev': 'OK', 'color': 'green',
                      'text': 'ALL SYSTEMS NOMINAL | No critical alerts detected', 'level': 0})

    return jsonify(items)

@app.route('/api/stats')
@login_required
def api_stats():
    """
    Returns analytics data for the dashboard:
    - 24h alert timeline (hourly buckets)
    - Top 8 alert rules by count
    - Top 8 agents by alert count
    - Top CrowdSec scenarios
    - Auth failures vs successes
    """
    out = {'timeline': [], 'top_rules': [], 'top_agents': [], 'top_scenarios': [], 'auth': {}}

    # --- Wazuh: 24h hourly timeline + top rules + top agents ---
    try:
        query = {
            'size': 0,
            'query': {'range': {'@timestamp': {'gte': 'now-24h'}}},
            'aggs': {
                'by_hour': {
                    'date_histogram': {
                        'field': '@timestamp',
                        'calendar_interval': 'hour',
                        'min_doc_count': 0,
                        'extended_bounds': {'min': 'now-24h', 'max': 'now'}
                    },
                    'aggs': {
                        'high': {'filter': {'range': {'rule.level': {'gte': 12}}}},
                        'med':  {'filter': {'range': {'rule.level': {'gte': 7, 'lt': 12}}}}
                    }
                },
                'top_rules': {
                    'terms': {'field': 'rule.description', 'size': 8}
                },
                'top_agents': {
                    'terms': {'field': 'agent.name', 'size': 8}
                },
                'auth_fail': {
                    'filter': {'terms': {'rule.groups': ['authentication_failure', 'authentication_failed']}}
                },
                'auth_ok': {
                    'filter': {'terms': {'rule.groups': ['authentication_success']}}
                }
            }
        }
        r = requests.post(f'{WAZUH_URL}/wazuh-alerts-4.x-*/_search',
                          auth=(WAZUH_USER, WAZUH_PASS), json=query,
                          verify=WAZUH_CA, timeout=10)
        if r.status_code == 200:
            aggs = r.json().get('aggregations', {})
            buckets = aggs.get('by_hour', {}).get('buckets', [])
            out['timeline'] = [{'ts': b['key_as_string'], 'total': b['doc_count'],
                                 'high': b['high']['doc_count'], 'med': b['med']['doc_count']} for b in buckets]
            out['top_rules'] = [{'rule': b['key'], 'count': b['doc_count']}
                                 for b in aggs.get('top_rules', {}).get('buckets', [])]
            out['top_agents'] = [{'agent': b['key'], 'count': b['doc_count']}
                                  for b in aggs.get('top_agents', {}).get('buckets', [])]
            out['auth'] = {
                'fail': aggs.get('auth_fail', {}).get('doc_count', 0),
                'ok':   aggs.get('auth_ok', {}).get('doc_count', 0)
            }
    except Exception as e:
        out['error_wazuh'] = _sanitize_err(e)

    # --- Recent auth events with IP/hostname ---
    try:
        auth_q = {
            'size': 8,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': 'now-24h'}}},
                {'bool': {'should': [
                    {'terms': {'rule.groups': ['authentication_failure','authentication_failed','authentication_success']}},
                ]}}
            ]}}
        }
        r2 = requests.post(f'{WAZUH_URL}/wazuh-alerts-4.x-*/_search',
                           auth=(WAZUH_USER, WAZUH_PASS), json=auth_q,
                           verify=WAZUH_CA, timeout=8)
        if r2.status_code == 200:
            recent = []
            for h in r2.json().get('hits', {}).get('hits', []):
                s = h['_source']
                groups = s.get('rule', {}).get('groups', [])
                success = 'authentication_success' in groups
                srcip = (s.get('data', {}).get('srcip') or
                         s.get('data', {}).get('src_ip') or
                         s.get('data', {}).get('win', {}).get('eventdata', {}).get('ipAddress') or '')
                user = (s.get('data', {}).get('dstuser') or
                        s.get('data', {}).get('win', {}).get('eventdata', {}).get('targetUserName') or
                        s.get('data', {}).get('user') or '')
                recent.append({
                    'ts':      s.get('@timestamp', ''),
                    'agent':   s.get('agent', {}).get('name', '?'),
                    'user':    user,
                    'srcip':   srcip,
                    'success': success,
                    'rule':    s.get('rule', {}).get('description', '')[:50],
                })
            out['auth']['recent'] = recent
    except Exception:
        pass

    # --- CrowdSec: top scenarios ---
    try:
        r = requests.get(f'{CROWDSEC_URL}/v1/decisions',
                         headers={'X-Api-Key': CROWDSEC_API_KEY}, timeout=6)
        decisions = r.json() or []
        if isinstance(decisions, list):
            from collections import Counter
            scenario_counts = Counter(d.get('scenario', 'unknown') for d in decisions)
            out['top_scenarios'] = [{'scenario': k, 'count': v}
                                     for k, v in scenario_counts.most_common(8)]
            out['total_blocked'] = len(decisions)
    except Exception as e:
        out['error_cs'] = _sanitize_err(e)

    return jsonify(out)

def _wazuh_token():
    """Get a short-lived Wazuh API JWT token."""
    r = requests.get(f'{WAZUH_API_URL}/security/user/authenticate',
                     auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=WAZUH_API_CA, timeout=10)
    r.raise_for_status()
    return r.json()['data']['token']

@app.route('/api/onboard/provision', methods=['POST'])
def onboard_provision():
    """
    Called by SomTechs-Deploy.ps1 at install time.
    Creates a Wazuh group for the customer if it doesn't already exist.
    Requires AGENT_SECRET for auth.
    Body: { "secret": "...", "customer": "ACME" }
    Returns: { "status": "created"|"exists", "group": "ACME" }
    """
    d = request.json or {}
    if d.get('secret') != AGENT_SECRET:
        return jsonify({'error': 'unauthorized'}), 403

    raw = d.get('customer', '').strip()
    if not raw:
        return jsonify({'error': 'customer name required'}), 400

    # Sanitize: uppercase, alphanumeric + hyphens only, max 32 chars
    import re
    group = re.sub(r'[^A-Za-z0-9\-]', '', raw.replace(' ', '-'))[:32].upper()
    if not group:
        return jsonify({'error': 'invalid customer name'}), 400

    try:
        token = _wazuh_token()
        headers = {'Authorization': f'Bearer {token}'}

        # Check if group already exists
        resp = requests.get(f'{WAZUH_API_URL}/groups',
                            params={'search': group}, headers=headers,
                            verify=WAZUH_API_CA, timeout=10)
        existing = [g['name'] for g in resp.json().get('data', {}).get('affected_items', [])]

        if group in existing:
            return jsonify({'status': 'exists', 'group': group})

        # Create the group
        r = requests.post(f'{WAZUH_API_URL}/groups',
                          json={'group_id': group}, headers=headers,
                          verify=WAZUH_API_CA, timeout=10)
        r.raise_for_status()
        app.logger.info(f'Wazuh group created: {group}')
        return jsonify({'status': 'created', 'group': group}), 201

    except Exception as e:
        app.logger.error(f'onboard_provision error: {e}')
        return jsonify({'error': _sanitize_err(e)}), 500

RESTIC_REG_SECRET  = _require_env('RESTIC_REG_SECRET')
RESTIC_HTPASSWD    = "/app/restic-config/htpasswd"
RESTIC_CLIENT_PASS = _require_env('RESTIC_CLIENT_PASS')  # legacy fallback for pre-migration repos
RESTIC_MASTER_KEY  = _require_env('RESTIC_MASTER_KEY')
_fernet            = Fernet(RESTIC_MASTER_KEY.encode())

def _fernet_enc(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode()).decode()

def _fernet_dec(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()

def _restic_creds(hostname: str):
    """Return (rest_password, repo_password) for a client, or (None, None) if not in DB."""
    conn = db_conn()
    try:
        row = conn.execute(
            'SELECT rest_password_enc, repo_password_enc FROM restic_clients WHERE hostname=?',
            (hostname,)
        ).fetchone()
        if not row:
            return None, None
        return _fernet_dec(row[0]), _fernet_dec(row[1])
    finally:
        conn.close()

@app.route('/api/restic/register', methods=['POST'])
def restic_register():
    """Register or re-issue credentials for a Restic client.
    Returns unique per-client rest_password and repo_password every time —
    clients store them with DPAPI; server stores them Fernet-encrypted in DB.
    """
    import bcrypt, re

    data = request.get_json(silent=True) or {}
    if data.get('secret') != RESTIC_REG_SECRET:
        return jsonify({'error': 'unauthorized'}), 401

    hostname = data.get('hostname', '').lower().strip()
    if not hostname or not re.match(r'^[a-z0-9\-]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400

    conn = db_conn()
    try:
        # If already in DB, return existing credentials so clients can re-run fix script
        row = conn.execute(
            'SELECT rest_password_enc, repo_password_enc FROM restic_clients WHERE hostname=?',
            (hostname,)
        ).fetchone()
        if row:
            rest_pass = _fernet_dec(row[0])
            repo_pass = _fernet_dec(row[1])
            app.logger.info(f'Restic re-issue credentials: {hostname}')
            return jsonify({
                'status': 'exists',
                'hostname': hostname,
                'rest_password': rest_pass,
                'repo_password': repo_pass,
            }), 200

        # Generate unique per-client passwords
        rest_pass = secrets.token_urlsafe(32)
        repo_pass = secrets.token_urlsafe(32)

        # Store Fernet-encrypted in DB
        conn.execute(
            'INSERT OR REPLACE INTO restic_clients (hostname, rest_password_enc, repo_password_enc) VALUES (?,?,?)',
            (hostname, _fernet_enc(rest_pass), _fernet_enc(repo_pass))
        )
        conn.commit()

        # Write bcrypt hash of rest_password to htpasswd (replace existing entry if present)
        try:
            with open(RESTIC_HTPASSWD, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            lines = []

        lines = [l for l in lines if not l.startswith(f'{hostname}:')]
        hashed = bcrypt.hashpw(rest_pass.encode(), bcrypt.gensalt()).decode()
        lines.append(f'{hostname}:{hashed}\n')
        with open(RESTIC_HTPASSWD, 'w') as f:
            f.writelines(lines)

        app.logger.info(f'Restic client registered with unique credentials: {hostname}')
        return jsonify({
            'status': 'registered',
            'hostname': hostname,
            'rest_password': rest_pass,
            'repo_password': repo_pass,
        }), 201
    finally:
        conn.close()


@app.route('/api/restic/mycreds', methods=['POST'])
def restic_mycreds():
    """
    Agent calls this with its agent secret to get its own restic credentials.
    Credentials never travel in command text — agent fetches them securely over HTTPS.
    POST body: { "secret": "<AGENT_SECRET>", "hostname": "<COMPUTERNAME>" }
    """
    import re
    data = request.json or {}
    secret  = data.get('secret', '').strip()
    hostname = data.get('hostname', '').strip().lower()

    if not secret or not hostname:
        return jsonify({'error': 'secret and hostname required'}), 400
    if secret != AGENT_SECRET:
        return jsonify({'error': 'unauthorized'}), 401
    if not re.match(r'^[a-z0-9\-_]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400

    conn = db_conn()
    try:
        row = conn.execute(
            'SELECT rest_password_enc, repo_password_enc FROM restic_clients WHERE hostname=?',
            (hostname,)
        ).fetchone()
        if not row:
            return jsonify({'error': 'not registered — run onboarding first'}), 404
        from cryptography.fernet import Fernet as _Fernet
        _f = _Fernet(RESTIC_MASTER_KEY.encode())
        rest_pass = _f.decrypt(row[0].encode()).decode()
        repo_pass = _f.decrypt(row[1].encode()).decode()
        return jsonify({
            'rest_password': rest_pass,
            'repo_password': repo_pass,
            'repo_url': f'rest:https://{hostname}:{rest_pass}@backup.somotechs.com/{hostname}/',
        })
    finally:
        conn.close()


RESTIC_DATA_DIR = "/app/restic-data"

def _restic_snapshots(hostname):
    """Run restic snapshots --json for a client repo. Returns list or raises."""
    import subprocess, re
    if not re.match(r'^[a-z0-9\-]+$', hostname):
        raise ValueError('invalid hostname')
    repo = f"{RESTIC_DATA_DIR}/{hostname}"
    # Use per-client repo password from DB; fall back to shared legacy password
    _, repo_pass = _restic_creds(hostname)
    password = repo_pass if repo_pass else RESTIC_CLIENT_PASS
    env = {**os.environ, 'RESTIC_PASSWORD': password}
    result = subprocess.run(
        ['restic', '--repo', repo, '--no-lock', 'snapshots', '--json'],
        capture_output=True, text=True, timeout=15, env=env
    )
    if result.returncode == 0:
        return json.loads(result.stdout) or []
    if 'no such file' in result.stderr.lower() or 'does not exist' in result.stderr.lower():
        return None  # no repo yet
    raise RuntimeError(result.stderr.strip())

def _snap_status(last_backup_iso):
    from datetime import timezone
    try:
        t = datetime.fromisoformat(last_backup_iso.replace('Z', '+00:00'))
        age_hours = (datetime.now(timezone.utc) - t).total_seconds() / 3600
        if age_hours < 26:
            return 'ok'
        elif age_hours < 72:
            return 'warning'
        return 'stale'
    except Exception:
        return 'ok'

@app.route('/backups')
@login_required
def backups():
    return render_template('backups.html')

@app.route('/api/restic/clients')
@login_required
def restic_clients():
    """Return all registered clients with their latest snapshot info."""
    try:
        with open(RESTIC_HTPASSWD, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    # Build set of online RMM agent hostnames (seen in last 5 min)
    online_agents = set()
    try:
        from datetime import timezone
        conn2 = db_conn()
        c2 = conn2.cursor()
        c2.execute("SELECT hostname, last_seen FROM agents")
        for ah, als in c2.fetchall():
            try:
                age = (datetime.utcnow() - datetime.fromisoformat(als)).total_seconds()
                if age < 300:
                    online_agents.add(ah.lower())
            except Exception:
                pass
        conn2.close()
    except Exception:
        pass

    clients = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        hostname = line.split(':')[0]
        info = {'hostname': hostname, 'status': 'unknown', 'last_backup': None,
                'snapshot_count': 0, 'agent_online': hostname.lower() in online_agents}
        try:
            snaps = _restic_snapshots(hostname)
            if snaps is None:
                info['status'] = 'no-repo'
            elif not snaps:
                info['status'] = 'never'
            else:
                snaps_sorted = sorted(snaps, key=lambda s: s.get('time', ''))
                latest = snaps_sorted[-1]
                info['snapshot_count'] = len(snaps)
                info['last_backup'] = latest.get('time', '')
                info['status'] = _snap_status(info['last_backup'])
        except Exception as e:
            info['status'] = 'error'
            app.logger.warning(f'restic query failed for {hostname}: {e}')
        clients.append(info)

    return jsonify(clients)

@app.route('/api/restic/snapshots/<hostname>')
@login_required
def restic_snapshots(hostname):
    """Return full snapshot list for a single client."""
    try:
        snaps = _restic_snapshots(hostname)
        if snaps is None:
            return jsonify([])
        snaps.sort(key=lambda s: s.get('time', ''), reverse=True)
        return jsonify(snaps)
    except ValueError as e:
        return jsonify({'error': _sanitize_err(e)}), 400
    except Exception as e:
        return jsonify({'error': _sanitize_err(e)}), 500

@app.route('/api/restic/clients/<hostname>', methods=['DELETE'])
@login_required
def restic_delete_client(hostname):
    """Remove a client from htpasswd (unregister)."""
    import re
    if not re.match(r'^[a-z0-9\-]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400
    try:
        with open(RESTIC_HTPASSWD, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return jsonify({'error': 'not found'}), 404
    new_lines = [l for l in lines if not l.startswith(f'{hostname}:')]
    if len(new_lines) == len(lines):
        return jsonify({'error': 'not found'}), 404
    with open(RESTIC_HTPASSWD, 'w') as f:
        f.writelines(new_lines)
    return jsonify({'status': 'removed', 'hostname': hostname})


RESTORE_DIR = '/app/data/restores'

@app.route('/api/restic/ls/<hostname>/<snap_id>')
@login_required
def restic_ls(hostname, snap_id):
    """List files in a snapshot at a given path."""
    import subprocess, re
    if not re.match(r'^[a-z0-9\-]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400
    if not re.match(r'^[a-f0-9]+$', snap_id):
        return jsonify({'error': 'invalid snapshot id'}), 400
    path = request.args.get('path', '/')
    repo = f"{RESTIC_DATA_DIR}/{hostname}"
    _, repo_pass = _restic_creds(hostname)
    env = {**os.environ, 'RESTIC_PASSWORD': repo_pass if repo_pass else RESTIC_CLIENT_PASS}
    try:
        result = subprocess.run(
            ['restic', '--repo', repo, '--no-lock', 'ls', '--json', snap_id, path],
            capture_output=True, text=True, timeout=30, env=env
        )
        if result.returncode != 0:
            return jsonify({'error': result.stderr.strip()}), 500
        entries = []
        seen = set()
        path = path.rstrip('/') or '/'
        for line in result.stdout.strip().splitlines():
            try:
                node = json.loads(line)
            except Exception:
                continue
            if node.get('struct_type') == 'snapshot':
                continue
            npath = node.get('path', '')
            # Only show direct children of the requested path
            rel = npath[len(path):].lstrip('/') if npath.startswith(path) else None
            if rel is None or rel == '' or '/' in rel.rstrip('/'):
                continue
            if npath in seen:
                continue
            seen.add(npath)
            entries.append({
                'name': node.get('name', rel),
                'path': npath,
                'type': node.get('type', 'file'),
                'size': node.get('size', 0),
                'mtime': node.get('mtime', ''),
            })
        entries.sort(key=lambda e: (e['type'] != 'dir', e['name'].lower()))
        return jsonify(entries)
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'timed out'}), 504
    except Exception as e:
        return jsonify({'error': _sanitize_err(e)}), 500


@app.route('/api/restic/restore/<hostname>/<snap_id>', methods=['POST'])
@login_required
def restic_restore(hostname, snap_id):
    """Restore a path from a snapshot and return a download token."""
    import subprocess, re, shutil, threading
    if not re.match(r'^[a-z0-9\-]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400
    if not re.match(r'^[a-f0-9]+$', snap_id):
        return jsonify({'error': 'invalid snapshot id'}), 400
    restore_path = request.json.get('path', '/') if request.json else '/'
    repo = f"{RESTIC_DATA_DIR}/{hostname}"
    _, repo_pass = _restic_creds(hostname)
    env = {**os.environ, 'RESTIC_PASSWORD': repo_pass if repo_pass else RESTIC_CLIENT_PASS}
    token = secrets.token_hex(16)
    target = os.path.join(RESTORE_DIR, token)
    os.makedirs(target, exist_ok=True)
    try:
        result = subprocess.run(
            ['restic', '--repo', repo, '--no-lock', 'restore', snap_id,
             '--target', target, '--include', restore_path],
            capture_output=True, text=True, timeout=120, env=env
        )
        if result.returncode != 0:
            shutil.rmtree(target, ignore_errors=True)
            return jsonify({'error': result.stderr.strip()}), 500
        # Auto-cleanup after 10 minutes
        def _cleanup():
            import time; time.sleep(600)
            shutil.rmtree(target, ignore_errors=True)
        threading.Thread(target=_cleanup, daemon=True).start()
        return jsonify({'token': token, 'path': restore_path})
    except subprocess.TimeoutExpired:
        shutil.rmtree(target, ignore_errors=True)
        return jsonify({'error': 'restore timed out (>2 min)'}), 504
    except Exception as e:
        shutil.rmtree(target, ignore_errors=True)
        return jsonify({'error': _sanitize_err(e)}), 500


@app.route('/api/restic/download/<token>')
@login_required
def restic_download(token):
    """Zip and stream a completed restore."""
    import re, shutil, io, zipfile
    if not re.match(r'^[a-f0-9]+$', token):
        return jsonify({'error': 'invalid token'}), 400
    target = os.path.join(RESTORE_DIR, token)
    if not os.path.exists(target):
        return jsonify({'error': 'restore not found or expired'}), 404
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(target):
            for fname in files:
                fpath = os.path.join(root, fname)
                arcname = os.path.relpath(fpath, target)
                zf.write(fpath, arcname)
    buf.seek(0)
    shutil.rmtree(target, ignore_errors=True)
    from flask import send_file
    return send_file(buf, mimetype='application/zip',
                     as_attachment=True, download_name='restore.zip')


@app.route('/api/backup/extrapaths/<hostname>', methods=['GET', 'POST'])
@login_required
def backup_extra_paths(hostname):
    """Get or set extra backup paths for a client."""
    import re
    if not re.match(r'^[a-zA-Z0-9\-_]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400
    conn = db_conn()
    if request.method == 'GET':
        row = conn.execute('SELECT extra_paths FROM restic_clients WHERE hostname=?', (hostname.lower(),)).fetchone()
        conn.close()
        paths = row[0] if row and row[0] else ''
        return jsonify({'hostname': hostname, 'extra_paths': paths})
    # POST — update extra paths
    data = request.json or {}
    paths = data.get('extra_paths', '').strip()
    # Validate each path looks like a Windows drive/path
    if paths:
        for p in paths.split(','):
            p = p.strip()
            if p and not re.match(r'^[A-Za-z]:\\', p):
                conn.close()
                return jsonify({'error': f'Invalid path format: {p} — must be Windows path like D:\\ or E:\\SQLData'}), 400
    conn.execute('UPDATE restic_clients SET extra_paths=? WHERE hostname=?', (paths, hostname.lower()))
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'hostname': hostname, 'extra_paths': paths})


@app.route('/api/backup/trigger/<hostname>', methods=['POST'])
@login_required
def backup_trigger(hostname):
    """Queue an on-demand backup command to the matching RMM agent."""
    import re
    if not re.match(r'^[a-zA-Z0-9\-_]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400

    # Find matching RMM agent by hostname (case-insensitive)
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, hostname, last_seen FROM agents ORDER BY last_seen DESC")
    agents = c.fetchall()
    conn.close()

    agent_row = None
    for row in agents:
        if row[1].lower() == hostname.lower():
            agent_row = row
            break

    if not agent_row:
        return jsonify({'error': f'No RMM agent found for hostname "{hostname}". Machine must be online with SoMo agent installed.'}), 404

    # Check if agent is online (seen in last 5 min)
    try:
        from datetime import timezone
        last = datetime.fromisoformat(agent_row[2])
        age = (datetime.utcnow() - last).total_seconds()
        if age > 300:
            return jsonify({'error': f'Agent "{hostname}" appears offline (last seen {int(age//60)}m ago). Cannot trigger backup.'}), 503
    except Exception:
        pass

    # Load credentials + extra paths for this client
    extra_paths_str = ''
    db_rest_pass = None
    db_repo_pass = None
    try:
        from cryptography.fernet import Fernet as _Fernet
        _f = _Fernet(RESTIC_MASTER_KEY.encode())
        cred_row = db_conn().execute(
            'SELECT rest_password_enc, repo_password_enc, extra_paths FROM restic_clients WHERE hostname=?',
            (hostname.lower(),)
        ).fetchone()
        if cred_row:
            db_rest_pass = _f.decrypt(cred_row[0].encode()).decode()
            db_repo_pass = _f.decrypt(cred_row[1].encode()).decode()
            extra_paths_str = cred_row[2] or ''
    except Exception:
        pass
    extra_drives = [p.strip() for p in extra_paths_str.split(',') if p.strip()] if extra_paths_str else []
    use_vss = len(extra_drives) > 0

    # Build extra drives PS snippet
    if extra_drives:
        extra_ps = ''.join(
            f'  if (Test-Path "{d}") {{ $dirs += "{d}" }} else {{ Write-Output "[WARN] Extra path not found: {d}" }}; '
            for d in extra_drives
        )
        vss_flag = ' --use-fs-snapshot'
    else:
        extra_ps = ''
        vss_flag = ''

    # Queue backup command — agent fetches its own credentials securely (no secrets in command text)
    cred_prefix = (
        '$resticBin = "C:\\ProgramData\\restic\\restic.exe"; '
        '$passFile  = "C:\\ProgramData\\restic\\repo.key"; '
        '$cacheDir  = "C:\\ProgramData\\restic\\cache"; '
        '$repoUser  = $env:COMPUTERNAME.ToLower(); '
        '$credsJson = try { Invoke-RestMethod -Uri "https://soc.somotechs.com/api/restic/mycreds" '
        '-Method POST -ContentType "application/json" '
        f'-Body (\'{{\"secret\":\"{AGENT_SECRET}\",\"hostname\":\"\' + $repoUser + \'\"}}\')'
        ' -ErrorAction Stop } catch { $null }; '
        'if ($credsJson -and $credsJson.repo_password) { '
        '  Set-Content -Path $passFile -Value $credsJson.repo_password -NoNewline; '
        '  $repoUrl = $credsJson.repo_url; '
        '} else { '
        '  $repoPass = (Get-Content $passFile -Raw -ErrorAction SilentlyContinue).Trim(); '
        '  $repoUrl = "rest:https://${repoUser}:${repoPass}@backup.somotechs.com/${repoUser}/"; '
        '  Write-Output "[WARN] Could not fetch creds from SOC — using local key file"; '
        '}; '
    )

    backup_cmd = (
        cred_prefix
        # Try scheduled task first (only if no extra paths — task may not know about them)
        + (
        '$task = Get-ScheduledTask -TaskName "ResticBackup" -ErrorAction SilentlyContinue; '
        'if (-not $task) { $task = Get-ScheduledTask -TaskName "SomTechsBackup" -ErrorAction SilentlyContinue }; '
        'if ($task) { '
        '  Start-ScheduledTask -TaskName $task.TaskName; '
        '  Start-Sleep -Seconds 5; '
        '  $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue; '
        '  Write-Output "[OK] Scheduled task $($task.TaskName) started. Last run: $($info.LastRunTime) | Result: $($info.LastTaskResult)"; '
        '} elseif (Test-Path $resticBin) { '
        if not use_vss else
        'if (Test-Path $resticBin) { '
        )
        + '  Write-Output "[FALLBACK] Running restic directly..."; '
        '  $env:RESTIC_PASSWORD_FILE = $passFile; '
        '  $env:RESTIC_CACHE_DIR = $cacheDir; '
        '  $dirs = @(); '
        '  Get-ChildItem C:\\Users -Directory -ErrorAction SilentlyContinue | '
        '    Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") } | '
        '    ForEach-Object { foreach ($s in @("Desktop","Documents","Downloads","Pictures","Favorites","AppData\\Roaming")) { '
        '      $p = Join-Path $_.FullName $s; if (Test-Path $p) { $dirs += $p } } }; '
        + extra_ps +
        f'  $result = & $resticBin -r $repoUrl --password-file $passFile backup --tag fullbackup{vss_flag} @dirs 2>&1; '
        '  $result | Select-Object -Last 8 | ForEach-Object { Write-Output $_ }; '
        '  if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3) { Write-Output "[OK] Backup complete (exit $LASTEXITCODE)" } '
        '  else { Write-Output "[ERROR] Backup failed (exit $LASTEXITCODE)" }; '
        '} else { '
        '  Write-Output "[ERROR] Restic not installed on this machine. Run the backup onboarding script first."; '
        '  Write-Output "  iex (Invoke-RestMethod https://soc.somotechs.com/static/scripts/Install-ResticBackup.ps1)"; '
        '}'
    )

    now = datetime.utcnow().isoformat()
    conn = db_conn()
    c = conn.cursor()
    c.execute("INSERT INTO commands (agent_id, command, status, created, cmd_type) VALUES (?, ?, 'pending', ?, 'backup')",
              (agent_row[0], backup_cmd, now))
    cmd_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'ok': True, 'cmd_id': cmd_id, 'agent_id': agent_row[0], 'hostname': agent_row[1]})


@app.route('/api/ai/evaluate')
@login_required
def api_ai_evaluate():
    """AI triage of recent high-severity alerts. Cached 3 min."""
    global _ai_eval_cache

    # Return cache if fresh
    if _ai_eval_cache['data'] and (time.time() - _ai_eval_cache['ts']) < _AI_CACHE_TTL:
        return jsonify(_ai_eval_cache['data'])

    if not ANTHROPIC_API_KEY:
        return jsonify({'enabled': False})

    # Pull last 20 high-severity alerts from the past 30 min
    query = {
        'size': 20,
        'sort': [{'@timestamp': {'order': 'desc'}}],
        'query': {'bool': {'must': [
            {'range': {'rule.level': {'gte': 10}}},
            {'range': {'@timestamp': {'gte': 'now-30m'}}}
        ]}}
    }
    try:
        r = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=8)
        hits = r.json().get('hits', {}).get('hits', []) if r.status_code == 200 else []
    except Exception:
        hits = []

    if not hits:
        result = {'enabled': True, 'needs_attention': False}
        _ai_eval_cache = {'ts': time.time(), 'data': result}
        return jsonify(result)

    # Build compact alert summary for Claude
    alert_lines = []
    for h in hits:
        s = h['_source']
        alert_lines.append(
            f"[L{s.get('rule',{}).get('level','?')}] {s.get('rule',{}).get('description','?')} "
            f"| agent={s.get('agent',{}).get('name','?')} "
            f"| src={s.get('data',{}).get('srcip','-')} "
            f"| groups={','.join(s.get('rule',{}).get('groups',[]))}"
        )
    alerts_text = '\n'.join(alert_lines)

    try:
        import anthropic as _anthropic
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        resp = client.messages.create(
            model='claude-haiku-4-5',
            max_tokens=300,
            system=(
                'You are a SOC analyst assistant. Analyze Wazuh security alerts and decide '
                'if a human analyst needs to be alerted immediately. '
                'Respond ONLY with a JSON object — no markdown, no explanation outside the JSON.'
            ),
            messages=[{'role': 'user', 'content': (
                f'Recent high-severity alerts (last 30 min):\n\n{alerts_text}\n\n'
                'Respond with this exact JSON:\n'
                '{"needs_attention":true/false,"severity":"critical|high|info",'
                '"title":"<60-char title>","summary":"<2 sentence explanation>"}\n\n'
                'Set needs_attention=true ONLY for: active brute-force success, lateral movement, '
                'privilege escalation, ransomware indicators, data exfiltration, or repeated '
                'critical hits on the same host. Routine auth failures = false.'
            )}]
        )
        raw = resp.content[0].text.strip()
        # Strip possible markdown fences
        if raw.startswith('```'):
            raw = raw.split('```')[1]
            if raw.startswith('json'):
                raw = raw[4:]
        data = json.loads(raw)
        result = {
            'enabled': True,
            'needs_attention': bool(data.get('needs_attention', False)),
            'severity':        data.get('severity', 'info'),
            'title':           data.get('title', 'Alert Triage Complete'),
            'summary':         data.get('summary', ''),
            'alert_count':     len(hits),
        }
    except Exception as e:
        result = {'enabled': True, 'needs_attention': False, 'error': _sanitize_err(e)}

    _ai_eval_cache = {'ts': time.time(), 'data': result}
    return jsonify(result)


_ai_login_cache = {'ts': 0, 'data': None}
_AI_LOGIN_CACHE_TTL = 300  # 5 min

_malware_cache = {'ts': 0, 'data': None}
_MALWARE_CACHE_TTL = 120  # 2 min

@app.route('/api/wazuh/malware')
@login_required
def api_wazuh_malware():
    """Recent malware events from Suricata, Windows Defender, and ClamAV via Wazuh rules 86600-86622."""
    global _malware_cache
    if _malware_cache['data'] and (time.time() - _malware_cache['ts']) < _MALWARE_CACHE_TTL:
        return jsonify(_malware_cache['data'])
    try:
        query = {
            'size': 50,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': 'now-24h'}}},
                {'terms': {'rule.id': [
                    '86600','86601','86602',                  # Suricata IDS
                    '86610','86611','86612','86613','86614',  # Windows Defender detections
                    '86620',                                  # ClamAV
                    '92900','92901','92902',                  # Lsass credential access (Sysmon)
                    '92043','92044','92045',                  # Netsh / firewall manipulation
                    '92050','92051','92052','92053',          # Suspicious process injection
                    '100310','100311','100312',               # Custom lateral movement rules
                    '110002','110003',                        # Rootkit detection
                ]}}
            ]}}
        }
        r = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=8)
        hits = r.json().get('hits', {}).get('hits', []) if r.status_code == 200 else []

        # Also get 24h total count per source
        agg_query = {
            'size': 0,
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': 'now-24h'}}},
                {'terms': {'rule.id': [
                    '86600','86601','86602','86610','86611','86612','86613','86614','86620',
                    '92900','92901','92902','92043','92044','92045','92050','92051','92052','92053',
                    '100310','100311','100312','110002','110003',
                ]}}
            ]}},
            'aggs': {'by_rule': {'terms': {'field': 'rule.id', 'size': 30}}}
        }
        ra = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=agg_query, verify=WAZUH_CA, timeout=8)
        buckets = ra.json().get('aggregations', {}).get('by_rule', {}).get('buckets', []) if ra.status_code == 200 else []

        suricata_ids  = {'86600','86601','86602'}
        defender_ids  = {'86610','86611','86612','86613','86614'}
        clamav_ids    = {'86620'}
        sysmon_ids    = {'92900','92901','92902','92050','92051','92052','92053'}
        lateral_ids   = {'100310','100311','100312'}
        firewall_ids  = {'92043','92044','92045'}
        rootkit_ids   = {'110002','110003'}
        suricata_count = sum(b['doc_count'] for b in buckets if b['key'] in suricata_ids)
        defender_count = sum(b['doc_count'] for b in buckets if b['key'] in defender_ids)
        clamav_count   = sum(b['doc_count'] for b in buckets if b['key'] in clamav_ids)
        sysmon_count   = sum(b['doc_count'] for b in buckets if b['key'] in sysmon_ids|lateral_ids|firewall_ids|rootkit_ids)
        total = suricata_count + defender_count + clamav_count + sysmon_count

        # Load dismissed alert IDs and active silences from DB
        _conn = sqlite3.connect(DB_PATH)
        try:
            dismissed_ids = {r[0] for r in _conn.execute('SELECT doc_id FROM dismissed_alerts').fetchall()}
            silence_rows  = _conn.execute(
                "SELECT rule_id, host FROM silenced_rules "
                "WHERE expires_at IS NULL OR expires_at > datetime('now')"
            ).fetchall()
        finally:
            _conn.close()
        # silenced_map: rule_id -> set of hosts (None means all hosts)
        silenced_map: dict = {}
        for sr_rule, sr_host in silence_rows:
            silenced_map.setdefault(sr_rule, set()).add(sr_host)

        def is_silenced(rule_id, host):
            hosts = silenced_map.get(rule_id)
            if hosts is None:
                return False
            return None in hosts or host in hosts

        # Known false positive signatures — flag but don't hide
        FP_SIGNATURES = [
            'MsMpEng.exe',   # Windows Defender accessing lsass — normal
            'MsSense.exe',   # Defender for Endpoint — normal
        ]

        def source_of(rule_id):
            if rule_id in suricata_ids:  return 'suricata'
            if rule_id in defender_ids:  return 'defender'
            if rule_id in sysmon_ids:    return 'sysmon'
            if rule_id in lateral_ids:   return 'lateral'
            if rule_id in firewall_ids:  return 'firewall'
            if rule_id in rootkit_ids:   return 'rootkit'
            return 'clamav'

        events = []
        for h in hits:
            s   = h['_source']
            src = h.get('_id', '')
            # Skip dismissed alerts
            if src in dismissed_ids:
                continue
            rule_id = str(s.get('rule', {}).get('id', ''))
            host_name = s.get('agent', {}).get('name', '')
            # Skip silenced rules
            if is_silenced(rule_id, host_name):
                continue
            data    = s.get('data', {})
            win     = data.get('win', {})
            wd      = win.get('eventdata', {})

            # Extract fields from Windows Defender, Suricata, ClamAV
            threat_name = (
                wd.get('threatName') or
                wd.get('name') or
                data.get('signature') or
                data.get('alert', {}).get('signature') if isinstance(data.get('alert'), dict) else None or
                s.get('rule', {}).get('description', '')
            )
            file_path = (
                wd.get('path') or
                wd.get('processName') or
                data.get('VirusEvent', {}).get('FileName') if isinstance(data.get('VirusEvent'), dict) else None or
                data.get('file') or ''
            )
            file_hash = (
                wd.get('sha256') or
                wd.get('sha1') or
                data.get('sha256') or
                data.get('md5') or ''
            )
            action = (
                wd.get('action') or
                wd.get('actionSuccess') or
                data.get('action') or ''
            )
            src_ip = (
                s.get('data', {}).get('srcip') or
                s.get('data', {}).get('src_ip') or
                (s.get('data', {}).get('alert', {}) or {}).get('src_ip') or ''
            )

            raw_str = json.dumps(s)
            likely_fp = any(fp in raw_str for fp in FP_SIGNATURES)

            events.append({
                'id':          src,
                'time':        s.get('@timestamp', ''),
                'source':      source_of(rule_id),
                'host':        s.get('agent', {}).get('name', '?'),
                'rule':        s.get('rule', {}).get('description', ''),
                'rule_id':     rule_id,
                'level':       s.get('rule', {}).get('level', 0),
                'threat_name': threat_name or 'Unknown',
                'file_path':   file_path,
                'file_hash':   file_hash,
                'action':      action,
                'src_ip':      src_ip,
                'likely_fp':   likely_fp,
                'raw':         s,
            })

        # Recount per-source from filtered events (excludes dismissed/silenced)
        active_src: dict = {}
        for ev in events:
            active_src[ev['source']] = active_src.get(ev['source'], 0) + 1

        result = {
            'total': len(events),  # active (post-dismiss/silence) count
            'raw_total': total,    # unfiltered 24h total for reference
            'suricata': active_src.get('suricata', 0),
            'defender': active_src.get('defender', 0),
            'clamav':   active_src.get('clamav', 0),
            'sysmon':   active_src.get('sysmon', 0) + active_src.get('lateral', 0)
                        + active_src.get('firewall', 0) + active_src.get('rootkit', 0),
            'recent': events,
        }
    except Exception as e:
        result = {'total': 0, 'suricata': 0, 'defender': 0, 'clamav': 0, 'recent': [], 'error': _sanitize_err(e)}
    _malware_cache = {'ts': time.time(), 'data': result}
    return jsonify(result)


@app.route('/api/malware/virustotal/<file_hash>')
@login_required
def api_virustotal_lookup(file_hash):
    """Look up a file hash on VirusTotal (no API key — uses public search)."""
    import re, hashlib
    file_hash = file_hash.strip().lower()
    if not re.match(r'^[a-f0-9]{32,64}$', file_hash):
        return jsonify({'error': 'invalid hash format'}), 400

    VT_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if VT_KEY:
        # Full API lookup with key
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={'x-apikey': VT_KEY}, timeout=10
            )
            if r.status_code == 200:
                d = r.json().get('data', {}).get('attributes', {})
                stats = d.get('last_analysis_stats', {})
                return jsonify({
                    'found': True,
                    'hash': file_hash,
                    'detections': stats.get('malicious', 0),
                    'total_engines': sum(stats.values()),
                    'threat_name': d.get('popular_threat_classification', {}).get('suggested_threat_label', ''),
                    'threat_category': d.get('popular_threat_classification', {}).get('popular_threat_category', []),
                    'file_type': d.get('type_description', ''),
                    'file_size': d.get('size', 0),
                    'first_seen': d.get('first_submission_date', ''),
                    'last_seen': d.get('last_analysis_date', ''),
                    'names': d.get('names', [])[:5],
                    'vt_link': f"https://www.virustotal.com/gui/file/{file_hash}",
                    'source': 'api',
                })
            elif r.status_code == 404:
                return jsonify({'found': False, 'hash': file_hash, 'vt_link': f"https://www.virustotal.com/gui/file/{file_hash}"})
        except Exception as e:
            pass

    # No API key — return link for manual lookup + check public community score
    return jsonify({
        'found': None,
        'hash': file_hash,
        'vt_link': f"https://www.virustotal.com/gui/file/{file_hash}",
        'source': 'link_only',
        'note': 'Add VIRUSTOTAL_API_KEY to .env for automated lookups',
    })


@app.route('/api/malware/detail/<doc_id>')
@login_required
def api_malware_detail(doc_id):
    """Full malware alert detail with enrichment — file hash VT lookup, raw alert, related events."""
    try:
        r = requests.get(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_doc/{doc_id}",
            auth=(WAZUH_USER, WAZUH_PASS), verify=WAZUH_CA, timeout=8)
        if r.status_code != 200:
            return jsonify({'error': 'alert not found'}), 404
        s = r.json().get('_source', {})
        data = s.get('data', {})
        win  = data.get('win', {})
        wd   = win.get('eventdata', {})

        file_hash = wd.get('sha256') or wd.get('sha1') or data.get('sha256') or data.get('md5') or ''
        file_path = wd.get('path') or wd.get('processName') or data.get('file') or ''
        threat_name = wd.get('threatName') or data.get('signature') or s.get('rule', {}).get('description', '')
        action = wd.get('action') or data.get('action') or ''

        # Get related events from same host ±30 min
        agent = s.get('agent', {}).get('name', '')
        ts = s.get('@timestamp', '')
        related = []
        if agent and ts:
            rq = {
                'size': 10,
                'sort': [{'@timestamp': {'order': 'desc'}}],
                'query': {'bool': {'must': [
                    {'term': {'agent.name': agent}},
                    {'range': {'@timestamp': {'gte': f'{ts}||-30m', 'lte': f'{ts}||+30m'}}}
                ], 'must_not': [{'ids': {'values': [doc_id]}}]}}
            }
            rr = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
                auth=(WAZUH_USER, WAZUH_PASS), json=rq, verify=WAZUH_CA, timeout=5)
            if rr.status_code == 200:
                for h in rr.json().get('hits', {}).get('hits', []):
                    hs = h['_source']
                    related.append({
                        'id': h['_id'],
                        'time': hs.get('@timestamp', ''),
                        'rule': hs.get('rule', {}).get('description', ''),
                        'level': hs.get('rule', {}).get('level', 0),
                    })

        return jsonify({
            'id': doc_id,
            'time': ts,
            'host': agent,
            'threat_name': threat_name,
            'file_path': file_path,
            'file_hash': file_hash,
            'action': action,
            'rule': s.get('rule', {}).get('description', ''),
            'rule_id': s.get('rule', {}).get('id', ''),
            'level': s.get('rule', {}).get('level', 0),
            'raw': s,
            'related': related,
            'vt_link': f"https://www.virustotal.com/gui/file/{file_hash}" if file_hash else '',
        })
    except Exception as e:
        return jsonify({'error': _sanitize_err(e)}), 500


@app.route('/api/malware/dismiss/<doc_id>', methods=['POST'])
@login_required
def api_malware_dismiss(doc_id):
    """Dismiss (mark as reviewed) a specific malware alert by Wazuh doc ID."""
    note = request.json.get('note', '') if request.is_json else ''
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('INSERT OR REPLACE INTO dismissed_alerts (doc_id, note) VALUES (?, ?)', (doc_id, note))
        conn.commit()
    finally:
        conn.close()
    _malware_cache['ts'] = 0  # bust cache so feed refreshes
    return jsonify({'ok': True, 'doc_id': doc_id})


@app.route('/api/malware/silence', methods=['POST'])
@login_required
def api_malware_silence():
    """Silence a rule for a duration. Body: {rule_id, host (optional), hours (0=permanent), note}."""
    data = request.json or {}
    rule_id = str(data.get('rule_id', '')).strip()
    host = str(data.get('host', '')).strip() or None
    hours = int(data.get('hours', 24))
    note = str(data.get('note', '')).strip()
    if not rule_id:
        return jsonify({'error': 'rule_id required'}), 400
    expires_at = None
    if hours > 0:
        from datetime import datetime, timedelta
        expires_at = (datetime.utcnow() + timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            'INSERT INTO silenced_rules (rule_id, host, expires_at, note) VALUES (?, ?, ?, ?)',
            (rule_id, host, expires_at, note)
        )
        silence_id = cur.lastrowid
        conn.commit()
    finally:
        conn.close()
    _malware_cache['ts'] = 0
    return jsonify({'ok': True, 'id': silence_id, 'rule_id': rule_id, 'host': host, 'expires_at': expires_at})


@app.route('/api/malware/silences', methods=['GET'])
@login_required
def api_malware_silences():
    """List active silences."""
    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute(
            "SELECT id, rule_id, host, expires_at, created_at, note FROM silenced_rules "
            "WHERE expires_at IS NULL OR expires_at > datetime('now') ORDER BY created_at DESC"
        ).fetchall()
    finally:
        conn.close()
    return jsonify([{'id': r[0], 'rule_id': r[1], 'host': r[2],
                     'expires_at': r[3], 'created_at': r[4], 'note': r[5]} for r in rows])


@app.route('/api/malware/silence/<int:silence_id>', methods=['DELETE'])
@login_required
def api_malware_silence_delete(silence_id):
    """Remove a silence rule."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('DELETE FROM silenced_rules WHERE id = ?', (silence_id,))
        conn.commit()
    finally:
        conn.close()
    _malware_cache['ts'] = 0
    return jsonify({'ok': True})


@app.route('/api/ai/login_investigation')
@login_required
def api_ai_login_investigation():
    """AI analysis of recent login events. Returns findings + recommended actions. Cached 5 min."""
    global _ai_login_cache
    if _ai_login_cache['data'] and (time.time() - _ai_login_cache['ts']) < _AI_LOGIN_CACHE_TTL:
        return jsonify(_ai_login_cache['data'])
    if not ANTHROPIC_API_KEY:
        return jsonify({'enabled': False})
    try:
        query = {
            'size': 60,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': 'now-24h'}}},
                {'terms': {'rule.id': ['100300','100301','100302','100303',
                                       '100304','100305','100306','100307',
                                       '100308','100309','100310']}}
            ]}}
        }
        r = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=8)
        hits = r.json().get('hits', {}).get('hits', []) if r.status_code == 200 else []
    except Exception:
        hits = []
    if not hits:
        result = {'enabled': True, 'threat': 'none', 'summary': 'No login events in the last 24 hours.',
                  'findings': [], 'actions': []}
        _ai_login_cache = {'ts': time.time(), 'data': result}
        return jsonify(result)
    lines = []
    for h in hits:
        s = h['_source']
        wd = s.get('data', {}).get('win', {}).get('eventdata', {}) or {}
        ws = s.get('data', {}).get('win', {}).get('system', {}) or {}
        lines.append(
            f"[{s.get('@timestamp','')[:16]}] {s.get('rule',{}).get('description','?')} "
            f"| host={s.get('agent',{}).get('name','?')} "
            f"| user={wd.get('targetUserName','-')} "
            f"| src={wd.get('ipAddress','-')} "
            f"| type={wd.get('logonType','-')} "
            f"| eventID={ws.get('eventID','-')}"
        )
    events_text = '\n'.join(lines)
    try:
        import anthropic as _anthropic
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        resp = client.messages.create(
            model='claude-haiku-4-5',
            max_tokens=500,
            system=(
                'You are a Windows security analyst reviewing login events from a managed IT environment. '
                'Identify suspicious patterns, anomalies, and recommend actionable fixes. '
                'Respond ONLY with a valid JSON object — no markdown, no text outside JSON.'
            ),
            messages=[{'role': 'user', 'content': (
                f'Windows login events from the last 24 hours:\n\n{events_text}\n\n'
                'Analyze these events and respond with this exact JSON (no markdown):\n'
                '{"threat":"none|low|medium|high","summary":"1-2 sentence overview",'
                '"findings":["finding 1","finding 2","finding 3"],'
                '"actions":["action 1","action 2","action 3"]}\n\n'
                'findings = specific observations (user accounts, IPs, patterns seen).\n'
                'actions = concrete steps an MSP tech should take.\n'
                'Keep each finding/action under 80 chars. Max 4 of each.'
            )}]
        )
        raw = resp.content[0].text.strip()
        if raw.startswith('```'):
            raw = raw.split('```')[1]
            if raw.startswith('json'):
                raw = raw[4:]
        data = json.loads(raw)
        result = {
            'enabled':  True,
            'threat':   data.get('threat', 'none'),
            'summary':  data.get('summary', ''),
            'findings': data.get('findings', [])[:4],
            'actions':  data.get('actions', [])[:4],
            'count':    len(hits),
        }
    except Exception as e:
        result = {'enabled': True, 'threat': 'none', 'error': _sanitize_err(e), 'findings': [], 'actions': []}
    _ai_login_cache = {'ts': time.time(), 'data': result}
    return jsonify(result)




@app.route('/api/agent/check', methods=['GET', 'POST'])
def agent_check():
    """
    Called by SomTechs-Deploy.ps1 to verify an agent phoned home to Wazuh.
    POST JSON: {"hostname": "MYPC", "secret": "..."} (preferred)
    GET query: ?hostname=MYPC&secret=... (legacy, still supported)
    Returns: { "connected": true|false, "status": "active"|"pending"|"never_connected"|"unknown" }
    """
    if request.method == 'POST':
        body = request.get_json(silent=True) or {}
        secret = body.get('secret', '')
        hostname = body.get('hostname', '').strip()
    else:
        secret = request.args.get('secret', '')
        hostname = request.args.get('hostname', '').strip()
    if secret != AGENT_SECRET:
        return jsonify({'error': 'unauthorized'}), 403
    if not hostname:
        return jsonify({'error': 'hostname required'}), 400
    try:
        token = get_wazuh_token()
        r = requests.get(
            f"{WAZUH_API_URL}/agents",
            params={'search': hostname, 'limit': 10},
            headers={'Authorization': f'Bearer {token}'},
            verify=WAZUH_API_CA, timeout=8
        )
        agents = r.json().get('data', {}).get('affected_items', [])
        match = next((a for a in agents if a.get('name', '').lower() == hostname.lower()), None)
        if not match:
            return jsonify({'connected': False, 'status': 'never_connected'})
        status = match.get('status', 'unknown')
        return jsonify({'connected': status == 'active', 'status': status, 'id': match.get('id')})
    except Exception as e:
        return jsonify({'connected': False, 'status': 'unknown', 'error': _sanitize_err(e)})




# ── Client Health / Onboarding Score ─────────────────────────────────────────

_client_health_cache = {'ts': 0, 'data': None}
_CLIENT_HEALTH_TTL = 60

@app.route('/api/health/clients')
@login_required
def api_health_clients():
    """Cross-reference beacon, Wazuh, and backups per client for onboarding score."""
    global _client_health_cache
    if _client_health_cache['data'] and (time.time() - _client_health_cache['ts']) < _CLIENT_HEALTH_TTL:
        return jsonify(_client_health_cache['data'])
    try:
        conn = db_conn()
        rows = conn.execute(
            "SELECT id, hostname, ip, cpu, ram, last_seen, client FROM agents ORDER BY client, hostname"
        ).fetchall()
        conn.close()

        try:
            token = get_wazuh_token()
            wr = requests.get(f"{WAZUH_API_URL}/agents",
                params={'limit': 500, 'status': 'active'},
                headers={'Authorization': f'Bearer {token}'},
                verify=WAZUH_API_CA, timeout=8)
            wazuh_active = {a.get('name','').lower()
                            for a in wr.json().get('data',{}).get('affected_items',[])}
        except Exception:
            wazuh_active = set()

        backup_status = {}
        try:
            with open(RESTIC_HTPASSWD) as f:
                for line in f:
                    h = line.strip().split(':')[0]
                    if not h:
                        continue
                    try:
                        snaps = _restic_snapshots(h)
                        if snaps:
                            latest = sorted(snaps, key=lambda s: s.get('time',''))[-1]
                            backup_status[h] = {
                                'status': _snap_status(latest.get('time','')),
                                'last': latest.get('time','')[:16].replace('T',' '),
                                'count': len(snaps),
                            }
                        else:
                            backup_status[h] = {'status': 'never', 'last': None, 'count': 0}
                    except Exception:
                        backup_status[h] = {'status': 'error', 'last': None, 'count': 0}
        except Exception:
            pass

        from collections import defaultdict
        by_client = defaultdict(list)
        now_ts = datetime.utcnow()
        for agent_id, hostname, ip, cpu, ram, last_seen, client in rows:
            try:
                age = (now_ts - datetime.fromisoformat(last_seen)).total_seconds()
                beacon_online = age < 300
            except Exception:
                beacon_online = False
            h = hostname.lower()
            bk = backup_status.get(h, backup_status.get(hostname, {}))
            by_client[client or 'Unknown'].append({
                'hostname': hostname,
                'ip': ip,
                'cpu': cpu,
                'ram': ram,
                'beacon_online': beacon_online,
                'wazuh': h in wazuh_active,
                'backup_status': bk.get('status', 'none'),
                'backup_last': bk.get('last'),
                'backup_count': bk.get('count', 0),
            })

        clients = []
        for name, machines in sorted(by_client.items()):
            total = len(machines)
            fully = sum(1 for m in machines
                        if m['beacon_online'] and m['wazuh'] and m['backup_status'] == 'ok')
            clients.append({
                'name': name,
                'total': total,
                'beacon_online': sum(1 for m in machines if m['beacon_online']),
                'wazuh_active':  sum(1 for m in machines if m['wazuh']),
                'backup_ok':     sum(1 for m in machines if m['backup_status'] == 'ok'),
                'score': round(fully / total * 100) if total else 0,
                'machines': machines,
            })

        result = {'clients': clients, 'ok': True}
    except Exception as e:
        result = {'clients': [], 'ok': False, 'error': _sanitize_err(e)}
    _client_health_cache = {'ts': time.time(), 'data': result}
    return jsonify(result)


# ── Proof-of-Value stats ──────────────────────────────────────────────────────

@app.route('/api/crowdsec/value')
@login_required
def api_crowdsec_value():
    """Return total bans + top scenarios for proof-of-value display."""
    try:
        hdrs = {'X-Api-Key': CROWDSEC_API_KEY}
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions?type=ban&limit=500",
                         headers=hdrs, timeout=8)
        decisions = r.json() if r.status_code == 200 and r.text.strip() not in ('null','') else []
        if not isinstance(decisions, list):
            decisions = []
        from collections import Counter
        sc = Counter(d.get('scenario', 'unknown') for d in decisions)
        total = get_crowdsec_total() or len(decisions)
        # Wazuh alerts last 7d
        try:
            q7 = {'size': 0, 'query': {'range': {'@timestamp': {'gte': 'now-7d'}}},
                  'aggs': {'n': {'value_count': {'field': '_id'}}}}
            rw = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
                               auth=(WAZUH_USER, WAZUH_PASS), json=q7,
                               verify=WAZUH_CA, timeout=8)
            alerts_7d = rw.json().get('aggregations',{}).get('n',{}).get('value', 0) if rw.status_code == 200 else 0
        except Exception:
            alerts_7d = 0
        return jsonify({
            'ok': True,
            'total_bans': total,
            'active_bans': len(decisions),
            'top_scenarios': [{'name': k, 'count': v} for k, v in sc.most_common(5)],
            'alerts_7d': alerts_7d,
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': _sanitize_err(e)})


# ── Endpoint Isolation (via beacon) ──────────────────────────────────────────

@app.route('/api/rmm/isolate/<hostname>', methods=['POST'])
@login_required
def rmm_isolate(hostname):
    """Queue a network isolation command to a beacon agent."""
    import re
    if not re.match(r'^[a-zA-Z0-9\-_]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400
    conn = db_conn()
    row = conn.execute(
        "SELECT id FROM agents WHERE lower(hostname)=lower(?) ORDER BY last_seen DESC LIMIT 1",
        (hostname,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': f'No beacon agent found for {hostname}'}), 404
    isolate_cmd = (
        '$ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; '
        'Write-EventLog -LogName Application -Source "SomoTechs" -EventId 9001 '
        '-Message "ISOLATION: Network isolation triggered by SOC at $ts" -EntryType Warning -ErrorAction SilentlyContinue; '
        'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object { '
        '  $n=$_.Name; Disable-NetAdapter -Name $n -Confirm:$false -ErrorAction SilentlyContinue; '
        '  Write-Output "Disabled: $n" }; '
        'Write-Output "[ISOLATED] Host isolated at $ts. Restore: Enable-NetAdapter -Name * -Confirm:$false"'
    )
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    c = conn.cursor()
    c.execute("INSERT INTO commands (agent_id,command,status,created,cmd_type) VALUES (?,?,'pending',?,'isolate')",
              (row[0], isolate_cmd, now))
    cmd_id = c.lastrowid
    conn.commit()
    conn.close()
    app.logger.warning(f'ISOLATION queued for {hostname} cmd_id={cmd_id}')
    return jsonify({'ok': True, 'cmd_id': cmd_id, 'hostname': hostname})


@app.route('/api/rmm/unisolate/<hostname>', methods=['POST'])
@login_required
def rmm_unisolate(hostname):
    """Queue a command to re-enable all network adapters."""
    import re
    if not re.match(r'^[a-zA-Z0-9\-_]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400
    conn = db_conn()
    row = conn.execute(
        "SELECT id FROM agents WHERE lower(hostname)=lower(?) ORDER BY last_seen DESC LIMIT 1",
        (hostname,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': f'No beacon agent for {hostname}'}), 404
    unisolate_cmd = (
        'Get-NetAdapter | ForEach-Object { '
        '  $n=$_.Name; Enable-NetAdapter -Name $n -Confirm:$false -ErrorAction SilentlyContinue; '
        '  Write-Output "Re-enabled: $n" }; '
        '$ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss"; '
        'Write-Output "[UN-ISOLATED] Network restored at $ts"'
    )
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    c = conn.cursor()
    c.execute("INSERT INTO commands (agent_id,command,status,created,cmd_type) VALUES (?,?,'pending',?,'unisolate')",
              (row[0], unisolate_cmd, now))
    cmd_id = c.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'cmd_id': cmd_id, 'hostname': hostname})


# ── Client Portal ─────────────────────────────────────────────────────────────

def _init_portal_tokens():
    conn = db_conn()
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS portal_tokens (
            token TEXT PRIMARY KEY,
            client TEXT NOT NULL,
            label TEXT,
            created TEXT DEFAULT (datetime('now'))
        )''')
        conn.commit()
    finally:
        conn.close()

_init_portal_tokens()


# ── Managed AV (beacon-based Windows Defender) ───────────────────────────────

def _init_av_scans():
    conn = db_conn()
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS av_scans (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname         TEXT,
            client           TEXT,
            cmd_id           INTEGER,
            triggered_at     TEXT,
            completed_at     TEXT,
            status           TEXT DEFAULT 'pending',
            threat_count     INTEGER DEFAULT 0,
            av_enabled       INTEGER DEFAULT 1,
            realtime_enabled INTEGER DEFAULT 1,
            last_scan_time   TEXT,
            threats_json     TEXT,
            raw_output       TEXT
        )''')
        conn.commit()
    finally:
        conn.close()

_init_av_scans()

# PowerShell: get AV status + recent threats + trigger quick scan (non-blocking)
_AV_SCAN_PS = (
    r"try{"
    r"$s=Get-MpComputerStatus|Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
    r"@{N='LastScan';E={$_.LastQuickScanEndTime.ToString('s')}},QuickScanInProgress,"
    r"@{N='SigDate';E={$_.AntivirusSignatureLastUpdated.ToString('s')}};"
    r"$t=@(Get-MpThreatDetection|Where-Object{$_.InitialDetectionTime-gt(Get-Date).AddDays(-7)}"
    r"|Select-Object ThreatName,ActionSuccess,"
    r"@{N='Path';E={($_.Resources-join';').Substring(0,[Math]::Min(200,($_.Resources-join';').Length))}},"
    r"@{N='When';E={$_.InitialDetectionTime.ToString('s')}}|Select-Object -First 20);"
    r"Start-MpScan -ScanType QuickScan -AsJob|Out-Null;"
    r"@{ok=$true;av=$s;threats=$t;count=$t.Count;scan_triggered=$true}|ConvertTo-Json -Depth 3 -Compress"
    r"}catch{@{ok=$false;error=$_.Exception.Message}|ConvertTo-Json -Compress}"
)


@app.route('/api/av/scan/<hostname>', methods=['POST'])
@login_required
def api_av_scan(hostname):
    """Trigger Windows Defender scan on a beacon agent by hostname."""
    import re
    if not re.match(r'^[a-zA-Z0-9\-_.]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400
    conn = db_conn()
    agent = conn.execute(
        "SELECT id, hostname, client FROM agents WHERE lower(hostname)=lower(?) ORDER BY last_seen DESC LIMIT 1",
        (hostname,)
    ).fetchone()
    if not agent:
        conn.close()
        return jsonify({'error': f'Agent {hostname} not found'}), 404
    agent_id, agent_hostname, client = agent
    now = datetime.utcnow().isoformat()
    c = conn.cursor()
    c.execute(
        "INSERT INTO commands (agent_id, command, status, created, cmd_type) VALUES (?,?,'pending',?,'av_scan')",
        (agent_id, _AV_SCAN_PS, now)
    )
    cmd_id = c.lastrowid
    conn.execute(
        "INSERT INTO av_scans (hostname, client, cmd_id, triggered_at, status) VALUES (?,?,?,?,'pending')",
        (agent_hostname, client or '', cmd_id, now)
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'cmd_id': cmd_id, 'hostname': agent_hostname})


@app.route('/api/av/results')
@login_required
def api_av_results():
    """Recent AV scans across all machines."""
    conn = db_conn()
    rows = conn.execute(
        "SELECT hostname, client, cmd_id, triggered_at, completed_at, status, "
        "threat_count, av_enabled, realtime_enabled, last_scan_time, threats_json "
        "FROM av_scans ORDER BY triggered_at DESC LIMIT 100"
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        threats = []
        try:
            if r[10]:
                threats = json.loads(r[10])
        except Exception:
            pass
        out.append({
            'hostname': r[0], 'client': r[1], 'cmd_id': r[2],
            'triggered_at': r[3], 'completed_at': r[4], 'status': r[5],
            'threat_count': r[6], 'av_enabled': bool(r[7]), 'realtime_enabled': bool(r[8]),
            'last_scan_time': r[9], 'threats': threats
        })
    return jsonify(out)


@app.route('/api/av/status')
@login_required
def api_av_status():
    """Latest scan status per machine (one row per hostname)."""
    conn = db_conn()
    rows = conn.execute(
        "SELECT hostname, client, status, threat_count, av_enabled, realtime_enabled, "
        "last_scan_time, completed_at, cmd_id "
        "FROM av_scans WHERE id IN (SELECT MAX(id) FROM av_scans GROUP BY hostname) "
        "ORDER BY completed_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([{
        'hostname': r[0], 'client': r[1], 'status': r[2], 'threat_count': r[3],
        'av_enabled': bool(r[4]), 'realtime_enabled': bool(r[5]),
        'last_scan_time': r[6], 'completed_at': r[7], 'cmd_id': r[8]
    } for r in rows])


# ── Clients metadata (email, notes) ──────────────────────────────────────────

def _init_clients_meta():
    conn = db_conn()
    try:
        conn.execute('''CREATE TABLE IF NOT EXISTS clients_meta (
            client       TEXT PRIMARY KEY,
            email        TEXT,
            phone        TEXT,
            notes        TEXT,
            logo_url     TEXT DEFAULT '',
            accent_color TEXT DEFAULT '',
            portal_company TEXT DEFAULT '',
            updated      TEXT DEFAULT (datetime('now'))
        )''')
        conn.commit()
        # Migrate: add columns if they don't exist yet
        for col in ['logo_url TEXT DEFAULT ""', 'accent_color TEXT DEFAULT ""', 'portal_company TEXT DEFAULT ""']:
            try:
                conn.execute(f'ALTER TABLE clients_meta ADD COLUMN {col}')
                conn.commit()
            except Exception:
                pass
    finally:
        conn.close()

_init_clients_meta()


@app.route('/api/clients', methods=['GET'])
@login_required
def api_clients_list():
    """Unified client list — returns all known client names from clients_meta
    PLUS any client names seen in agents table that aren't already there.
    Used by every dropdown in the dashboard."""
    conn = db_conn()
    meta_clients = {r[0] for r in conn.execute("SELECT client FROM clients_meta WHERE client IS NOT NULL AND client != ''").fetchall()}
    agent_clients = {r[0] for r in conn.execute("SELECT DISTINCT client FROM agents WHERE client IS NOT NULL AND client != ''").fetchall()}
    all_clients = sorted(meta_clients | agent_clients)
    conn.close()
    return jsonify(all_clients)


@app.route('/api/clients/meta', methods=['GET'])
@login_required
def api_clients_meta_list():
    conn = db_conn()
    rows = conn.execute(
        "SELECT client, email, phone, notes, logo_url, accent_color, portal_company, updated FROM clients_meta ORDER BY client"
    ).fetchall()
    conn.close()
    return jsonify([{
        'client': r[0], 'email': r[1], 'phone': r[2], 'notes': r[3],
        'logo_url': r[4] or '', 'accent_color': r[5] or '', 'portal_company': r[6] or '',
        'updated': r[7]
    } for r in rows])


@app.route('/api/clients/meta', methods=['POST'])
@login_required
def api_clients_meta_save():
    data = request.get_json(silent=True) or {}
    client = data.get('client', '').strip()
    if not client:
        return jsonify({'error': 'client required'}), 400
    email          = data.get('email', '').strip()
    phone          = data.get('phone', '').strip()
    notes          = data.get('notes', '').strip()
    logo_url       = data.get('logo_url', '').strip()
    accent_color   = data.get('accent_color', '').strip()
    portal_company = data.get('portal_company', '').strip()
    conn = db_conn()
    conn.execute(
        "INSERT OR REPLACE INTO clients_meta (client,email,phone,notes,logo_url,accent_color,portal_company,updated) "
        "VALUES (?,?,?,?,?,?,?,datetime('now'))",
        (client, email, phone, notes, logo_url, accent_color, portal_company)
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'client': client})


@app.route('/api/portal/tokens', methods=['GET'])
@login_required
def api_portal_tokens_list():
    conn = db_conn()
    rows = conn.execute(
        "SELECT token, client, label, created FROM portal_tokens ORDER BY created DESC"
    ).fetchall()
    conn.close()
    return jsonify([{'token': r[0], 'client': r[1], 'label': r[2], 'created': r[3]} for r in rows])


@app.route('/api/portal/tokens', methods=['POST'])
@login_required
def api_portal_token_create():
    data = request.get_json(silent=True) or {}
    client = data.get('client', '').strip()
    label  = data.get('label', client).strip()
    if not client:
        return jsonify({'error': 'client required'}), 400
    token = secrets.token_urlsafe(32)
    conn = db_conn()
    conn.execute("INSERT INTO portal_tokens (token,client,label) VALUES (?,?,?)", (token, client, label))
    conn.commit()
    conn.close()
    return jsonify({'token': token, 'client': client, 'label': label})


@app.route('/api/portal/tokens/<token>', methods=['DELETE'])
@login_required
def api_portal_token_delete(token):
    conn = db_conn()
    conn.execute("DELETE FROM portal_tokens WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/portal/<token>')
def portal_view(token):
    """Read-only client security portal — no login required, token-gated."""
    conn = db_conn()
    row = conn.execute("SELECT client, label FROM portal_tokens WHERE token=?", (token,)).fetchone()
    if not row:
        conn.close()
        return render_template('banned.html'), 403
    client, label = row[0], row[1]
    meta = conn.execute(
        "SELECT logo_url, accent_color, portal_company FROM clients_meta WHERE client=?", (client,)
    ).fetchone()
    conn.close()
    return render_template('portal.html',
        client=client, label=label, token=token,
        logo_url       = (meta[0] or '') if meta else '',
        accent_color   = (meta[1] or '') if meta else '',
        portal_company = (meta[2] or '') if meta else '',
    )


# ── Blocked IPs / CrowdSec dashboard ─────────────────────────────────────────

@app.route('/blocked')
@login_required
def blocked_page():
    return render_template('blocked.html')


# ── Tools / Recovery page ─────────────────────────────────────────────────────

# Recovery scripts keyed by symptom slug.
# Each script runs on the remote Windows machine via the beacon command queue.
_RECOVERY_SCRIPTS = {
    'slow': {
        'label': 'Computer is Running Slow',
        'icon': '🐢',
        'desc': 'Clears temp files, empties recycle bin, restarts Explorer, flushes standby memory.',
        'cmd': (
            'Write-Output "--- Clearing temp files ---"; '
            'Remove-Item "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue; '
            'Remove-Item "C:\\Windows\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue; '
            'Write-Output "--- Emptying Recycle Bin ---"; '
            'Clear-RecycleBin -Force -ErrorAction SilentlyContinue; '
            'Write-Output "--- Flushing DNS cache ---"; '
            'ipconfig /flushdns | Out-Null; '
            'Write-Output "--- Restarting Explorer ---"; '
            'Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; '
            'Start-Sleep 2; Start-Process explorer; '
            'Write-Output "Done. If still slow, run a full disk check next."'
        ),
    },
    'no_internet': {
        'label': 'Cannot Connect to the Internet',
        'icon': '🌐',
        'desc': 'Resets TCP/IP stack, flushes DNS, renews IP address, resets Winsock.',
        'cmd': (
            'Write-Output "--- Resetting network stack ---"; '
            'netsh winsock reset | Out-Null; '
            'netsh int ip reset | Out-Null; '
            'ipconfig /flushdns | Out-Null; '
            'ipconfig /release | Out-Null; '
            'ipconfig /renew | Out-Null; '
            'Write-Output "--- Current IP config ---"; '
            'ipconfig | Select-String -Pattern "IPv4|Gateway|DNS"; '
            'Write-Output "Done. A restart may be needed for Winsock reset to take full effect."'
        ),
    },
    'printer': {
        'label': 'Printer Stopped Working',
        'icon': '🖨️',
        'desc': 'Clears the print queue, restarts the Print Spooler service.',
        'cmd': (
            'Write-Output "--- Stopping Print Spooler ---"; '
            'Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue; '
            'Write-Output "--- Clearing print queue ---"; '
            'Remove-Item "C:\\Windows\\System32\\spool\\PRINTERS\\*" -Force -Recurse -ErrorAction SilentlyContinue; '
            'Write-Output "--- Starting Print Spooler ---"; '
            'Start-Service -Name Spooler; '
            '$s=(Get-Service Spooler).Status; '
            'Write-Output "Spooler status: $s"; '
            'Write-Output "Done. Try printing again."'
        ),
    },
    'frozen': {
        'label': 'Screen is Frozen / Apps Not Responding',
        'icon': '🧊',
        'desc': 'Kills and restarts Windows Explorer, clears clipboard, ends common stuck processes.',
        'cmd': (
            'Write-Output "--- Ending stuck processes ---"; '
            'foreach($p in @("SearchIndexer","SearchProtocolHost","SearchFilterHost")){'
            '  Stop-Process -Name $p -Force -ErrorAction SilentlyContinue; '
            '  Write-Output "Stopped $p" }; '
            'Write-Output "--- Restarting Explorer ---"; '
            'Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; '
            'Start-Sleep 3; Start-Process explorer; '
            'Write-Output "Done."'
        ),
    },
    'cant_open_files': {
        'label': "Can't Open Files or Programs Crash",
        'icon': '📂',
        'desc': 'Runs System File Checker to repair corrupted Windows system files.',
        'cmd': (
            'Write-Output "--- Running System File Checker (this takes 5-10 min) ---"; '
            'sfc /scannow; '
            'Write-Output "--- Checking Windows image health ---"; '
            'DISM /Online /Cleanup-Image /CheckHealth; '
            'Write-Output "Done. Reboot recommended after SFC completes."'
        ),
    },
    'disk_full': {
        'label': 'Running Out of Disk Space',
        'icon': '💾',
        'desc': 'Removes temp files, empties recycle bin, clears Windows Update cache.',
        'cmd': (
            '$before=[math]::Round((Get-PSDrive C).Free/1GB,2); '
            'Write-Output "Free space before: ${before}GB"; '
            'Remove-Item "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue; '
            'Remove-Item "C:\\Windows\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue; '
            'Clear-RecycleBin -Force -ErrorAction SilentlyContinue; '
            'Write-Output "--- Cleaning Windows Update cache ---"; '
            'Stop-Service wuauserv -Force -ErrorAction SilentlyContinue; '
            'Remove-Item "C:\\Windows\\SoftwareDistribution\\Download\\*" -Recurse -Force -ErrorAction SilentlyContinue; '
            'Start-Service wuauserv -ErrorAction SilentlyContinue; '
            '$after=[math]::Round((Get-PSDrive C).Free/1GB,2); '
            'Write-Output "Free space after: ${after}GB"; '
            'Write-Output "Done."'
        ),
    },
    'update_broken': {
        'label': 'Windows Update Not Working',
        'icon': '🔄',
        'desc': 'Resets all Windows Update components and clears the update cache.',
        'cmd': (
            'Write-Output "--- Stopping Windows Update services ---"; '
            'foreach($s in @("wuauserv","cryptSvc","bits","msiserver")){'
            '  Stop-Service $s -Force -ErrorAction SilentlyContinue; '
            '  Write-Output "Stopped $s" }; '
            'Write-Output "--- Clearing update cache ---"; '
            'Remove-Item "C:\\Windows\\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue; '
            'Remove-Item "C:\\Windows\\System32\\catroot2" -Recurse -Force -ErrorAction SilentlyContinue; '
            'Write-Output "--- Restarting services ---"; '
            'foreach($s in @("wuauserv","cryptSvc","bits","msiserver")){'
            '  Start-Service $s -ErrorAction SilentlyContinue; '
            '  Write-Output "Started $s" }; '
            'Write-Output "Done. Open Windows Update and try again."'
        ),
    },
    'no_sound': {
        'label': 'No Sound / Audio Not Working',
        'icon': '🔇',
        'desc': 'Restarts the Windows Audio service and audio endpoint builder.',
        'cmd': (
            'Write-Output "--- Restarting audio services ---"; '
            'foreach($s in @("AudioSrv","AudioEndpointBuilder")){'
            '  Restart-Service $s -Force -ErrorAction SilentlyContinue; '
            '  $st=(Get-Service $s).Status; '
            '  Write-Output "$s status: $st" }; '
            'Write-Output "Done. If still no sound, check volume mixer and default playback device."'
        ),
    },
    'virus_scan': {
        'label': 'Think There May Be a Virus',
        'icon': '🦠',
        'desc': 'Triggers a Windows Defender quick scan and reports any threats found.',
        'cmd': (
            'Write-Output "--- Starting Windows Defender Quick Scan ---"; '
            'Start-MpScan -ScanType QuickScan; '
            '$threats=Get-MpThreatDetection -ErrorAction SilentlyContinue; '
            'if($threats){'
            '  Write-Output "THREATS FOUND:"; '
            '  $threats | Select-Object -Property ThreatName,ActionSuccess,Resources | Format-List'
            '} else { Write-Output "No threats detected." }; '
            'Write-Output "Done."'
        ),
    },
    'check_health': {
        'label': "Check Computer's Overall Health",
        'icon': '🩺',
        'desc': 'Reports CPU usage, RAM, disk space, uptime, and recent errors from Event Log.',
        'cmd': (
            'Write-Output "=== System Health Report ==="; '
            'Write-Output "--- Uptime ---"; '
            '(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime | Select-Object -Property Days,Hours,Minutes | Format-List; '
            'Write-Output "--- CPU ---"; '
            '[math]::Round((Get-Counter "\\Processor(_Total)\\% Processor Time").CounterSamples.CookedValue,1) | ForEach-Object {"CPU: $_%" }; '
            'Write-Output "--- RAM ---"; '
            '$os=gcim Win32_OperatingSystem; '
            '$used=[math]::Round(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/1MB,1); '
            '$total=[math]::Round($os.TotalVisibleMemorySize/1MB,1); '
            'Write-Output "RAM: ${used}GB used of ${total}GB"; '
            'Write-Output "--- Disk C ---"; '
            '$d=Get-PSDrive C; '
            '$free=[math]::Round($d.Free/1GB,1); $used2=[math]::Round($d.Used/1GB,1); '
            'Write-Output "C: ${used2}GB used, ${free}GB free"; '
            'Write-Output "--- Recent Critical Events (last 24h) ---"; '
            'Get-EventLog -LogName System -EntryType Error -Newest 5 -ErrorAction SilentlyContinue | '
            'Select-Object TimeGenerated,Source,Message | Format-List; '
            'Write-Output "=== Done ==="'
        ),
    },
}


@app.route('/tools')
@login_required
def tools_page():
    return render_template('tools.html')


# ── IDS / Network Intelligence ────────────────────────────────────────────────

@app.route('/ids')
@login_required
def ids_page():
    return render_template('ids.html')


_ids_cache = {'ts': 0, 'data': None}
_IDS_CACHE_TTL = 60

@app.route('/api/ids/summary')
@login_required
def api_ids_summary():
    """IDS summary: sensor status, alert counts by category, top talkers, DNS, SSL anomalies."""
    global _ids_cache
    force = request.args.get('force') == '1'
    if not force and _ids_cache['data'] and (time.time() - _ids_cache['ts']) < _IDS_CACHE_TTL:
        return jsonify(_ids_cache['data'])
    try:
        # ── Sensor list from Wazuh API ─────────────────────────────────────
        sensors = []
        try:
            wazuh_api = os.environ.get('WAZUH_API_URL', 'https://172.17.0.1:55000')
            wazuh_api_user = os.environ.get('WAZUH_API_USER', 'cloude')
            wazuh_api_pass = os.environ.get('WAZUH_API_PASS', '')
            tok_r = requests.post(f"{wazuh_api}/security/user/authenticate",
                auth=(wazuh_api_user, wazuh_api_pass), verify=False, timeout=5)
            if tok_r.status_code == 200:
                token = tok_r.json()['data']['token']
                ag_r = requests.get(f"{wazuh_api}/agents?limit=100&sort=-lastKeepAlive",
                    headers={'Authorization': f'Bearer {token}'}, verify=False, timeout=5)
                if ag_r.status_code == 200:
                    cutoff_dt = datetime.utcnow().timestamp() - 300  # 5 min
                    for ag in ag_r.json().get('data', {}).get('affected_items', []):
                        if ag.get('id') == '000':
                            continue  # skip manager
                        ka = ag.get('lastKeepAlive', '')
                        try:
                            ts = datetime.fromisoformat(ka.replace('Z', '+00:00')).timestamp()
                            online = ts > cutoff_dt
                        except:
                            online = ag.get('status') == 'active'
                        sensors.append({
                            'hostname': ag.get('name', '?'),
                            'id': ag.get('id'),
                            'ip': ag.get('ip', ''),
                            'os': ag.get('os', {}).get('name', ''),
                            'version': ag.get('version', ''),
                            'online': online,
                            'last_seen': ka,
                            'status': ag.get('status', ''),
                        })
        except Exception:
            pass

        # ── Suricata / IDS alert breakdown by category (24h) ─────────────
        # Broad query: any Suricata/IDS event — by alert.category if present
        cat_query = {
            'size': 0,
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': 'now-24h'}}},
            ], 'should': [
                {'exists': {'field': 'data.alert.category'}},
                {'exists': {'field': 'data.alert.signature'}},
                {'term': {'rule.groups': 'suricata'}},
                {'wildcard': {'data.program_name': '*suricata*'}},
                {'range': {'rule.id': {'gte': '86600', 'lte': '86699'}}},
            ], 'minimum_should_match': 1}},
            'aggs': {
                'by_category': {'terms': {'field': 'data.alert.category', 'size': 15,
                    'missing': 'Network Alert'}},
                'by_sensor': {'terms': {'field': 'agent.name', 'size': 20}},
                'severity': {'terms': {'field': 'data.alert.severity', 'size': 5}},
                'timeline': {'date_histogram': {'field': '@timestamp', 'fixed_interval': '1h',
                    'min_doc_count': 0}},
                'total': {'value_count': {'field': '_id'}},
            }
        }
        cr = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=cat_query, verify=WAZUH_CA, timeout=10)
        caggs = cr.json().get('aggregations', {}) if cr.status_code == 200 else {}
        total_hits = cr.json().get('hits', {}).get('total', {}).get('value', 0) if cr.status_code == 200 else 0

        # ── Top DNS queries (Zeek dns.log via Wazuh) ─────────────────────
        dns_query = {
            'size': 0,
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': 'now-24h'}}},
                {'bool': {'should': [
                    {'exists': {'field': 'data.zeek.dns.query'}},
                    {'term': {'rule.groups': 'zeek_dns'}},
                    {'match': {'full_log': 'dns.log'}},
                ], 'minimum_should_match': 1}}
            ]}},
            'aggs': {
                'top_domains': {'terms': {'field': 'data.zeek.dns.query', 'size': 20}},
            }
        }
        dr = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=dns_query, verify=WAZUH_CA, timeout=8)
        daggs = dr.json().get('aggregations', {}) if dr.status_code == 200 else {}

        # ── SSL anomalies (Zeek ssl.log) ──────────────────────────────────
        ssl_query = {
            'size': 10,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': 'now-24h'}}},
                {'bool': {'should': [
                    {'term': {'rule.groups': 'zeek_ssl'}},
                    {'exists': {'field': 'data.zeek.ssl.validation_status'}},
                ], 'minimum_should_match': 1}}
            ]}}
        }
        sr = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=ssl_query, verify=WAZUH_CA, timeout=8)
        ssl_hits = sr.json().get('hits', {}).get('hits', []) if sr.status_code == 200 else []

        # ── Recent IDS/Suricata alerts ────────────────────────────────────
        recent_query = {
            'size': 25,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': 'now-24h'}}},
            ], 'should': [
                {'exists': {'field': 'data.alert.category'}},
                {'exists': {'field': 'data.alert.signature'}},
                {'term': {'rule.groups': 'suricata'}},
                {'range': {'rule.id': {'gte': '86600', 'lte': '86699'}}},
            ], 'minimum_should_match': 1}}
        }
        rr = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=recent_query, verify=WAZUH_CA, timeout=8)
        recent_hits = rr.json().get('hits', {}).get('hits', []) if rr.status_code == 200 else []

        recent_alerts = []
        for h in recent_hits:
            s = h['_source']
            d = s.get('data', {})
            alert = d.get('alert', {}) if isinstance(d.get('alert'), dict) else {}
            sev = alert.get('severity') or s.get('rule', {}).get('level', 3)
            try:
                sev = int(sev)
            except:
                sev = 3
            recent_alerts.append({
                'doc_id': h.get('_id', ''),
                'time': s.get('@timestamp', ''),
                'sensor': s.get('agent', {}).get('name', '?'),
                'category': alert.get('category') or s.get('rule', {}).get('description', 'Network Alert'),
                'signature': alert.get('signature', ''),
                'sig_id': str(alert.get('signature_id') or alert.get('gid', '') or ''),
                'severity': sev,
                'src_ip': d.get('srcip') or d.get('src_ip') or alert.get('src_ip', ''),
                'dst_ip': d.get('dstip') or d.get('dst_ip') or alert.get('dest_ip', ''),
                'dst_port': str(d.get('dest_port') or d.get('dstport') or alert.get('dest_port', '') or ''),
                'proto': d.get('proto', ''),
            })

        # High severity = Suricata sev 1 (critical) OR Wazuh level >= 12
        high_sev = sum(1 for a in recent_alerts if a['severity'] == 1 or a['severity'] >= 12)

        result = {
            'sensors': sensors,
            'total_alerts': total_hits,
            'high_sev': high_sev,
            'categories': [{'cat': b['key'], 'count': b['doc_count']}
                           for b in caggs.get('by_category', {}).get('buckets', [])],
            'by_sensor': [{'sensor': b['key'], 'count': b['doc_count']}
                          for b in caggs.get('by_sensor', {}).get('buckets', [])],
            'severity_counts': {str(b['key']): b['doc_count']
                                for b in caggs.get('severity', {}).get('buckets', [])},
            'timeline': [{'ts': b['key_as_string'], 'count': b['doc_count']}
                         for b in caggs.get('timeline', {}).get('buckets', [])],
            'top_domains': [{'domain': b['key'], 'count': b['doc_count']}
                            for b in daggs.get('top_domains', {}).get('buckets', [])],
            'ssl_anomalies': [{'time': h['_source'].get('@timestamp'),
                               'host': h['_source'].get('data', {}).get('zeek', {}).get('ssl', {}).get('server_name', '?'),
                               'issue': h['_source'].get('data', {}).get('zeek', {}).get('ssl', {}).get('validation_status', '?'),
                               'sensor': h['_source'].get('agent', {}).get('name', '?')}
                              for h in ssl_hits],
            'recent_alerts': recent_alerts,
        }
    except Exception as ex:
        result = {'error': _sanitize_err(ex), 'sensors': sensors if 'sensors' in dir() else [],
                  'categories': [], 'recent_alerts': [], 'timeline': [], 'top_domains': [],
                  'total_alerts': 0, 'high_sev': 0}
    _ids_cache = {'ts': time.time(), 'data': result}
    return jsonify(result)


@app.route('/api/ids/block', methods=['POST'])
@login_required
def api_ids_block():
    """Permanently ban an IP via CrowdSec (cscli decisions add)."""
    data = request.json or {}
    ip = str(data.get('ip', '')).strip()
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return jsonify({'ok': False, 'error': 'Invalid IP address'}), 400
    note = str(data.get('note', '')).strip()[:200]
    try:
        result = subprocess.run(
            ['cscli', 'decisions', 'add', '--ip', ip, '--duration', '87600h',
             '--reason', note or 'Blocked via SOC IDS dashboard', '--type', 'ban'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return jsonify({'ok': False, 'error': result.stderr.strip() or 'cscli failed'})
        return jsonify({'ok': True, 'ip': ip})
    except FileNotFoundError:
        return jsonify({'ok': False, 'error': 'cscli not found on this host'})
    except Exception as ex:
        return jsonify({'ok': False, 'error': _sanitize_err(ex)}), 500


@app.route('/api/ids/suppress', methods=['GET'])
@login_required
def api_ids_suppress_list():
    """Return current IDS suppress list."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute('SELECT id, type, value, note, created_at FROM ids_suppress ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify([{'id': r[0], 'type': r[1], 'value': r[2], 'note': r[3], 'created_at': r[4]} for r in rows])


@app.route('/api/ids/suppress', methods=['POST'])
@login_required
def api_ids_suppress_add():
    """Add an IP or rule sig_id to the suppress list."""
    data = request.json or {}
    sup_type = str(data.get('type', '')).strip()
    value = str(data.get('value', '')).strip()[:200]
    note = str(data.get('note', '')).strip()[:200]
    if sup_type not in ('ip', 'rule'):
        return jsonify({'ok': False, 'error': 'type must be ip or rule'}), 400
    if not value:
        return jsonify({'ok': False, 'error': 'value required'}), 400
    import re
    if sup_type == 'ip' and not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
        return jsonify({'ok': False, 'error': 'Invalid IP address'}), 400
    if sup_type == 'rule' and not re.match(r'^\d+$', value):
        return jsonify({'ok': False, 'error': 'Rule ID must be numeric'}), 400
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('INSERT OR IGNORE INTO ids_suppress (type, value, note) VALUES (?, ?, ?)',
                     (sup_type, value, note))
        conn.commit()
        row_id = conn.execute('SELECT id FROM ids_suppress WHERE type=? AND value=?', (sup_type, value)).fetchone()
        return jsonify({'ok': True, 'id': row_id[0] if row_id else None})
    except Exception as ex:
        return jsonify({'ok': False, 'error': _sanitize_err(ex)}), 500
    finally:
        conn.close()


@app.route('/api/ids/suppress/<int:row_id>', methods=['DELETE'])
@login_required
def api_ids_suppress_delete(row_id):
    """Remove an entry from the suppress list."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('DELETE FROM ids_suppress WHERE id=?', (row_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/ids/sensor/enroll', methods=['POST'])
@login_required
def api_ids_sensor_enroll():
    """Return a shell script to deploy a remote IDS sensor that phones home."""
    data = request.json or {}
    location = str(data.get('location', 'sensor')).strip()[:40]
    import re
    if not re.match(r'^[a-zA-Z0-9\-_ ]+$', location):
        return jsonify({'error': 'invalid location name'}), 400
    slug = re.sub(r'[^a-z0-9-]', '-', location.lower())
    manager_ip = '10.10.0.170'
    agent_secret = os.environ.get('AGENT_SECRET', '')
    script = f"""#!/bin/bash
# SomoTechs IDS Sensor Deploy — {location}
# Run as root on Ubuntu 22.04+ or Debian 12+
set -e
SENSOR_NAME="{slug}"
MANAGER_IP="{manager_ip}"
IFACE="${{1:-$(ip route | grep default | awk '{{print $5}}' | head -1)}}"
echo "=== SomoTechs IDS Sensor: $SENSOR_NAME ==="
echo "Interface: $IFACE | Manager: $MANAGER_IP"

# ── Wazuh Agent ──────────────────────────────────────────────────────────────
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq
WAZUH_MANAGER=$MANAGER_IP apt-get install -y -qq wazuh-agent=4.7.5-1

cat > /var/ossec/etc/ossec.conf << 'AGENTEOF'
<ossec_config>
  <client>
    <server><address>{manager_ip}</address><port>1514</port><protocol>tcp</protocol></server>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>
  <localfile><log_format>json</log_format><location>/var/log/suricata/eve.json</location></localfile>
  <localfile><log_format>json</log_format><location>/var/log/zeek/current/notice.log</location></localfile>
  <localfile><log_format>json</log_format><location>/var/log/zeek/current/dns.log</location></localfile>
  <localfile><log_format>json</log_format><location>/var/log/zeek/current/ssl.log</location></localfile>
  <localfile><log_format>json</log_format><location>/var/log/zeek/current/conn.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>
</ossec_config>
AGENTEOF
systemctl enable wazuh-agent && systemctl start wazuh-agent

# ── Suricata ─────────────────────────────────────────────────────────────────
apt-get install -y -qq suricata suricata-update
sed -i "s/interface: eth0/interface: $IFACE/" /etc/suricata/suricata.yaml
sed -i "s|192.168.0.0/16|10.0.0.0/8|g" /etc/suricata/suricata.yaml
suricata-update --no-test 2>&1 | tail -3
suricata-update 2>&1 | tail -3
systemctl enable suricata && systemctl restart suricata

# ── Zeek ─────────────────────────────────────────────────────────────────────
echo "deb http://download.opensuse.org/repositories/security:/zeek/$(lsb_release -rs | grep -q 22 && echo xUbuntu_22.04 || echo Debian_12)/ /" > /etc/apt/sources.list.d/zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/$(lsb_release -rs | grep -q 22 && echo xUbuntu_22.04 || echo Debian_12)/Release.key | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg 2>/dev/null
apt-get update -qq && apt-get install -y -qq zeek
ZEEK=/opt/zeek/bin
echo "redef Log::default_rotation_interval = 1hr;" >> /opt/zeek/share/zeek/site/local.zeek
$ZEEK/zeekctl deploy 2>/dev/null || ($ZEEK/zeekctl install && $ZEEK/zeekctl start)

# ── Done ─────────────────────────────────────────────────────────────────────
systemctl is-active wazuh-agent suricata
echo ""
echo "✓ IDS sensor '$SENSOR_NAME' deployed"
echo "  Suricata + Zeek watching: $IFACE"
echo "  Shipping alerts to Wazuh manager: $MANAGER_IP"
echo "  Check SOC dashboard: https://soc.somotechs.com/ids"
"""
    win_script = f"""# SomoTechs IDS Sensor Deploy (Windows) — {location}
# Run in PowerShell as Administrator
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$SensorName = "{slug}"
$ManagerIP  = "{manager_ip}"

Write-Host "=== SomoTechs IDS Sensor: $SensorName ===" -ForegroundColor Cyan

# ── Wazuh Agent ──────────────────────────────────────────────────────────────
Write-Host "[1/3] Installing Wazuh agent..." -ForegroundColor Yellow
$WazuhUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi"
$WazuhMsi = "$env:TEMP\\wazuh-agent.msi"
Write-Host "  Downloading Wazuh agent..."
Invoke-WebRequest -Uri $WazuhUrl -OutFile $WazuhMsi -UseBasicParsing
Write-Host "  Installing..."
Start-Process msiexec.exe -ArgumentList "/i `"$WazuhMsi`" /qn WAZUH_MANAGER=`"$ManagerIP`" WAZUH_AGENT_NAME=`"$SensorName`"" -Wait -NoNewWindow
Remove-Item $WazuhMsi -Force -ErrorAction SilentlyContinue

# ossec.conf — add Suricata/Sysmon log sources
$OssecConf = @"
<ossec_config>
  <client>
    <server><address>{manager_ip}</address><port>1514</port><protocol>tcp</protocol></server>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Security</location>
  </localfile>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>System</location>
  </localfile>
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>C:\\Program Files\\Suricata\\log\\eve.json</location>
  </localfile>
</ossec_config>
"@
$OssecPath = "C:\\Program Files (x86)\\ossec-agent\\ossec.conf"
if (Test-Path $OssecPath) {{ Set-Content -Path $OssecPath -Value $OssecConf -Encoding UTF8 }}
Start-Service -Name WazuhSvc -ErrorAction SilentlyContinue
Set-Service  -Name WazuhSvc -StartupType Automatic -ErrorAction SilentlyContinue

# ── Suricata ─────────────────────────────────────────────────────────────────
Write-Host "[2/3] Installing Suricata..." -ForegroundColor Yellow
$SuricataUrl = "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.7-1-64bit.msi"
$SuricataMsi = "$env:TEMP\\suricata.msi"
Write-Host "  Downloading Suricata..."
Invoke-WebRequest -Uri $SuricataUrl -OutFile $SuricataMsi -UseBasicParsing
Start-Process msiexec.exe -ArgumentList "/i `"$SuricataMsi`" /qn" -Wait -NoNewWindow
Remove-Item $SuricataMsi -Force -ErrorAction SilentlyContinue

# Update ET Open rules
$SuricataDir = "C:\\Program Files\\Suricata"
if (Test-Path "$SuricataDir\\suricata-update.exe") {{
    Write-Host "  Updating rules..."
    & "$SuricataDir\\suricata-update.exe" 2>&1 | Select-Object -Last 3
}}

# Enable and start Suricata service
Start-Service -Name Suricata -ErrorAction SilentlyContinue
Set-Service  -Name Suricata -StartupType Automatic -ErrorAction SilentlyContinue

# ── Sysmon (enhances Windows visibility in Wazuh) ────────────────────────────
Write-Host "[3/3] Installing Sysmon..." -ForegroundColor Yellow
$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$SysmonZip = "$env:TEMP\\Sysmon.zip"
$SysmonDir = "$env:TEMP\\Sysmon"
Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonZip -UseBasicParsing
Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
# SwiftOnSecurity Sysmon config (industry standard)
$SysmonConfig = "$env:TEMP\\sysmonconfig.xml"
try {{
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $SysmonConfig -UseBasicParsing -TimeoutSec 15
    & "$SysmonDir\\Sysmon64.exe" -accepteula -i $SysmonConfig 2>&1 | Out-Null
}} catch {{
    & "$SysmonDir\\Sysmon64.exe" -accepteula -i 2>&1 | Out-Null
}}
Remove-Item $SysmonZip,$SysmonDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "IDS sensor '$SensorName' deployed:" -ForegroundColor Green
Write-Host "  Wazuh agent     -> reporting to $ManagerIP" -ForegroundColor Green
Write-Host "  Suricata IDS    -> monitoring network traffic" -ForegroundColor Green
Write-Host "  Sysmon          -> process/network event logging" -ForegroundColor Green
Write-Host "  Check dashboard -> https://soc.somotechs.com/ids" -ForegroundColor Cyan
"""

    win_oneliner = (
        f'irm "https://soc.somotechs.com/api/ids/sensor/enroll" '
        f'-Method POST -ContentType "application/json" '
        f'-Body \'{{\"location\":\"{location}\",\"os\":\"windows\"}}\' | '
        f'%{{ $_.win_script | iex }}'
    )

    return jsonify({'ok': True, 'location': location,
                    'script': script,
                    'oneliner': f"curl -s https://soc.somotechs.com/api/ids/sensor/enroll -X POST -H 'Content-Type: application/json' -d '{{\"location\":\"{location}\"}}' | python3 -c \"import sys,json; print(json.load(sys.stdin)['script'])\" | sudo bash",
                    'win_script': win_script,
                    'win_oneliner': win_oneliner})


@app.route('/api/tools/run', methods=['POST'])
@login_required
def api_tools_run():
    """Queue a recovery script on a target machine by symptom slug."""
    data = request.json or {}
    hostname = str(data.get('hostname', '')).strip()
    slug = str(data.get('slug', '')).strip()
    import re
    if not re.match(r'^[a-zA-Z0-9\-_]+$', hostname):
        return jsonify({'error': 'invalid hostname'}), 400
    if slug not in _RECOVERY_SCRIPTS:
        return jsonify({'error': 'unknown script'}), 400
    script = _RECOVERY_SCRIPTS[slug]
    conn = db_conn()
    row = conn.execute(
        "SELECT id FROM agents WHERE lower(hostname)=lower(?) ORDER BY last_seen DESC LIMIT 1",
        (hostname,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': f'No agent found for {hostname}. Is it online?'}), 404
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "INSERT INTO commands (agent_id,command,status,created,cmd_type) VALUES (?,?,'pending',?,'recovery')",
        (row[0], script['cmd'], now))
    cmd_id = c.lastrowid
    conn.commit()
    conn.close()
    app.logger.info(f'Recovery script "{slug}" queued for {hostname} cmd_id={cmd_id}')
    return jsonify({'ok': True, 'cmd_id': cmd_id, 'hostname': hostname,
                    'label': script['label']})


@app.route('/api/tools/status/<int:cmd_id>')
@login_required
def api_tools_status(cmd_id):
    """Poll a command result by ID."""
    conn = db_conn()
    row = conn.execute(
        "SELECT status,output,created,completed FROM commands WHERE id=?",
        (cmd_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'cmd_id': cmd_id, 'status': row[0],
                    'output': row[1], 'created': row[2], 'completed': row[3]})


# ── Client Management page ────────────────────────────────────────────────────

@app.route('/clients')
@login_required
def clients_page():
    return render_template('clients.html')


# ── Weekly Report ─────────────────────────────────────────────────────────────

@app.route('/api/reports/weekly')
@login_required
def api_weekly_report():
    """Generate a weekly summary report as JSON."""
    from collections import Counter
    report = {'generated': datetime.utcnow().isoformat(), 'period': '7d'}

    # CrowdSec bans
    try:
        hdrs = {'X-Api-Key': CROWDSEC_API_KEY}
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions?type=ban&limit=500", headers=hdrs, timeout=8)
        decisions = r.json() if r.status_code == 200 and r.text.strip() not in ('null','') else []
        report['threats_blocked'] = get_crowdsec_total() or len(decisions or [])
        sc = Counter(d.get('scenario','unknown') for d in (decisions or []))
        report['top_scenarios'] = [{'name': k, 'count': v} for k, v in sc.most_common(3)]
    except Exception:
        report['threats_blocked'] = 0
        report['top_scenarios'] = []

    # Wazuh alerts 7d
    try:
        q = {
            'size': 0,
            'query': {'range': {'@timestamp': {'gte': 'now-7d'}}},
            'aggs': {
                'total': {'value_count': {'field': '_id'}},
                'by_level': {'range': {'field': 'rule.level', 'ranges': [
                    {'key': 'critical', 'from': 12},
                    {'key': 'high',     'from': 10, 'to': 12},
                    {'key': 'medium',   'from': 7,  'to': 10},
                ]}},
                'by_agent': {'terms': {'field': 'agent.name', 'size': 5}},
            }
        }
        wr = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
                           auth=(WAZUH_USER, WAZUH_PASS), json=q, verify=WAZUH_CA, timeout=10)
        aggs = wr.json().get('aggregations', {}) if wr.status_code == 200 else {}
        lvl = {b['key']: b['doc_count'] for b in aggs.get('by_level',{}).get('buckets',[])}
        report['alerts_7d'] = {
            'total':    aggs.get('total',{}).get('value', 0),
            'critical': lvl.get('critical', 0),
            'high':     lvl.get('high', 0),
            'medium':   lvl.get('medium', 0),
        }
        report['top_endpoints'] = [
            {'name': b['key'], 'count': b['doc_count']}
            for b in aggs.get('by_agent',{}).get('buckets',[])
        ]
    except Exception:
        report['alerts_7d'] = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0}
        report['top_endpoints'] = []

    # Malware 7d
    try:
        mq = {
            'size': 0,
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': 'now-7d'}}},
                {'terms': {'rule.id': ['86600','86601','86602',
                                       '86610','86611','86612','86613','86614','86620']}}
            ]}},
            'aggs': {'n': {'value_count': {'field': '_id'}}}
        }
        mr = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
                           auth=(WAZUH_USER, WAZUH_PASS), json=mq, verify=WAZUH_CA, timeout=8)
        report['malware_events_7d'] = (mr.json().get('aggregations',{}).get('n',{}).get('value', 0)
                                       if mr.status_code == 200 else 0)
    except Exception:
        report['malware_events_7d'] = 0

    # Backup summary
    ok_c = warn_c = stale_c = 0
    try:
        with open(RESTIC_HTPASSWD) as f:
            for line in f:
                h = line.strip().split(':')[0]
                if not h:
                    continue
                try:
                    snaps = _restic_snapshots(h)
                    if snaps:
                        latest = sorted(snaps, key=lambda s: s.get('time',''))[-1]
                        st = _snap_status(latest.get('time',''))
                        if st == 'ok': ok_c += 1
                        elif st == 'warning': warn_c += 1
                        else: stale_c += 1
                    else:
                        stale_c += 1
                except Exception:
                    stale_c += 1
    except Exception:
        pass
    report['backups'] = {'ok': ok_c, 'warning': warn_c, 'stale': stale_c}

    # Agent counts
    try:
        conn = db_conn()
        total_a = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
        ls_rows = conn.execute("SELECT last_seen FROM agents").fetchall()
        conn.close()
        now_ts = datetime.utcnow()
        online_a = sum(1 for (ls,) in ls_rows
                       if ls and (now_ts - datetime.fromisoformat(ls)).total_seconds() < 300)
        report['agents'] = {'total': total_a, 'online': online_a}
    except Exception:
        report['agents'] = {'total': 0, 'online': 0}

    return jsonify(report)


@app.route('/api/reports/email', methods=['POST'])
@login_required
def api_send_report_email():
    """Send the weekly report as an email to SMTP_TO."""
    if not SMTP_HOST:
        return jsonify({'ok': False, 'error': 'SMTP not configured. Add SMTP_HOST/SMTP_USER/SMTP_PASS to .env'})
    data = request.get_json(silent=True) or {}
    # Determine recipient: explicit override > client email from DB > default SMTP_TO
    send_to = data.get('to', '').strip()
    if not send_to:
        client_name = data.get('client', '').strip()
        if client_name:
            conn = db_conn()
            row = conn.execute("SELECT email FROM clients_meta WHERE client=?", (client_name,)).fetchone()
            conn.close()
            if row and row[0]:
                send_to = row[0]
    if not send_to:
        send_to = SMTP_TO
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        a = data.get('alerts_7d') or {}
        bk = data.get('backups') or {}
        ag = data.get('agents') or {}
        sc = (data.get('top_scenarios') or [])[:3]
        generated = data.get('generated', '')[:10]

        scenarios_html = ''.join(
            f'<tr><td style="padding:4px 8px;font-size:12px;color:#8892a4;">{s["name"].split("/")[-1]}</td>'
            f'<td style="padding:4px 8px;font-size:12px;color:#ef4444;font-weight:600;">×{s["count"]}</td></tr>'
            for s in sc
        ) or '<tr><td colspan="2" style="padding:4px 8px;color:#22c55e;font-size:12px;">No significant threats</td></tr>'

        html = f"""<!DOCTYPE html><html><body style="background:#06070c;color:#e8eaf0;font-family:Inter,sans-serif;padding:32px;">
<div style="max-width:600px;margin:0 auto;">
  <div style="background:linear-gradient(135deg,#1D6FFF,#8b5cf6);border-radius:12px;padding:24px 28px;margin-bottom:24px;">
    <h1 style="margin:0;font-size:22px;color:#fff;">SomoTechs SOC</h1>
    <p style="margin:6px 0 0;color:rgba(255,255,255,.75);font-size:13px;">Weekly Security Report · {generated}</p>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:24px;">
    <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;">
      <div style="font-size:28px;font-weight:700;color:#22c55e;">{data.get("threats_blocked",0):,}</div>
      <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-top:4px;">Threats Blocked</div>
    </div>
    <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;">
      <div style="font-size:28px;font-weight:700;color:{"#ef4444" if a.get("critical",0)>0 else "#f59e0b" if a.get("high",0)>0 else "#22c55e"};">{a.get("total",0):,}</div>
      <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-top:4px;">Wazuh Alerts</div>
      <div style="font-size:11px;color:#8892a4;margin-top:3px;">{a.get("critical",0)} critical · {a.get("high",0)} high</div>
    </div>
    <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;">
      <div style="font-size:28px;font-weight:700;color:#22c55e;">{bk.get("ok",0)}</div>
      <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-top:4px;">Backups Healthy</div>
      <div style="font-size:11px;color:#8892a4;margin-top:3px;">{bk.get("warning",0)} warning · {bk.get("stale",0)} stale</div>
    </div>
    <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;">
      <div style="font-size:28px;font-weight:700;color:#93C5FD;">{ag.get("online",0)}</div>
      <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-top:4px;">Agents Online</div>
      <div style="font-size:11px;color:#8892a4;margin-top:3px;">of {ag.get("total",0)} managed</div>
    </div>
  </div>
  <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;margin-bottom:24px;">
    <div style="font-size:11px;font-weight:600;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-bottom:10px;">Top Attack Patterns</div>
    <table style="width:100%;border-collapse:collapse;">{scenarios_html}</table>
  </div>
  <div style="text-align:center;font-size:11px;color:#475569;border-top:1px solid rgba(255,255,255,.07);padding-top:16px;">
    SomoTechs · (417) 390-5129 · <a href="mailto:helpdesk@somotechs.com" style="color:#60A5FA;">helpdesk@somotechs.com</a><br>
    This is an automated security report. Dashboard: <a href="https://soc.somotechs.com" style="color:#60A5FA;">soc.somotechs.com</a>
  </div>
</div>
</body></html>"""

        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'SomoTechs Weekly Security Report — {generated}'
        msg['From']    = SMTP_FROM
        msg['To']      = SMTP_TO
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            if SMTP_USER and SMTP_PASS:
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_FROM, [SMTP_TO], msg.as_string())

        return jsonify({'ok': True, 'sent_to': SMTP_TO})
    except Exception as e:
        return jsonify({'ok': False, 'error': _sanitize_err(e)})


@app.route('/api/reports/monthly', methods=['POST'])
@login_required
def api_trigger_monthly_report():
    """Manually trigger the monthly report (for testing)."""
    import threading as _t
    _t.Thread(target=_send_monthly_report, daemon=True).start()
    return jsonify({'ok': True, 'msg': 'Monthly report queued'})


# ── AI single-alert triage ────────────────────────────────────────────────────

@app.route('/api/ai/triage_alert', methods=['POST'])
@login_required
def api_ai_triage_alert():
    """Deep AI triage of a single alert. POST {rule, level, agent, groups, srcip, timestamp, raw}"""
    if not ANTHROPIC_API_KEY:
        return jsonify({'ok': False, 'error': 'AI not configured'})
    d = request.json or {}
    rule    = d.get('rule', 'Unknown')
    level   = d.get('level', 0)
    agent   = d.get('agent', 'Unknown')
    groups  = ', '.join(d.get('groups', []))
    srcip   = d.get('srcip', '—')
    ts      = d.get('timestamp', '')
    raw     = d.get('raw', '')[:800]  # cap raw log

    context = (
        f"Alert: {rule}\n"
        f"Level: {level} ({'CRITICAL' if level>=15 else 'HIGH' if level>=12 else 'MEDIUM' if level>=7 else 'LOW'})\n"
        f"Agent/Host: {agent}\n"
        f"Rule Groups: {groups or 'none'}\n"
        f"Source IP: {srcip}\n"
        f"Time: {ts}\n"
    )
    if raw:
        context += f"Raw log snippet:\n{raw}\n"

    try:
        import anthropic as _anthropic
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        resp = client.messages.create(
            model='claude-haiku-4-5',
            max_tokens=600,
            system=(
                'You are a senior SOC analyst at a small MSP. '
                'Analyze security alerts and give practical, actionable guidance. '
                'Be direct and concise. Respond ONLY with valid JSON — no markdown.'
            ),
            messages=[{'role': 'user', 'content': (
                f'Analyze this Wazuh alert:\n\n{context}\n\n'
                'Respond with this exact JSON:\n'
                '{"urgency":"critical|high|medium|low","is_likely_fp":true/false,'
                '"what_happened":"<1-2 sentences explaining what this alert means>",'
                '"risk":"<1 sentence on the actual risk if real>",'
                '"steps":["<action 1>","<action 2>","<action 3>"],'
                '"confidence":"high|medium|low"}\n\n'
                'steps should be specific, actionable things to do RIGHT NOW on this specific host.'
            )}]
        )
        raw_resp = resp.content[0].text.strip()
        if raw_resp.startswith('```'):
            raw_resp = raw_resp.split('```')[1]
            if raw_resp.startswith('json'):
                raw_resp = raw_resp[4:]
        data = json.loads(raw_resp.strip())
        return jsonify({'ok': True, **data})
    except Exception as e:
        return jsonify({'ok': False, 'error': _sanitize_err(e)})


# ── Alert notification helpers ────────────────────────────────────────────────

def _send_ntfy(title, body, priority='high', tags=None):
    """Send push notification via ntfy.sh."""
    if not NTFY_TOPIC:
        return
    try:
        headers = {
            'Title':    title,
            'Priority': priority,
            'Tags':     ','.join(tags or ['warning']),
        }
        requests.post(f"{NTFY_URL}/{NTFY_TOPIC}", data=body.encode('utf-8'),
                      headers=headers, timeout=6)
    except Exception:
        pass


def _send_alert_email(subject, html_body):
    """Send alert email via configured SMTP."""
    if not SMTP_HOST:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = SMTP_FROM
        msg['To']      = SMTP_TO
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, [SMTP_TO], msg.as_string())
    except Exception as e:
        app.logger.warning(f'Alert email failed: {e}')


def _ai_remediation(alert_lines_text, single_alert=None):
    """Call Claude to generate remediation for a batch of alerts. Returns string."""
    if not ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic as _anthropic
        client = _anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        prompt = (
            f'New high-severity Wazuh alerts just fired on the SomoTechs SOC:\n\n'
            f'{alert_lines_text}\n\n'
            'For each alert provide:\n'
            '1. What likely happened (1 sentence)\n'
            '2. Immediate action steps (2-3 bullets)\n'
            '3. Whether it is likely a false positive\n\n'
            'Be direct and practical. This goes to a solo MSP owner.'
        )
        resp = client.messages.create(
            model='claude-haiku-4-5', max_tokens=800,
            system='You are a senior SOC analyst. Give concise, actionable remediation guidance.',
            messages=[{'role': 'user', 'content': prompt}]
        )
        return resp.content[0].text.strip()
    except Exception:
        return None


# ── Policy Engine ─────────────────────────────────────────────────────────────

_POLICY_SCHEDULES = {
    'on_checkin':  None,          # handled at beacon time
    'hourly':      3600,
    'daily_2am':   None,          # handled by time-of-day check
    'daily_6am':   None,
    'daily_noon':  None,
    'weekly_sun':  None,
    'once':        None,          # run once then disable
}

def _policy_targets(policy, conn):
    """Return list of agent dicts matching this policy's target."""
    t = policy['target_type']
    v = policy['target_value'] or ''
    if t == 'agent':
        rows = conn.execute('SELECT id, hostname, client FROM agents WHERE id=?', (v,)).fetchall()
    elif t == 'client':
        rows = conn.execute('SELECT id, hostname, client FROM agents WHERE lower(client)=lower(?)', (v,)).fetchall()
    else:  # 'all'
        rows = conn.execute('SELECT id, hostname, client FROM agents').fetchall()
    return [{'id': r[0], 'hostname': r[1], 'client': r[2] or ''} for r in rows]

def _run_policy(policy, conn):
    """Queue policy command to all matching agents, log runs."""
    targets = _policy_targets(policy, conn)
    if not targets:
        return 0
    now = datetime.utcnow().isoformat()
    sent = 0
    for a in targets:
        cmd_id = conn.execute(
            "INSERT INTO commands (agent_id,command,status,created,cmd_type) VALUES (?,?,'pending',?,'policy')",
            (a['id'], policy['command'], now)
        ).lastrowid
        conn.execute(
            "INSERT INTO policy_runs (policy_id,agent_id,hostname,cmd_id,started,status) VALUES (?,?,?,?,'queued','queued')",
            (policy['id'], a['id'], a['hostname'], cmd_id)
        )
        sent += 1
    conn.execute(
        "UPDATE policies SET last_run=?, run_count=run_count+1 WHERE id=?",
        (now, policy['id'])
    )
    if policy['schedule'] == 'once':
        conn.execute("UPDATE policies SET enabled=0 WHERE id=?", (policy['id'],))
    conn.commit()
    return sent

def _should_run_policy(policy, now_dt):
    """Return True if this policy should fire right now (minute-resolution)."""
    sched = policy['schedule']
    if sched in ('on_checkin', 'once'):
        return False
    last = policy['last_run']
    h, m = now_dt.hour, now_dt.minute
    wd = now_dt.weekday()  # 0=Mon … 6=Sun
    if sched == 'hourly':
        if m != 0:
            return False
        if last and last[:13] == now_dt.strftime('%Y-%m-%dT%H'):
            return False
        return True
    if sched == 'daily_2am':
        if not (h == 2 and m == 0):
            return False
    elif sched == 'daily_6am':
        if not (h == 6 and m == 0):
            return False
    elif sched == 'daily_noon':
        if not (h == 12 and m == 0):
            return False
    elif sched == 'weekly_sun':
        if not (wd == 6 and h == 2 and m == 0):
            return False
    else:
        return False
    today = now_dt.strftime('%Y-%m-%d')
    if last and last[:10] == today:
        return False
    return True

def _check_on_checkin_policies(agent_id):
    """Called from beacon handler — runs any on_checkin policies for this agent."""
    try:
        conn = db_conn()
        policies = conn.execute(
            "SELECT id,name,command,schedule,target_type,target_value,last_run,run_count "
            "FROM policies WHERE enabled=1 AND schedule='on_checkin'"
        ).fetchall()
        cols = ['id','name','command','schedule','target_type','target_value','last_run','run_count']
        for row in policies:
            p = dict(zip(cols, row))
            targets = _policy_targets(p, conn)
            if any(t['id'] == agent_id for t in targets):
                _run_policy(p, conn)
        conn.close()
    except Exception as e:
        app.logger.warning(f'on_checkin policy error: {e}')

def _policy_scheduler_tick():
    """Called every minute from the monitor loop."""
    try:
        now_dt = datetime.utcnow()
        conn = db_conn()
        policies = conn.execute(
            "SELECT id,name,command,schedule,target_type,target_value,last_run,run_count "
            "FROM policies WHERE enabled=1"
        ).fetchall()
        cols = ['id','name','command','schedule','target_type','target_value','last_run','run_count']
        for row in policies:
            p = dict(zip(cols, row))
            if _should_run_policy(p, now_dt):
                sent = _run_policy(p, conn)
                app.logger.info(f'Policy "{p["name"]}" fired ({p["schedule"]}) → {sent} agents')
        conn.close()
    except Exception as e:
        app.logger.warning(f'Policy scheduler error: {e}')

# ── Policy API endpoints ───────────────────────────────────────────────────────

@app.route('/api/rmm/policies', methods=['GET'])
@login_required
def api_policies_list():
    conn = db_conn()
    rows = conn.execute(
        "SELECT id,name,command,schedule,target_type,target_value,enabled,last_run,run_count,created,note "
        "FROM policies ORDER BY id DESC"
    ).fetchall()
    cols = ['id','name','command','schedule','target_type','target_value','enabled','last_run','run_count','created','note']
    out = [dict(zip(cols, r)) for r in rows]
    conn.close()
    return jsonify(out)

@app.route('/api/rmm/policies', methods=['POST'])
@login_required
def api_policies_create():
    d = request.get_json(silent=True) or {}
    name    = (d.get('name') or '').strip()
    command = (d.get('command') or '').strip()
    schedule = d.get('schedule', 'daily_2am')
    target_type  = d.get('target_type', 'all')
    target_value = (d.get('target_value') or '').strip()
    note    = (d.get('note') or '').strip()
    if not name or not command:
        return jsonify({'error': 'name and command required'}), 400
    conn = db_conn()
    row_id = conn.execute(
        "INSERT INTO policies (name,command,schedule,target_type,target_value,note) VALUES (?,?,?,?,?,?)",
        (name, command, schedule, target_type, target_value, note)
    ).lastrowid
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'id': row_id})

@app.route('/api/rmm/policies/<int:pid>', methods=['PUT'])
@login_required
def api_policies_update(pid):
    d = request.get_json(silent=True) or {}
    fields, vals = [], []
    for col in ['name','command','schedule','target_type','target_value','enabled','note']:
        if col in d:
            fields.append(f'{col}=?')
            vals.append(d[col])
    if not fields:
        return jsonify({'error': 'nothing to update'}), 400
    vals.append(pid)
    conn = db_conn()
    conn.execute(f"UPDATE policies SET {','.join(fields)} WHERE id=?", vals)
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/rmm/policies/<int:pid>', methods=['DELETE'])
@login_required
def api_policies_delete(pid):
    conn = db_conn()
    conn.execute('DELETE FROM policies WHERE id=?', (pid,))
    conn.execute('DELETE FROM policy_runs WHERE policy_id=?', (pid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/rmm/policies/<int:pid>/run-now', methods=['POST'])
@login_required
def api_policies_run_now(pid):
    conn = db_conn()
    row = conn.execute(
        "SELECT id,name,command,schedule,target_type,target_value,last_run,run_count FROM policies WHERE id=?", (pid,)
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'not found'}), 404
    cols = ['id','name','command','schedule','target_type','target_value','last_run','run_count']
    p = dict(zip(cols, row))
    sent = _run_policy(p, conn)
    conn.close()
    return jsonify({'ok': True, 'sent': sent})

@app.route('/api/rmm/policies/<int:pid>/runs', methods=['GET'])
@login_required
def api_policy_runs(pid):
    conn = db_conn()
    rows = conn.execute(
        "SELECT pr.id, pr.hostname, pr.started, pr.status, c.status as cmd_status, c.output "
        "FROM policy_runs pr LEFT JOIN commands c ON pr.cmd_id=c.id "
        "WHERE pr.policy_id=? ORDER BY pr.id DESC LIMIT 100",
        (pid,)
    ).fetchall()
    conn.close()
    out = [{'id':r[0],'hostname':r[1],'started':r[2],'status':r[3],'cmd_status':r[4],'output':(r[5] or '')[:300]} for r in rows]
    return jsonify(out)

# ── RMM Alerting ──────────────────────────────────────────────────────────────

def _rmm_alert(conn, agent_id, hostname, client, atype, message, severity='warning'):
    """Insert an RMM alert if no unacknowledged alert of same type exists for this agent."""
    existing = conn.execute(
        "SELECT id FROM rmm_alerts WHERE agent_id=? AND type=? AND acknowledged=0",
        (agent_id, atype)
    ).fetchone()
    if existing:
        return  # already open
    conn.execute(
        "INSERT INTO rmm_alerts (agent_id,hostname,client,type,message,severity) VALUES (?,?,?,?,?,?)",
        (agent_id, hostname, client or '', atype, message, severity)
    )
    conn.commit()
    _push_rmm_alert(hostname, message, severity)

def _push_rmm_alert(hostname, message, severity):
    """Send ntfy notification for RMM alert."""
    if not NTFY_TOPIC:
        return
    try:
        icon = '🔴' if severity == 'critical' else '🟡'
        priority = 'high' if severity == 'critical' else 'default'
        requests.post(
            f'https://ntfy.sh/{NTFY_TOPIC}',
            data=f'{icon} RMM: {message}'.encode(),
            headers={
                'Title': f'RMM Alert — {hostname}',
                'Priority': priority,
                'Tags': 'computer,warning',
            },
            timeout=5
        )
    except Exception:
        pass

def _check_agent_health(beacon_data, conn):
    """Called from beacon — check disk/CPU thresholds and raise RMM alerts."""
    agent_id = beacon_data.get('id', '')
    hostname = beacon_data.get('hostname', '?')
    client   = beacon_data.get('client', '')
    disk     = float(beacon_data.get('disk', 0))
    cpu      = float(beacon_data.get('cpu', 0))

    if disk >= 95:
        _rmm_alert(conn, agent_id, hostname, client,
                   'disk_critical', f'{hostname}: disk {disk:.0f}% full', 'critical')
    elif disk >= 85:
        _rmm_alert(conn, agent_id, hostname, client,
                   'disk_warning', f'{hostname}: disk {disk:.0f}% full', 'warning')
    else:
        # Auto-resolve disk alerts when back below threshold
        conn.execute(
            "UPDATE rmm_alerts SET acknowledged=1, acknowledged_at=? "
            "WHERE agent_id=? AND type IN ('disk_critical','disk_warning') AND acknowledged=0",
            (datetime.utcnow().isoformat(), agent_id)
        )
        conn.commit()

    if cpu >= 95:
        _rmm_alert(conn, agent_id, hostname, client,
                   'cpu_critical', f'{hostname}: CPU at {cpu:.0f}%', 'warning')

def _check_offline_agents():
    """Called from background loop — raise alert for agents not seen in 15 min."""
    try:
        cutoff = datetime.utcnow().timestamp() - 900  # 15 min
        conn = db_conn()
        rows = conn.execute('SELECT id, hostname, client, last_seen FROM agents').fetchall()
        for agent_id, hostname, client, last_seen in rows:
            try:
                ts = datetime.fromisoformat(last_seen).timestamp()
            except Exception:
                continue
            if ts < cutoff:
                _rmm_alert(conn, agent_id, hostname, client,
                           'offline', f'{hostname} has been offline for >{int((datetime.utcnow().timestamp()-ts)/60)} min', 'warning')
            else:
                # auto-resolve offline alert when agent comes back
                conn.execute(
                    "UPDATE rmm_alerts SET acknowledged=1, acknowledged_at=? "
                    "WHERE agent_id=? AND type='offline' AND acknowledged=0",
                    (datetime.utcnow().isoformat(), agent_id)
                )
                conn.commit()
        conn.close()
    except Exception as e:
        app.logger.warning(f'Offline check error: {e}')

@app.route('/api/rmm/alerts', methods=['GET'])
@login_required
def api_rmm_alerts_list():
    ack = request.args.get('ack', '0')
    conn = db_conn()
    rows = conn.execute(
        "SELECT id,agent_id,hostname,client,type,message,severity,created,acknowledged,acknowledged_at "
        "FROM rmm_alerts WHERE acknowledged=? ORDER BY id DESC LIMIT 200",
        (1 if ack == '1' else 0,)
    ).fetchall()
    cols = ['id','agent_id','hostname','client','type','message','severity','created','acknowledged','acknowledged_at']
    conn.close()
    return jsonify([dict(zip(cols, r)) for r in rows])

@app.route('/api/rmm/alerts/<int:aid>/ack', methods=['POST'])
@login_required
def api_rmm_alert_ack(aid):
    conn = db_conn()
    conn.execute(
        "UPDATE rmm_alerts SET acknowledged=1, acknowledged_at=? WHERE id=?",
        (datetime.utcnow().isoformat(), aid)
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/rmm/alerts/ack-all', methods=['POST'])
@login_required
def api_rmm_alerts_ack_all():
    conn = db_conn()
    conn.execute("UPDATE rmm_alerts SET acknowledged=1, acknowledged_at=? WHERE acknowledged=0",
                 (datetime.utcnow().isoformat(),))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ── File Transfers ─────────────────────────────────────────────────────────────

import uuid as _uuid

UPLOAD_DIR = Path('/app/data/uploads')
UPLOAD_DIR.mkdir(exist_ok=True)

@app.route('/api/rmm/upload', methods=['POST'])
@login_required
def api_rmm_upload():
    """Upload a file to be fetched by an agent."""
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'error': 'no file'}), 400
    safe_name = Path(f.filename).name
    token = _uuid.uuid4().hex
    dest = UPLOAD_DIR / token
    dest.mkdir()
    fpath = dest / safe_name
    f.save(str(fpath))
    size = fpath.stat().st_size
    conn = db_conn()
    conn.execute(
        "INSERT INTO agent_files (token,filename,path,size,created) VALUES (?,?,?,?,?)",
        (token, safe_name, str(fpath), size, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'token': token, 'filename': safe_name,
                    'url': f'https://soc.somotechs.com/api/rmm/file/{token}/{safe_name}'})

@app.route('/api/rmm/file/<token>/<filename>')
def api_rmm_file_download(token, filename):
    """Agent downloads a staged file using its token (no auth — token is the secret)."""
    # Validate token format (hex only)
    if not token.replace('-','').isalnum() or len(token) > 64:
        return 'invalid', 400
    safe_name = Path(filename).name
    conn = db_conn()
    row = conn.execute("SELECT path FROM agent_files WHERE token=?", (token,)).fetchone()
    conn.execute("UPDATE agent_files SET downloaded=downloaded+1 WHERE token=?", (token,))
    conn.commit()
    conn.close()
    if not row:
        return 'not found', 404
    fpath = Path(row[0])
    if not fpath.exists():
        return 'not found', 404
    from flask import send_file
    return send_file(str(fpath), as_attachment=True, download_name=safe_name)

@app.route('/api/rmm/file-list', methods=['GET'])
@login_required
def api_rmm_file_list():
    conn = db_conn()
    rows = conn.execute(
        "SELECT token,filename,size,created,downloaded FROM agent_files ORDER BY created DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([{'token':r[0],'filename':r[1],'size':r[2],'created':r[3],'downloaded':r[4]} for r in rows])

@app.route('/api/rmm/file/<token>', methods=['DELETE'])
@login_required
def api_rmm_file_delete(token):
    if not token.replace('-','').isalnum() or len(token) > 64:
        return jsonify({'error': 'invalid'}), 400
    conn = db_conn()
    row = conn.execute("SELECT path FROM agent_files WHERE token=?", (token,)).fetchone()
    conn.execute("DELETE FROM agent_files WHERE token=?", (token,))
    conn.commit()
    conn.close()
    if row:
        try:
            import shutil
            shutil.rmtree(str(Path(row[0]).parent), ignore_errors=True)
        except Exception:
            pass
    return jsonify({'ok': True})

# ── Screenshots ────────────────────────────────────────────────────────────────

@app.route('/api/rmm/screenshot/<agent_id>', methods=['POST'])
@login_required
def api_rmm_screenshot_request(agent_id):
    """Queue a screenshot command for the agent."""
    cmd = (
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
        "$screens=[System.Windows.Forms.Screen]::AllScreens;"
        "$b=[System.Drawing.Rectangle]::Union($screens[0].Bounds,$screens[0].Bounds);"
        "foreach($s in $screens){$b=[System.Drawing.Rectangle]::Union($b,$s.Bounds)};"
        "$bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height);"
        "$g=[System.Drawing.Graphics]::FromImage($bmp);"
        "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
        "$g.Dispose();"
        "$ms=New-Object System.IO.MemoryStream;"
        # Scale down to 1280 wide max to keep output small
        "$sw=[math]::Min(1280,$b.Width);"
        "$sh=[int]($b.Height*($sw/$b.Width));"
        "$bmp2=New-Object System.Drawing.Bitmap($sw,$sh);"
        "$g2=[System.Drawing.Graphics]::FromImage($bmp2);"
        "$g2.DrawImage($bmp,0,0,$sw,$sh);"
        "$g2.Dispose();$bmp.Dispose();"
        "$enc=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,35L);"
        "$eps=New-Object System.Drawing.Imaging.EncoderParameters(1);"
        "$eps.Param[0]=$enc;"
        "$codec=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|Where-Object{$_.MimeType -eq 'image/jpeg'}|Select-Object -First 1;"
        "$bmp2.Save($ms,$codec,$eps);"
        "$bmp2.Dispose();"
        "[Convert]::ToBase64String($ms.ToArray())"
    )
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    cmd_id = conn.execute(
        "INSERT INTO commands (agent_id,command,status,created,cmd_type) VALUES (?,?,'pending',?,'screenshot')",
        (agent_id, cmd, now)
    ).lastrowid
    conn.commit()
    conn.close()
    return jsonify({'ok': True, 'cmd_id': cmd_id})

@app.route('/api/rmm/screenshot/<agent_id>/latest', methods=['GET'])
@login_required
def api_rmm_screenshot_latest(agent_id):
    """Get the latest stored screenshot for this agent."""
    conn = db_conn()
    row = conn.execute(
        "SELECT image_b64, taken_at FROM agent_screenshots WHERE agent_id=?", (agent_id,)
    ).fetchone()
    conn.close()
    if not row or not row[0]:
        return jsonify({'ok': False, 'error': 'no screenshot yet'})
    return jsonify({'ok': True, 'image': row[0], 'taken_at': row[1]})

# ── SomoAgent WebSocket endpoint ─────────────────────────────────────────────

def _ws_send(ws, obj):
    try:
        ws.send(json.dumps(obj))
        return True
    except Exception:
        return False

def _ws_agent_push_cmd(agent_id, cmd_id, command):
    """Push a command to an agent via WebSocket if connected. Returns True if sent."""
    with _ws_agents_lock:
        entry = _ws_agents.get(agent_id)
    if not entry:
        return False
    return _ws_send(entry['ws'], {'type': 'cmd', 'id': cmd_id, 'command': command})

@sock.route('/ws/agent')
def somoagent_ws(ws):
    """SomoAgent persistent WebSocket connection."""
    agent_id = None
    try:
        # First message must be hello with auth
        raw = ws.receive(timeout=30)
        if not raw:
            return
        d = json.loads(raw)
        if d.get('type') != 'hello' or d.get('key') != AGENT_SECRET:
            _ws_send(ws, {'type': 'error', 'msg': 'unauthorized'})
            return

        agent_id = d.get('id', '')
        if not agent_id:
            return

        hostname = d.get('hostname', agent_id)
        now = datetime.utcnow().isoformat()

        # Build initial telemetry snapshot from hello message
        _telem_keys = ('cpu_pct','ram_used_gb','ram_total_gb','disk_free_gb','disk_total_gb',
                       'os','version','cpu_model','model','manufacturer','domain','win_build')
        _telem = {k: d.get(k) for k in _telem_keys if d.get(k) is not None}

        # Register (clear ghost if reconnecting)
        with _ws_agents_lock:
            _ws_agents_ghost.pop(agent_id, None)
            _ws_agents[agent_id] = {
                'ws': ws, 'hostname': hostname,
                'connected_at': now, 'last_seen': now,
                'telemetry': _telem,
            }

        app.logger.info(f'SomoAgent connected: {hostname} ({agent_id})')
        _ws_send(ws, {'type': 'ack', 'msg': f'Connected as {hostname}'})

        # Update agent last_seen and store initial telemetry
        conn = db_conn()
        try:
            # Store telemetry from hello message
            c = conn.cursor()
            c.execute('SELECT first_seen FROM agents WHERE id=?', (agent_id,))
            row = c.fetchone()
            first_seen = row[0] if row else now
            c.execute('''INSERT OR REPLACE INTO agents
                (id,hostname,ip,os,cpu,ram,disk,uptime,logged_user,last_seen,first_seen,version,client,
                 model,manufacturer,serial,ram_gb,cpu_model,domain,win_build,disk_model,bios)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
                agent_id, hostname, d.get('ip','?'), d.get('os','?'),
                d.get('cpu',0), d.get('ram',0), d.get('disk',0),
                d.get('uptime','?'), d.get('user','?'), now, first_seen,
                d.get('version','2.0'), d.get('client',''),
                d.get('model',''), d.get('manufacturer',''), d.get('serial',''),
                d.get('ram_gb',0), d.get('cpu_model',''), d.get('domain',''),
                d.get('win_build',''), d.get('disk_model',''), d.get('bios',''),
            ))
            conn.commit()
            try:
                _check_agent_health(d, conn)
            except Exception:
                pass
        finally:
            conn.close()

        # Push any pending commands immediately
        conn = db_conn()
        try:
            pending = conn.execute(
                "SELECT id,command FROM commands WHERE agent_id=? AND status='pending' ORDER BY id LIMIT 10",
                (agent_id,)
            ).fetchall()
            for cmd_id, command in pending:
                _ws_send(ws, {'type': 'cmd', 'id': cmd_id, 'command': command})
        finally:
            conn.close()

        # Main message loop
        while True:
            raw = ws.receive(timeout=120)  # 120s timeout — agent sends ping every 60s
            if raw is None:
                break
            try:
                msg = json.loads(raw)
            except Exception:
                continue

            mtype = msg.get('type', '')

            if mtype in ('telemetry', 'ping'):
                tnow = datetime.utcnow().isoformat()
                # Update in-memory telemetry (fast path for live display)
                with _ws_agents_lock:
                    if agent_id in _ws_agents:
                        _ws_agents[agent_id]['last_seen'] = tnow
                        if mtype == 'telemetry':
                            _ws_agents[agent_id]['telemetry'] = {
                                k: msg.get(k) for k in _telem_keys if msg.get(k) is not None
                            }

                if mtype == 'ping':
                    _ws_send(ws, {'type': 'pong'})
                    continue

                # Persist telemetry to DB
                conn = db_conn()
                try:
                    conn.execute(
                        '''UPDATE agents SET cpu=?,ram=?,disk=?,uptime=?,logged_user=?,last_seen=?,
                           ip=?,model=?,manufacturer=?,serial=?,ram_gb=?,cpu_model=?,domain=?,
                           win_build=?,disk_model=?,bios=? WHERE id=?''',
                        (msg.get('cpu',0), msg.get('ram',0), msg.get('disk',0),
                         msg.get('uptime','?'), msg.get('user','?'), tnow,
                         msg.get('ip','?'), msg.get('model',''), msg.get('manufacturer',''),
                         msg.get('serial',''), msg.get('ram_gb',0), msg.get('cpu_model',''),
                         msg.get('domain',''), msg.get('win_build',''), msg.get('disk_model',''),
                         msg.get('bios',''), agent_id)
                    )
                    conn.commit()
                    try:
                        _check_agent_health(msg | {'id': agent_id, 'hostname': hostname, 'client': msg.get('client','')}, conn)
                    except Exception:
                        pass
                finally:
                    conn.close()

            elif mtype == 'result':
                # Command result
                cmd_id = msg.get('cmd_id')
                output = msg.get('output', '')
                if cmd_id:
                    rnow = datetime.utcnow().isoformat()
                    conn = db_conn()
                    try:
                        conn.execute(
                            "UPDATE commands SET status='done', output=?, completed=? WHERE id=?",
                            (output, rnow, cmd_id)
                        )
                        conn.commit()
                        row = conn.execute("SELECT cmd_type FROM commands WHERE id=?", (cmd_id,)).fetchone()
                        if row:
                            ctype = row[0]
                            if ctype == 'av_scan':
                                _process_av_result(conn, cmd_id, output, rnow)
                            elif ctype == 'screenshot':
                                clean = output.strip().replace('\r','').replace('\n','')
                                conn.execute(
                                    "INSERT OR REPLACE INTO agent_screenshots (agent_id,hostname,image_b64,taken_at) VALUES (?,?,?,?)",
                                    (agent_id, hostname, clean[:2_000_000], rnow)
                                )
                                conn.commit()
                            elif ctype == 'policy':
                                conn.execute("UPDATE policy_runs SET status='done' WHERE cmd_id=?", (cmd_id,))
                                conn.commit()
                    finally:
                        conn.close()

            elif mtype == 'file_list':
                # File browser listing — store as a special command result
                cmd_id = msg.get('cmd_id')
                if cmd_id:
                    conn = db_conn()
                    try:
                        conn.execute(
                            "UPDATE commands SET status='done', output=?, completed=? WHERE id=?",
                            (json.dumps(msg.get('items', [])), datetime.utcnow().isoformat(), cmd_id)
                        )
                        conn.commit()
                    finally:
                        conn.close()

            elif mtype == 'screen_frame':
                # Live screen frame — store as screenshot
                frame = msg.get('data', '')
                if frame:
                    fnow = datetime.utcnow().isoformat()
                    conn = db_conn()
                    try:
                        conn.execute(
                            "INSERT OR REPLACE INTO agent_screenshots (agent_id,hostname,image_b64,taken_at) VALUES (?,?,?,?)",
                            (agent_id, hostname, frame[:2_000_000], fnow)
                        )
                        conn.commit()
                    finally:
                        conn.close()

    except Exception as e:
        app.logger.debug(f'SomoAgent WS error ({agent_id}): {e}')
    finally:
        if agent_id:
            with _ws_agents_lock:
                entry = _ws_agents.pop(agent_id, None)
                if entry:
                    # Keep in ghost list so UI shows "reconnecting" instead of vanishing
                    _ws_agents_ghost[agent_id] = {
                        'hostname':     entry['hostname'],
                        'connected_at': entry['connected_at'],
                        'last_seen':    entry.get('last_seen', entry['connected_at']),
                        'telemetry':    entry.get('telemetry', {}),
                        'disconnected_at': datetime.utcnow().isoformat(),
                    }
            app.logger.info(f'SomoAgent disconnected: {agent_id}')

@app.route('/api/rmm/enroll-cmd')
@login_required
def api_rmm_enroll_cmd():
    """Return the one-liner install command with the agent key embedded (login required)."""
    base = request.host_url.rstrip('/')
    # Use public URL if behind reverse proxy
    fwd_proto = request.headers.get('X-Forwarded-Proto', '')
    fwd_host  = request.headers.get('X-Forwarded-Host', '')
    if fwd_host:
        base = f"{fwd_proto or 'https'}://{fwd_host}"
    script_url = f"{base}/static/scripts/SomoAgent.ps1"
    cmd = (
        f"[Net.ServicePointManager]::SecurityProtocol='Tls12';"
        f"$p='C:\\ProgramData\\SomoAgent';"
        f"if(-not(Test-Path $p)){{New-Item -ItemType Directory -Path $p -Force|Out-Null}};"
        f"Invoke-WebRequest -Uri '{script_url}' -OutFile \"$p\\SomoAgent.ps1\";"
        f"powershell -ExecutionPolicy Bypass -File \"$p\\SomoAgent.ps1\" -Install -AgentKey '{AGENT_SECRET}'"
    )
    return jsonify({'cmd': cmd, 'key': AGENT_SECRET})

@app.route('/api/rmm/ws-agents')
@login_required
def api_ws_agents():
    """List agents currently connected (or recently disconnected) via WebSocket."""
    now_ts = time.time()
    out = {}
    with _ws_agents_lock:
        # Live connections
        for aid, v in _ws_agents.items():
            t = v.get('telemetry', {})
            out[aid] = {
                'hostname':     v['hostname'],
                'connected_at': v['connected_at'],
                'last_seen':    v.get('last_seen', v['connected_at']),
                'status':       'live',
                **t,
            }
        # Ghost: recently disconnected agents — prune expired ones
        expired = []
        for aid, v in _ws_agents_ghost.items():
            if aid in out:
                expired.append(aid); continue  # reconnected, clean up ghost
            disc_at = v.get('disconnected_at', '')
            try:
                age = (datetime.utcnow() - datetime.fromisoformat(disc_at)).total_seconds()
            except Exception:
                age = 9999
            if age > _WS_GHOST_TTL:
                expired.append(aid)
            else:
                t = v.get('telemetry', {})
                out[aid] = {
                    'hostname':        v['hostname'],
                    'connected_at':    v['connected_at'],
                    'last_seen':       v.get('last_seen', v['connected_at']),
                    'disconnected_at': v['disconnected_at'],
                    'status':          'offline',
                    **t,
                }
        for aid in expired:
            _ws_agents_ghost.pop(aid, None)
    return jsonify(out)

@app.route('/api/rmm/ws-cmd/<agent_id>', methods=['POST'])
@login_required
def api_ws_cmd(agent_id):
    """Queue a command and push it instantly via WebSocket if agent is connected."""
    d = request.get_json(silent=True) or {}
    command = (d.get('command') or '').strip()
    cmd_type = d.get('cmd_type', '')
    if not command:
        return jsonify({'error': 'no command'}), 400
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    cmd_id = conn.execute(
        "INSERT INTO commands (agent_id,command,status,created,cmd_type) VALUES (?,?,'pending',?,?)",
        (agent_id, command, now, cmd_type)
    ).lastrowid
    conn.commit()
    conn.close()
    pushed = _ws_agent_push_cmd(agent_id, cmd_id, command)
    return jsonify({'ok': True, 'cmd_id': cmd_id, 'pushed': pushed})

@app.route('/api/rmm/ws-file-list/<agent_id>', methods=['POST'])
@login_required
def api_ws_file_list(agent_id):
    """Ask a WS-connected agent to list a directory."""
    d = request.get_json(silent=True) or {}
    path = d.get('path', 'C:\\')
    with _ws_agents_lock:
        entry = _ws_agents.get(agent_id)
    if not entry:
        return jsonify({'error': 'agent not connected via SomoAgent'}), 400
    now = datetime.utcnow().isoformat()
    conn = db_conn()
    cmd_id = conn.execute(
        "INSERT INTO commands (agent_id,command,status,created,cmd_type) VALUES (?,?,'pending',?,'file_list')",
        (agent_id, f'file_list:{path}', now)
    ).lastrowid
    conn.commit()
    conn.close()
    _ws_send(entry['ws'], {'type': 'file_list_req', 'cmd_id': cmd_id, 'path': path})
    return jsonify({'ok': True, 'cmd_id': cmd_id})

@app.route('/api/rmm/ws-screen-stream/<agent_id>', methods=['POST'])
@login_required
def api_ws_screen_stream(agent_id):
    """Tell a WS agent to start/stop streaming screenshots."""
    d = request.get_json(silent=True) or {}
    action = d.get('action', 'start')
    interval = max(2, min(30, int(d.get('interval', 5))))
    with _ws_agents_lock:
        entry = _ws_agents.get(agent_id)
    if not entry:
        return jsonify({'error': 'agent not connected via SomoAgent'}), 400
    _ws_send(entry['ws'], {'type': 'screen_stream', 'action': action, 'interval': interval})
    return jsonify({'ok': True})

# Patch rmm_command to also push instantly via WS when agent is connected
_orig_rmm_command = None  # resolved after function definition

# ── Action1 RMM cloud integration ────────────────────────────────────────────

_a1_ep_cache = {'data': None, 'ts': 0}
_A1_EP_TTL   = 120  # cache endpoint list 2 min

@app.route('/api/action1/endpoints')
@login_required
def api_action1_endpoints():
    """Return Action1 endpoint list with online/offline counts across all orgs."""
    now = time.time()
    if _a1_ep_cache['data'] and now - _a1_ep_cache['ts'] < _A1_EP_TTL:
        return jsonify(_a1_ep_cache['data'])
    if not ACTION1_CLIENT_ID:
        return jsonify({'ok': False, 'error': 'Action1 not configured', 'online': 0, 'offline': 0, 'total': 0, 'endpoints': []})
    try:
        orgs = _a1_orgs()
        tok  = _a1_token()
        all_eps = []
        for org in orgs:
            oid   = org.get('id') or org.get('organization_id', '')
            oname = org.get('name', oid)
            try:
                r = requests.get(f'{_A1_BASE}/endpoints/{oid}',
                                 headers={'Authorization': f'Bearer {tok}'}, timeout=10)
                if r.status_code == 200:
                    body = r.json()
                    eps  = body if isinstance(body, list) else body.get('items', body.get('endpoints', []))
                    for ep in eps:
                        ep['org']    = oname
                        ep['org_id'] = oid
                        all_eps.append(ep)
            except Exception:
                pass
        online  = sum(1 for e in all_eps if (e.get('status') or '').lower() in ('connected', 'online'))
        offline = len(all_eps) - online
        result  = {'ok': True, 'online': online, 'offline': offline, 'total': len(all_eps), 'endpoints': all_eps}
        _a1_ep_cache['data'] = result
        _a1_ep_cache['ts']   = now
        return jsonify(result)
    except Exception as e:
        app.logger.error(f'Action1 endpoints error: {e}')
        return jsonify({'ok': False, 'error': 'Internal server error', 'online': 0, 'offline': 0, 'total': 0, 'endpoints': []})

@app.route('/api/action1/remote/<hostname>')
@login_required
def api_action1_remote(hostname):
    """Return the Action1 console URL for a given hostname."""
    if not ACTION1_CLIENT_ID:
        return jsonify({'ok': False, 'error': 'Action1 not configured'})
    try:
        orgs = _a1_orgs()
        tok  = _a1_token()
        hn   = hostname.lower()
        for org in orgs:
            oid = org.get('id') or org.get('organization_id', '')
            try:
                r = requests.get(f'{_A1_BASE}/endpoints/{oid}',
                                 headers={'Authorization': f'Bearer {tok}'}, timeout=10)
                if r.status_code != 200:
                    continue
                body = r.json()
                eps  = body if isinstance(body, list) else body.get('items', body.get('endpoints', []))
                for ep in eps:
                    name = (ep.get('name') or ep.get('hostname') or ep.get('device_name') or '').lower()
                    if name == hn or hn in name:
                        ep_id = ep.get('id') or ep.get('endpoint_id', '')
                        if ep_id:
                            url = f'https://app.action1.com/console/endpoint/{oid}/{ep_id}'
                        else:
                            url = f'https://app.action1.com/console/endpoints?org={oid}'
                        return jsonify({'ok': True, 'url': url, 'org': org.get('name', oid)})
            except Exception:
                pass
        return jsonify({'ok': False, 'error': f'{hostname} not found in Action1'})
    except Exception as e:
        app.logger.error(f'Action1 remote error: {e}')
        return jsonify({'ok': False, 'error': 'Internal server error'})

# ── Background alert monitor ──────────────────────────────────────────────────

_monitor_state = {
    'last_ts': None,           # ISO timestamp of last alert we processed
    'last_email_ts': 0,
    'last_ntfy_ts': 0,
    'last_sms_ts': 0,
    'email_cooldown': 300,     # 5 min between batch emails
    'ntfy_cooldown': 120,
    'sms_cooldown': 300,       # 5 min between SMS batches (don't spam cell)
    'seen_rule_ts': {},        # {rule_id: last_notified_ts} — dedup noise rules
    'last_monthly_report': '',  # YYYY-MM-DD of last monthly report sent
}

# ── Alert tuning — based on real observed traffic ─────────────────────────────
# Rules that are pure Windows/AD noise — still shown in dashboard but suppressed
# from email/SMS notifications. These all fire constantly on healthy systems.
_NOISE_RULES = {
    '100307',   # SYSTEM privilege assigned — fires every Windows service start
    '60137',    # Windows User Logoff — informational
    '86601',    # Suricata ET INFO — ip-api.com calls (that's US doing geoip lookups)
    '60775',    # Windows service unavailable to handle notification — benign
}

# Machine accounts (ending in $) getting privileges is normal AD Kerberos behavior.
# We only care when HUMAN accounts get unexpected privileges.
_MACHINE_ACCOUNT_RULES = {'100308'}  # only noise when user ends in $

# Rules that ALWAYS get immediate SMS regardless of cooldown (high-value detections)
_ALWAYS_SMS_RULES = {
    '100309',   # Explicit credentials used (runas/lateral movement indicator)
    '533',      # New port opened on monitored host
    '5710',     # Rootkit detection
    '5712',     # Rootkit detection
    '100200',   # Malware/VirusTotal hit
    '87105',    # ClamAV detection
    '100100',   # Windows Defender detection
    '61138',    # Brute force — too many auth failures
    '2932',     # Shellshock attempt
    '31101',    # Web attack SQL injection
    '31103',    # Web attack XSS
}

# Minimum level threshold — alerts below this are silently ignored for notifications
# (still visible in dashboard). Set to 7 based on real traffic analysis.
_ALERT_NOTIFY_LEVEL = 7

# Noise rules get a longer dedup window (30 min) before re-alerting
# High-value rules get a shorter window (10 min)
_NOISE_DEDUP_SECONDS  = 1800   # 30 min — suppress repeat noise
_SIGNAL_DEDUP_SECONDS = 600    # 10 min — repeat genuine alerts

def _auto_make_permanent():
    """Background task: silently convert all timed CrowdSec bans to permanent (-1s)."""
    import docker as _docker
    try:
        r = requests.get(f"{CROWDSEC_URL}/v1/decisions?type=ban&limit=500",
                         headers=_cs_headers(), timeout=10)
        decisions = r.json() if r.status_code == 200 else []
        if not decisions:
            return
        timed = [d for d in decisions if not d.get('duration', '').startswith('-')]
        if not timed:
            return
        client = _docker.DockerClient(base_url='unix:///var/run/docker.sock')
        container = client.containers.get('crowdsec')
        for dec in timed:
            ip = dec.get('value', '')
            if not ip:
                continue
            requests.delete(f"{CROWDSEC_URL}/v1/decisions",
                            headers=_cs_headers(), params={'ip': ip}, timeout=5)
            container.exec_run(
                ['cscli', 'decisions', 'add', '--ip', ip,
                 '--duration', '-1s', '--reason', dec.get('scenario', 'auto-ban')],
                demux=False
            )
        app.logger.info(f'Auto-permanent: converted {len(timed)} timed ban(s)')
    except Exception as e:
        app.logger.debug(f'Auto-permanent failed: {e}')

def _send_monthly_report():
    """Generate and email the monthly security report. Called on the 1st of each month."""
    from collections import Counter
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    if not SMTP_HOST:
        app.logger.info('Monthly report: SMTP not configured, skipping')
        return

    try:
        now = datetime.utcnow()
        generated = now.strftime('%Y-%m-%d')
        month_label = now.strftime('%B %Y')

        # CrowdSec bans
        try:
            hdrs = {'X-Api-Key': CROWDSEC_API_KEY}
            r = requests.get(f"{CROWDSEC_URL}/v1/decisions?type=ban&limit=500", headers=hdrs, timeout=8)
            decisions = r.json() if r.status_code == 200 and r.text.strip() not in ('null','') else []
            threats_blocked = get_crowdsec_total() or len(decisions or [])
            sc = Counter(d.get('scenario','unknown') for d in (decisions or []))
            top_scenarios = [{'name': k, 'count': v} for k, v in sc.most_common(3)]
        except Exception:
            threats_blocked = 0
            top_scenarios = []

        # Wazuh alerts 30d
        try:
            q = {
                'size': 0,
                'query': {'range': {'@timestamp': {'gte': 'now-30d'}}},
                'aggs': {
                    'total': {'value_count': {'field': '_id'}},
                    'by_level': {'range': {'field': 'rule.level', 'ranges': [
                        {'key': 'critical', 'from': 12},
                        {'key': 'high',     'from': 10, 'to': 12},
                        {'key': 'medium',   'from': 7,  'to': 10},
                    ]}},
                    'by_agent': {'terms': {'field': 'agent.name', 'size': 5}},
                }
            }
            wr = requests.post(f"{WAZUH_URL}/wazuh-alerts-4.x-*/_search",
                               auth=(WAZUH_USER, WAZUH_PASS), json=q, verify=WAZUH_CA, timeout=10)
            aggs = wr.json().get('aggregations', {}) if wr.status_code == 200 else {}
            lvl = {b['key']: b['doc_count'] for b in aggs.get('by_level',{}).get('buckets',[])}
            alerts_30d = {
                'total':    aggs.get('total',{}).get('value', 0),
                'critical': lvl.get('critical', 0),
                'high':     lvl.get('high', 0),
                'medium':   lvl.get('medium', 0),
            }
        except Exception:
            alerts_30d = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0}

        # Backups
        ok_c = warn_c = stale_c = 0
        try:
            with open(RESTIC_HTPASSWD) as f:
                for line in f:
                    h = line.strip().split(':')[0]
                    if not h:
                        continue
                    try:
                        snaps = _restic_snapshots(h)
                        if snaps:
                            latest = sorted(snaps, key=lambda s: s.get('time',''))[-1]
                            st = _snap_status(latest.get('time',''))
                            if st == 'ok': ok_c += 1
                            elif st == 'warning': warn_c += 1
                            else: stale_c += 1
                        else:
                            stale_c += 1
                    except Exception:
                        stale_c += 1
        except Exception:
            pass

        # Agent counts
        try:
            conn = db_conn()
            total_a = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
            ls_rows = conn.execute("SELECT last_seen FROM agents").fetchall()
            conn.close()
            now_ts = datetime.utcnow()
            online_a = sum(1 for (ls,) in ls_rows
                           if ls and (now_ts - datetime.fromisoformat(ls)).total_seconds() < 300)
        except Exception:
            total_a = online_a = 0

        a = alerts_30d
        bk = {'ok': ok_c, 'warning': warn_c, 'stale': stale_c}
        scenarios_html = ''.join(
            f'<tr><td style="padding:4px 8px;font-size:12px;color:#8892a4;">{s["name"].split("/")[-1]}</td>'
            f'<td style="padding:4px 8px;font-size:12px;color:#ef4444;font-weight:600;">×{s["count"]}</td></tr>'
            for s in top_scenarios
        ) or '<tr><td colspan="2" style="padding:4px 8px;color:#22c55e;font-size:12px;">No significant threats</td></tr>'

        html = f"""<!DOCTYPE html><html><body style="background:#06070c;color:#e8eaf0;font-family:Inter,sans-serif;padding:32px;">
<div style="max-width:600px;margin:0 auto;">
  <div style="background:linear-gradient(135deg,#1D6FFF,#8b5cf6);border-radius:12px;padding:24px 28px;margin-bottom:24px;">
    <h1 style="margin:0;font-size:22px;color:#fff;">SomoTechs SOC</h1>
    <p style="margin:6px 0 0;color:rgba(255,255,255,.75);font-size:13px;">Monthly Security Report · {month_label}</p>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:24px;">
    <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;">
      <div style="font-size:28px;font-weight:700;color:#22c55e;">{threats_blocked:,}</div>
      <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-top:4px;">Threats Blocked</div>
      <div style="font-size:11px;color:#8892a4;margin-top:3px;">Active bans this month</div>
    </div>
    <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;">
      <div style="font-size:28px;font-weight:700;color:{"#ef4444" if a.get("critical",0)>0 else "#f59e0b" if a.get("high",0)>0 else "#22c55e"};">{a.get("total",0):,}</div>
      <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-top:4px;">Wazuh Alerts (30d)</div>
      <div style="font-size:11px;color:#8892a4;margin-top:3px;">{a.get("critical",0)} critical · {a.get("high",0)} high</div>
    </div>
    <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;">
      <div style="font-size:28px;font-weight:700;color:#22c55e;">{ok_c}</div>
      <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-top:4px;">Backups Healthy</div>
      <div style="font-size:11px;color:#8892a4;margin-top:3px;">{warn_c} warning · {stale_c} stale</div>
    </div>
    <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;">
      <div style="font-size:28px;font-weight:700;color:#93C5FD;">{online_a}</div>
      <div style="font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-top:4px;">Agents Online</div>
      <div style="font-size:11px;color:#8892a4;margin-top:3px;">of {total_a} managed</div>
    </div>
  </div>
  <div style="background:#0d0f17;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px 20px;margin-bottom:24px;">
    <div style="font-size:11px;font-weight:600;color:#475569;text-transform:uppercase;letter-spacing:.4px;margin-bottom:10px;">Top Attack Patterns</div>
    <table style="width:100%;border-collapse:collapse;">{scenarios_html}</table>
  </div>
  <div style="text-align:center;font-size:11px;color:#475569;border-top:1px solid rgba(255,255,255,.07);padding-top:16px;">
    SomoTechs · (417) 390-5129 · <a href="mailto:helpdesk@somotechs.com" style="color:#60A5FA;">helpdesk@somotechs.com</a><br>
    This is your automated monthly security report. Dashboard: <a href="https://soc.somotechs.com" style="color:#60A5FA;">soc.somotechs.com</a>
  </div>
</div>
</body></html>"""

        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'SomoTechs Monthly Security Report — {month_label}'
        msg['From']    = SMTP_FROM
        msg['To']      = SMTP_TO
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            if SMTP_USER and SMTP_PASS:
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_FROM, [SMTP_TO], msg.as_string())

        _monitor_state['last_monthly_report'] = generated
        app.logger.info(f'Monthly security report sent to {SMTP_TO} for {month_label}')

    except Exception as e:
        app.logger.warning(f'Monthly report failed: {e}')


def _alert_monitor_loop():
    """Background thread: Wazuh alerts every 5 min, policy scheduler + offline check every 60s."""
    import time as _time
    _time.sleep(30)  # wait for app to fully start
    app.logger.info('Alert monitor + policy scheduler started')
    _last_wazuh_check = 0
    _last_perm_convert = 0

    while True:
        try:
            now_ts = _time.time()
            # Policy scheduler + offline check — every 60 s
            _policy_scheduler_tick()
            _check_offline_agents()
            # Wazuh alerts — every 5 min
            if now_ts - _last_wazuh_check >= 300:
                _check_new_alerts()
                _last_wazuh_check = _time.time()
            # Auto-convert timed bans to permanent — every 5 min
            if now_ts - _last_perm_convert >= 300:
                _auto_make_permanent()
                _last_perm_convert = _time.time()
            # Monthly security report — fires on the 1st of each month
            today_str = datetime.utcnow().strftime('%Y-%m-%d')
            if (datetime.utcnow().day == 1
                    and _monitor_state.get('last_monthly_report') != today_str):
                _send_monthly_report()
        except Exception as e:
            app.logger.warning(f'Monitor loop error: {e}')
        _time.sleep(60)


def _check_new_alerts():
    """
    Check Wazuh for new alerts. Smart filtering:
    - Threshold L7+ (not L10 — we never saw a L10 in production)
    - Suppresses known-noisy rules (SYSTEM priv, machine account logons, our own ip-api calls)
    - Deduplicates: same rule_id won't re-fire for 30 min (noise) or 10 min (signal)
    - Always-SMS rules bypass cooldowns (explicit creds, rootkit, malware, port changes)
    - Email + SMS on actionable alerts
    """
    import time as _time
    now = datetime.utcnow()
    state = _monitor_state
    now_ts = _time.time()

    if state['last_ts'] is None:
        state['last_ts'] = now.strftime('%Y-%m-%dT%H:%M:%SZ')
        app.logger.info(f'Alert monitor baseline set: {state["last_ts"]}')
        return

    # Use correct field name (timestamp, not @timestamp) and correct index pattern
    query = {
        'size': 50,
        'sort': [{'timestamp': {'order': 'asc'}}],
        'query': {'bool': {'must': [
            {'range': {'rule.level': {'gte': _ALERT_NOTIFY_LEVEL}}},
            {'range': {'timestamp': {'gt': state['last_ts']}}}
        ]}}
    }
    try:
        r = requests.post(f"{WAZUH_URL}/wazuh-alerts-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS), json=query, verify=WAZUH_CA, timeout=15)
        if r.status_code != 200:
            app.logger.warning(f'Alert check HTTP {r.status_code}')
            return
        hits = r.json().get('hits', {}).get('hits', [])
    except Exception as e:
        app.logger.warning(f'Alert check error: {e}')
        return

    if not hits:
        return

    # Advance our timestamp cursor
    last_ts = hits[-1]['_source'].get('timestamp', state['last_ts'])
    state['last_ts'] = last_ts

    actionable   = []   # alerts we will email about
    immediate_sms = []  # alerts needing instant SMS
    seen_rules = state['seen_rule_ts']

    for h in hits:
        s     = h['_source']
        rule  = s.get('rule', {})
        lvl   = int(rule.get('level', 0))
        rid   = str(rule.get('id', '?'))
        desc  = rule.get('description', '?')
        agent = s.get('agent', {}).get('name', '?')
        srcip = s.get('data', {}).get('srcip', '')
        ts    = s.get('timestamp', '')[:19].replace('T', ' ')
        groups = rule.get('groups', [])
        win   = s.get('data', {}).get('win', {}) or {}
        evtdata = win.get('eventdata', {}) or {}
        user  = (evtdata.get('subjectUserName') or evtdata.get('targetUserName') or
                 evtdata.get('targetUserName', '')).strip()

        # ── Noise suppression ────────────────────────────────────────────────
        # 1. Pure noise rules — skip entirely for notifications
        if rid in _NOISE_RULES:
            continue

        # 2. Machine account privilege rules — skip when user ends in $ (AD computer)
        if rid in _MACHINE_ACCOUNT_RULES and user.endswith('$'):
            continue

        # 3. Suricata ET INFO — skip all info-level IDS noise
        if 'suricata' in groups and lvl < 8:
            continue

        # ── Deduplication ────────────────────────────────────────────────────
        dedup_key = f"{rid}:{agent}"  # per-rule per-host dedup
        is_always_sms = rid in _ALWAYS_SMS_RULES
        dedup_window = _SIGNAL_DEDUP_SECONDS if is_always_sms or lvl >= 9 else _NOISE_DEDUP_SECONDS

        last_seen = seen_rules.get(dedup_key, 0)
        if now_ts - last_seen < dedup_window and not is_always_sms:
            continue  # already notified recently for this rule+host combo

        seen_rules[dedup_key] = now_ts

        alert = {
            'lvl': lvl, 'rid': rid, 'desc': desc, 'agent': agent,
            'srcip': srcip, 'ts': ts, 'user': user, 'groups': groups,
            'is_always_sms': is_always_sms
        }
        actionable.append(alert)
        if is_always_sms or lvl >= 9:
            immediate_sms.append(alert)

    if not actionable:
        return

    app.logger.info(f'Alert monitor: {len(actionable)} actionable alerts after filtering')

    # ── Immediate SMS for high-priority alerts ────────────────────────────────
    if immediate_sms and (now_ts - state['last_sms_ts']) > state['sms_cooldown']:
        top = immediate_sms[0]
        lvl_label = {15:'CRITICAL',12:'HIGH',9:'WARNING'}.get(
            15 if top['lvl']>=15 else 12 if top['lvl']>=12 else 9, 'ALERT')
        sms_parts = [f"SomoShield {lvl_label}: {top['desc'][:55]}"]
        sms_parts.append(f"Host: {top['agent']}")
        if top['user'] and not top['user'].endswith('$'):
            sms_parts.append(f"User: {top['user']}")
        if top['srcip']:
            sms_parts.append(f"Src: {top['srcip']}")
        if len(immediate_sms) > 1:
            sms_parts.append(f"+{len(immediate_sms)-1} more alerts")
        sms_parts.append("soc.somotechs.com/alerts")
        _send_sms('\n'.join(sms_parts))
        state['last_sms_ts'] = now_ts
        app.logger.info(f'SMS alert sent for {top["rid"]} on {top["agent"]}')

    # ── Email batch — every 5 min max ─────────────────────────────────────────
    if (now_ts - state['last_email_ts']) > state['email_cooldown']:
        count     = len(actionable)
        crit_count = sum(1 for a in actionable if a['lvl'] >= 12)
        lvl_word  = 'CRITICAL' if crit_count else ('HIGH' if any(a['lvl']>=9 for a in actionable) else 'MEDIUM')
        subject   = f"🚨 SomoShield Alert: {count} actionable event(s) [{lvl_word}]"

        alert_text = '\n'.join(
            f"[L{a['lvl']}] [{a['rid']}] {a['desc']} | host={a['agent']}"
            + (f" user={a['user']}" if a['user'] and not a['user'].endswith('$') else '')
            + (f" src={a['srcip']}" if a['srcip'] else '')
            + f" | {a['ts']}"
            for a in actionable
        )
        ai_text = _ai_remediation(alert_text)

        def _lvl_color(lv):
            if lv >= 12: return '#f87171'
            if lv >= 9:  return '#fb923c'
            if lv >= 7:  return '#facc15'
            return '#94a3b8'

        rows_html = ''.join(
            f'''<tr>
              <td style="padding:5px 10px;border-bottom:1px solid rgba(255,255,255,.06)">
                <span style="background:{_lvl_color(a['lvl'])};color:#000;font-weight:700;font-size:10px;padding:2px 6px;border-radius:4px">L{a['lvl']}</span>
              </td>
              <td style="padding:5px 10px;font-family:monospace;font-size:12px;color:#e2e8f0;border-bottom:1px solid rgba(255,255,255,.06)">{a['desc'][:70]}</td>
              <td style="padding:5px 10px;font-size:11px;color:#94a3b8;border-bottom:1px solid rgba(255,255,255,.06)">{a['agent']}</td>
              <td style="padding:5px 10px;font-size:11px;color:#64748b;border-bottom:1px solid rgba(255,255,255,.06)">{a['ts']}</td>
            </tr>'''
            for a in actionable
        )

        ai_section = ''
        if ai_text:
            ai_section = f'''
            <div style="background:#0d1420;border:1px solid rgba(29,111,255,.2);border-radius:10px;padding:16px 20px;margin-top:16px;">
              <div style="font-size:11px;font-weight:700;color:#60a5fa;text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px;">🤖 AI Remediation Analysis</div>
              <div style="font-size:13px;color:#c8d0e0;white-space:pre-wrap;line-height:1.7;">{ai_text}</div>
            </div>'''

        html_body = f"""<!DOCTYPE html><html><body style="background:#080c14;color:#e8eaf0;font-family:Inter,Arial,sans-serif;padding:0;margin:0;">
<div style="max-width:720px;margin:0 auto;padding:24px 16px;">
  <div style="background:linear-gradient(135deg,#1D6FFF,#8b5cf6);border-radius:12px;padding:20px 24px;margin-bottom:20px;">
    <div style="font-size:20px;font-weight:800;color:#fff;">🛡️ SomoShield Security Alert</div>
    <div style="font-size:13px;color:rgba(255,255,255,.75);margin-top:4px;">{count} actionable event(s) · {now.strftime('%Y-%m-%d %H:%M')} UTC · Noise filtered</div>
  </div>
  <div style="background:#0e1420;border:1px solid rgba(255,255,255,.07);border-radius:10px;overflow:hidden;margin-bottom:16px;">
    <div style="padding:10px 16px;border-bottom:1px solid rgba(255,255,255,.07);font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.8px;">Alert Details</div>
    <table style="width:100%;border-collapse:collapse;">{rows_html}</table>
  </div>
  {ai_section}
  <div style="margin-top:20px;text-align:center;">
    <a href="https://soc.somotechs.com/alerts" style="background:linear-gradient(135deg,#1D6FFF,#8b5cf6);color:#fff;text-decoration:none;padding:11px 28px;border-radius:8px;font-weight:700;font-size:13px;">View in SOC Dashboard →</a>
  </div>
  <div style="margin-top:16px;font-size:10px;color:#475569;text-align:center;">SomoTechs Security Operations · soc.somotechs.com · Noise-filtered alerts only</div>
</div></body></html>"""

        _send_alert_email(subject, html_body)
        state['last_email_ts'] = now_ts
        app.logger.info(f'Alert email sent: {subject}')


# ── Disk Health ───────────────────────────────────────────────────────────────

@app.route('/disk')
@login_required
def disk_page():
    return render_template('disk.html')


@app.route('/api/disk/health')
@login_required
def api_disk_health():
    import subprocess, re, json as _json

    # ── filesystem usage (df) ───────────────────────────────��─────────────────
    filesystems = []
    try:
        df_lines = subprocess.check_output(
            ['df', '-B1', '--output=source,size,used,avail,pcent,target'],
            text=True, stderr=subprocess.DEVNULL, timeout=10
        ).strip().split('\n')[1:]
        skip = {'tmpfs', 'devtmpfs', 'udev', 'overlay', 'shm', 'none'}
        for line in df_lines:
            parts = line.split()
            if len(parts) < 6:
                continue
            src = parts[0]
            if any(src.startswith(s) for s in skip):
                continue
            try:
                size_gb = round(int(parts[1]) / 1e9, 1)
                used_gb = round(int(parts[2]) / 1e9, 1)
                avail_gb = round(int(parts[3]) / 1e9, 1)
                pct = int(parts[4].rstrip('%'))
            except ValueError:
                continue
            filesystems.append({
                'device': src,
                'size_gb': size_gb,
                'used_gb': used_gb,
                'avail_gb': avail_gb,
                'pct': pct,
                'mountpoint': parts[5]
            })
    except Exception as e:
        app.logger.warning(f'disk df error: {_sanitize_err(e)}')

    # ── SMART data per physical drive ─────────────────────────────────────────
    drives = []
    try:
        scan_raw = subprocess.check_output(
            ['smartctl', '--scan'], text=True, stderr=subprocess.DEVNULL, timeout=10
        )
        for line in scan_raw.strip().split('\n'):
            if not line:
                continue
            dev = line.split()[0]
            try:
                info = subprocess.check_output(
                    ['smartctl', '-i', '-H', '-A', dev],
                    text=True, stderr=subprocess.DEVNULL, timeout=20
                )
            except subprocess.CalledProcessError as ce:
                info = ce.output or ''
            except Exception:
                continue

            d = {'device': dev, 'model': '', 'capacity': '', 'type': 'HDD',
                 'rpm': None, 'health': 'UNKNOWN', 'temp_c': None,
                 'power_on_hours': None, 'reallocated': 0,
                 'pending': 0, 'uncorrectable': 0}

            for ln in info.split('\n'):
                ln = ln.strip()
                if ln.startswith('Device Model:'):
                    d['model'] = ln.split(':', 1)[1].strip()
                elif ln.startswith('Model Number:'):
                    d['model'] = ln.split(':', 1)[1].strip()
                    d['type'] = 'NVMe'
                elif ln.startswith('User Capacity:'):
                    m = re.search(r'\[(.+?)\]', ln)
                    if m:
                        d['capacity'] = m.group(1)
                elif ln.startswith('Rotation Rate:'):
                    val = ln.split(':', 1)[1].strip()
                    if 'Solid State' in val or 'rpm' not in val.lower():
                        d['type'] = 'SSD'
                    else:
                        try:
                            d['rpm'] = int(re.search(r'\d+', val).group())
                        except Exception:
                            pass
                elif 'SMART overall-health' in ln or 'SMART Health Status' in ln:
                    d['health'] = 'PASSED' if 'PASSED' in ln or 'OK' in ln else 'FAILED'
                elif re.match(r'\s*5\s+Reallocated_Sector', ln):
                    try:
                        d['reallocated'] = int(ln.split()[-1])
                    except Exception:
                        pass
                elif re.match(r'\s*9\s+Power_On_Hours', ln):
                    try:
                        d['power_on_hours'] = int(ln.split()[-1])
                    except Exception:
                        pass
                elif re.match(r'\s*19[04]\s+', ln) or re.match(r'\s*194\s+Temperature', ln):
                    try:
                        d['temp_c'] = int(ln.split()[-1])
                    except Exception:
                        pass
                elif re.match(r'\s*197\s+Current_Pending', ln):
                    try:
                        d['pending'] = int(ln.split()[-1])
                    except Exception:
                        pass
                elif re.match(r'\s*198\s+Offline_Uncorrectable', ln):
                    try:
                        d['uncorrectable'] = int(ln.split()[-1])
                    except Exception:
                        pass
                # NVMe temperature
                elif ln.startswith('Temperature:') and d['type'] == 'NVMe':
                    m = re.search(r'(\d+)\s+Celsius', ln)
                    if m:
                        d['temp_c'] = int(m.group(1))

            drives.append(d)
    except Exception as e:
        app.logger.warning(f'disk smart error: {_sanitize_err(e)}')

    return jsonify({'filesystems': filesystems, 'drives': drives})


# ── Link Tracker (faceless engine click/conversion tracking) ─────────────────

_TRACKER_PRODUCTS = {
    "crowdsec-smb":   ("https://somotechs.gumroad.com/l/crowdsec-smb",  "https://somotechs.github.io/products/crowdsec-smb.html"),
    "somoshield-kit": ("https://somotechs.gumroad.com/l/somoshield-kit", "https://somotechs.github.io/products/somoshield-kit.html"),
    "soc-setup":      ("https://somotechs.gumroad.com/l/soc-setup",      "https://somotechs.github.io/products/soc-setup.html"),
}

_TRACKER_DB = "/app/data/tracker.db"

def _tracker_init():
    conn = sqlite3.connect(_TRACKER_DB)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT, source TEXT, ref TEXT, ip_hash TEXT, clicked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS conversions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT, amount REAL, source TEXT, ref TEXT, converted_at TEXT
        );
    """)
    conn.commit()
    conn.close()

_tracker_init()

@app.route('/t/<slug>')
def tracker_redirect(slug):
    """Click tracking redirect. /t/crowdsec-smb?src=reddit&ref=selfhosted"""
    if slug not in _TRACKER_PRODUCTS:
        return redirect("https://somotechs.github.io"), 302
    src  = request.args.get('src', 'direct')[:32]
    ref  = request.args.get('ref', '')[:64]
    raw_ip = request.remote_addr or ''
    ip_hash = hashlib.sha256(raw_ip.encode()).hexdigest()[:16]
    try:
        conn = sqlite3.connect(_TRACKER_DB)
        conn.execute("INSERT INTO clicks (slug,source,ref,ip_hash,clicked_at) VALUES (?,?,?,?,?)",
                     (slug, src, ref, ip_hash, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    except Exception:
        pass
    gumroad_url, _ = _TRACKER_PRODUCTS[slug]
    return redirect(gumroad_url), 302

@app.route('/t/<slug>/land')
def tracker_land(slug):
    """Redirect to landing page instead of Gumroad direct."""
    if slug not in _TRACKER_PRODUCTS:
        return redirect("https://somotechs.github.io"), 302
    src  = request.args.get('src', 'direct')[:32]
    ref  = request.args.get('ref', '')[:64]
    raw_ip = request.remote_addr or ''
    ip_hash = hashlib.sha256(raw_ip.encode()).hexdigest()[:16]
    try:
        conn = sqlite3.connect(_TRACKER_DB)
        conn.execute("INSERT INTO clicks (slug,source,ref,ip_hash,clicked_at) VALUES (?,?,?,?,?)",
                     (slug, src, ref, ip_hash, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    except Exception:
        pass
    _, landing_url = _TRACKER_PRODUCTS[slug]
    return redirect(landing_url), 302

@app.route('/api/tracker/stats')
@login_required
def api_tracker_stats():
    try:
        conn = sqlite3.connect(_TRACKER_DB)
        clicks = conn.execute("""
            SELECT slug, source, COUNT(*) as n
            FROM clicks GROUP BY slug, source ORDER BY n DESC
        """).fetchall()
        conversions = conn.execute("""
            SELECT slug, COUNT(*) as n, COALESCE(SUM(amount),0) as revenue
            FROM conversions GROUP BY slug ORDER BY revenue DESC
        """).fetchall()
        total_revenue = conn.execute("SELECT COALESCE(SUM(amount),0) FROM conversions").fetchone()[0]
        conn.close()
        return jsonify({
            "total_revenue": round(total_revenue, 2),
            "clicks": [{"slug": r[0], "source": r[1], "count": r[2]} for r in clicks],
            "conversions": [{"slug": r[0], "count": r[1], "revenue": round(r[2],2)} for r in conversions],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/tracker/conversion', methods=['POST'])
def api_tracker_conversion():
    """Gumroad webhook or manual conversion logging."""
    data = request.json or {}
    slug   = data.get('slug', '')[:32]
    amount = float(data.get('amount', 0))
    source = data.get('source', '')[:32]
    ref    = data.get('ref', '')[:64]
    if slug not in _TRACKER_PRODUCTS:
        return jsonify({'error': 'unknown slug'}), 400
    try:
        conn = sqlite3.connect(_TRACKER_DB)
        conn.execute("INSERT INTO conversions (slug,amount,source,ref,converted_at) VALUES (?,?,?,?,?)",
                     (slug, amount, source, ref, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── MeshCentral integration ───────────────────────────────────────────────────

MESH_URL         = os.environ.get('MESH_URL', 'https://mesh.somotechs.com')
MESH_WS_URL      = os.environ.get('MESH_WS_URL', 'ws://meshcentral:4430')
MESH_USER        = os.environ.get('MESH_USER', 'cloude')
MESH_PASS        = os.environ.get('MESH_PASS', '')

def _mesh_ws_auth():
    import base64
    u = base64.b64encode(MESH_USER.encode()).decode()
    p = base64.b64encode(MESH_PASS.encode()).decode()
    return f"{u}, {p}"

async def _mesh_call(payload_list, timeout=8):
    """Send one or more WS messages to MeshCentral and collect all responses."""
    import websockets as _ws
    results = []
    try:
        headers = {'x-meshauth': _mesh_ws_auth()}
        uri = f"{MESH_WS_URL}/control.ashx"
        async with _ws.connect(uri, additional_headers=headers, open_timeout=6) as ws:
            for p in payload_list:
                await ws.send(json.dumps(p))
            import asyncio
            deadline = asyncio.get_event_loop().time() + timeout
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    break
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=remaining)
                    results.append(json.loads(msg))
                except asyncio.TimeoutError:
                    break
    except Exception as e:
        app.logger.error(f'MeshCentral WS error: {e}')
    return results

def _mesh_run(payload_list, timeout=8):
    import asyncio
    return asyncio.run(_mesh_call(payload_list, timeout))

@app.route('/api/mesh/remote/<hostname>')
@login_required
def api_mesh_remote(hostname):
    """Look up a device in MeshCentral by hostname and return a direct remote-desktop URL."""
    if not hostname or len(hostname) > 128:
        return jsonify({'error': 'invalid hostname'}), 400
    import urllib.parse
    # Try to find the node in MeshCentral for a direct RDP link
    try:
        msgs = _mesh_run([{'action': 'nodes'}], timeout=6)
        for msg in msgs:
            if msg.get('action') != 'nodes':
                continue
            for mesh_id, nodes in (msg.get('nodes') or {}).items():
                for node in (nodes or []):
                    node_name = (node.get('name') or '').lower().strip()
                    if node_name == hostname.lower().strip():
                        node_id = node.get('_id', '')
                        if node_id:
                            safe_id = urllib.parse.quote(node_id, safe='')
                            # viewmode=11 opens remote desktop tab directly
                            url = f"{MESH_URL}/?viewmode=11&nodeId={safe_id}"
                            return jsonify({'url': url, 'nodeId': node_id})
    except Exception as e:
        app.logger.warning(f'MeshCentral node lookup failed: {e}')
    # Fallback: search page
    safe = urllib.parse.quote(hostname, safe='')
    return jsonify({'url': f"{MESH_URL}/?search={safe}", 'fallback': True})

@app.route('/api/mesh/groups', methods=['GET'])
@login_required
def api_mesh_groups_list():
    """List all MeshCentral device groups with their install commands."""
    msgs = _mesh_run([{'action': 'meshes'}])
    groups = []
    for m in msgs:
        if m.get('action') == 'meshes':
            for g in (m.get('meshes') or []):
                mesh_id = g.get('_id', '').replace('mesh//', '')
                name = g.get('name', '')
                # Build PowerShell install command (script block style — paste-safe)
                ps_cmd = (
                    f'$m="{MESH_URL}/meshagents?id=6&meshid={mesh_id}&meshinstallflags=0"; '
                    f'$f="$env:TEMP\\ma.msi"; '
                    f'Invoke-WebRequest -Uri $m -OutFile $f -UseBasicParsing; '
                    f'Start-Process msiexec.exe -ArgumentList "/i","$f","/quiet" -Wait; '
                    f'Remove-Item $f'
                )
                groups.append({
                    'name': name,
                    'id': mesh_id,
                    'device_count': g.get('deviceCount', 0),
                    'install_cmd': ps_cmd,
                    'mesh_url': f"{MESH_URL}/?search="
                })
    return jsonify(groups)

MESH_ADMIN_USER = os.environ.get('MESH_ADMIN_USER', 'user//somo')

@app.route('/api/mesh/groups', methods=['POST'])
@login_required
def api_mesh_groups_create():
    """Create a new MeshCentral device group and add all admins to it."""
    data = request.json or {}
    name = (data.get('name') or '').strip()[:64]
    if not name:
        return jsonify({'error': 'name required'}), 400
    # Create group then re-list to get the new meshid, then add the site admin
    msgs = _mesh_run([
        {'action': 'createmesh', 'meshname': name, 'meshtype': 2, 'responseid': 'create'},
    ], timeout=5)
    # Re-fetch groups to find the new meshid
    msgs2 = _mesh_run([{'action': 'meshes'}], timeout=5)
    new_meshid = None
    for m in msgs2:
        if m.get('action') == 'meshes':
            for g in (m.get('meshes') or []):
                if g.get('name') == name:
                    new_meshid = g.get('_id', '')
                    break
    # Add site admin to the new group with full rights
    if new_meshid:
        _mesh_run([{
            'action': 'addmeshuser',
            'meshid': new_meshid,
            'userid': MESH_ADMIN_USER,
            'rights': 4294967295,
            'responseid': 'addadmin'
        }], timeout=5)
    return jsonify({'ok': True, 'name': name, 'meshid': new_meshid})

# ── Support Requests ──────────────────────────────────────────────────────────

def _init_support_requests():
    conn = db_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS support_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client      TEXT,
            hostname    TEXT,
            description TEXT,
            status      TEXT DEFAULT 'open',
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT
        )
    """)
    conn.commit()
    conn.close()

_init_support_requests()

@app.route('/api/support/request', methods=['POST'])
def api_support_request():
    """Client or portal submits a quick support request. No login required (portal token auth)."""
    d = request.get_json(silent=True) or {}
    client   = str(d.get('client','')).strip()[:60]
    hostname = str(d.get('hostname','')).strip()[:60]
    desc     = str(d.get('description','No details provided')).strip()[:500]
    pt       = d.get('pt','')
    urgent   = bool(d.get('urgent', False))

    # validate: either logged in OR valid portal token
    if not session.get('logged_in'):
        if pt:
            conn = db_conn()
            row = conn.execute("SELECT client FROM portal_tokens WHERE token=?", (pt,)).fetchone()
            conn.close()
            if not row:
                return jsonify({'ok': False, 'error': 'unauthorized'}), 403
            if not client:
                client = row[0]
        else:
            return jsonify({'ok': False, 'error': 'unauthorized'}), 403

    conn = db_conn()
    conn.execute(
        "INSERT INTO support_requests (client, hostname, description) VALUES (?,?,?)",
        (client, hostname, desc)
    )
    conn.commit()
    req_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    # 911 urgent = SMS immediately, email with URGENT subject
    who = f"{client} / {hostname}" if hostname else client
    mesh_link = f"{MESH_URL}/?search={urllib.parse.quote(hostname, safe='')}" if hostname else MESH_URL
    _email_base = """
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0a1628;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a1628;padding:32px 0;">
    <tr><td align="center">
      <table width="580" cellpadding="0" cellspacing="0" style="background:#0f1c2d;border-radius:10px;overflow:hidden;border:1px solid #1e3a5f;">
        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#1e3a6e 0%,#0f2444 100%);padding:28px 32px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#ffffff;letter-spacing:1px;">
              🛡️ SomoShield SOC
            </div>
            <div style="font-size:12px;color:#7fa8d4;margin-top:4px;letter-spacing:2px;text-transform:uppercase;">
              Managed Security · SomoTechs
            </div>
          </td>
        </tr>
        <!-- Alert Banner -->
        <tr>
          <td style="background:{banner_bg};padding:14px 32px;text-align:center;">
            <span style="font-size:16px;font-weight:600;color:{banner_fg};">{banner_text}</span>
          </td>
        </tr>
        <!-- Body -->
        <tr>
          <td style="padding:28px 32px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #1e3a5f;">
                  <span style="color:#7fa8d4;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Client</span><br>
                  <span style="color:#e2e8f0;font-size:15px;font-weight:600;">{client}</span>
                </td>
              </tr>
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #1e3a5f;">
                  <span style="color:#7fa8d4;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Device</span><br>
                  <span style="color:#e2e8f0;font-size:15px;">{hostname}</span>
                </td>
              </tr>
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #1e3a5f;">
                  <span style="color:#7fa8d4;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Message</span><br>
                  <span style="color:#e2e8f0;font-size:15px;line-height:1.6;">{desc}</span>
                </td>
              </tr>
            </table>
            <div style="margin-top:24px;text-align:center;">
              <a href="{mesh_link}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;padding:12px 28px;border-radius:6px;font-weight:600;font-size:14px;">
                🖥️ Connect via MeshCentral
              </a>
            </div>
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="background:#07111e;padding:16px 32px;text-align:center;border-top:1px solid #1e3a5f;">
            <span style="color:#4a6fa5;font-size:11px;">
              Powered by SomoShield · SomoTechs LLC · (417) 390-5129
            </span>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
    if urgent:
        html_body = _email_base.format(
            banner_bg='#7f1d1d', banner_fg='#fca5a5',
            banner_text='🚨 URGENT / 911 — IMMEDIATE RESPONSE NEEDED',
            client=client, hostname=hostname or 'Unknown',
            desc=desc, mesh_link=mesh_link
        )
        _send_sms(f"🚨 911 URGENT from {who}: {desc[:100]} — Connect: {mesh_link}")
        _send_email_notify(subject=f"🚨 911 URGENT SUPPORT — {who}", body=html_body)
    else:
        html_body = _email_base.format(
            banner_bg='#1e3a5f', banner_fg='#93c5fd',
            banner_text='📋 New Support Request',
            client=client, hostname=hostname or 'Not specified',
            desc=desc, mesh_link=mesh_link
        )
        _send_email_notify(subject=f"[Support Request] {who}", body=html_body)
    return jsonify({'ok': True, 'id': req_id})

@app.route('/api/support/requests', methods=['GET'])
@login_required
def api_support_requests_list():
    status = request.args.get('status', 'open')
    conn = db_conn()
    rows = conn.execute(
        "SELECT id, client, hostname, description, status, created_at FROM support_requests WHERE status=? ORDER BY created_at DESC LIMIT 50",
        (status,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/support/requests/<int:req_id>/resolve', methods=['POST'])
@login_required
def api_support_request_resolve(req_id):
    conn = db_conn()
    conn.execute(
        "UPDATE support_requests SET status='resolved', resolved_at=CURRENT_TIMESTAMP WHERE id=?",
        (req_id,)
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ── Start background monitor ──────────────────────────────────────────────────

import threading as _threading
_monitor_thread = _threading.Thread(target=_alert_monitor_loop, daemon=True)
_monitor_thread.start()

# ── USB Backup Status ─────────────────────────────────────────────────────────
USB_STATUS_FILE = '/tmp/usb-backup-status.json'

@app.route('/api/usb/status')
@login_required
def api_usb_status():
    try:
        if os.path.exists(USB_STATUS_FILE):
            with open(USB_STATUS_FILE) as f:
                return jsonify(json.load(f))
    except Exception:
        pass
    return jsonify({'state': 'idle'})

@app.route('/api/usb/clear', methods=['POST'])
@login_required
def api_usb_clear():
    try:
        os.remove(USB_STATUS_FILE)
    except Exception:
        pass
    return jsonify({'ok': True})


# ═══════════════════════════════════════════════════════════════════════════════
# BILLING / PSA MODULE
# Replaces SuperOps billing — time tracking, MRR, invoice PDF, email
# Copyright (c) 2024-2026 Somo Technologies LLC
# ═══════════════════════════════════════════════════════════════════════════════

import io, smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

INVOICE_DIR = os.path.join(os.path.dirname(__file__), 'secrets', 'invoices')
os.makedirs(INVOICE_DIR, exist_ok=True)

COMPANY_NAME    = os.environ.get('COMPANY_NAME',  'Somo Technologies LLC')
COMPANY_ADDR    = os.environ.get('COMPANY_ADDR',  'Missouri, MO')
COMPANY_EMAIL   = os.environ.get('COMPANY_EMAIL', 'anthony@somotechs.com')
COMPANY_PHONE   = os.environ.get('COMPANY_PHONE', '(417) 390-5129')
COMPANY_WEBSITE = os.environ.get('COMPANY_WEBSITE','somotechs.com')

@app.route('/billing')
@login_required
def billing_page():
    return render_template('billing.html')

# ── Client rates ──────────────────────────────────────────────────────────────

@app.route('/api/billing/rates', methods=['GET'])
@login_required
def billing_rates_get():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM client_rates ORDER BY client').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/billing/rates', methods=['POST'])
@login_required
def billing_rates_set():
    d = request.get_json(force=True)
    client = d.get('client','').strip()
    if not client:
        return jsonify({'ok': False, 'error': 'client required'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''INSERT INTO client_rates (client,hourly_rate,monthly_fee,per_seat,notes)
                        VALUES (?,?,?,?,?)
                        ON CONFLICT(client) DO UPDATE SET
                          hourly_rate=excluded.hourly_rate,
                          monthly_fee=excluded.monthly_fee,
                          per_seat=excluded.per_seat,
                          notes=excluded.notes''',
                     (client, d.get('hourly_rate',125), d.get('monthly_fee',0),
                      d.get('per_seat',0), d.get('notes','')))
        conn.commit()
    return jsonify({'ok': True})

# ── Time entries ──────────────────────────────────────────────────────────────

@app.route('/api/billing/time', methods=['GET'])
@login_required
def billing_time_get():
    client  = request.args.get('client','')
    invoiced = request.args.get('invoiced', '')   # '0' = unbilled only
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        q = 'SELECT * FROM time_entries WHERE 1=1'
        params = []
        if client:
            q += ' AND client=?'; params.append(client)
        if invoiced != '':
            q += ' AND invoiced=?'; params.append(int(invoiced))
        q += ' ORDER BY date DESC, id DESC'
        rows = conn.execute(q, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/billing/time', methods=['POST'])
@login_required
def billing_time_add():
    d = request.get_json(force=True)
    required = ['client','date','description','hours']
    if not all(d.get(k) for k in required):
        return jsonify({'ok': False, 'error': 'client, date, description, hours required'}), 400
    # Look up rate for client
    with sqlite3.connect(DB_PATH) as conn:
        rate_row = conn.execute('SELECT hourly_rate FROM client_rates WHERE client=?',
                                (d['client'],)).fetchone()
        rate = d.get('rate', rate_row[0] if rate_row else 125.0)
        cur = conn.execute('''INSERT INTO time_entries
                              (client,date,description,hours,rate,billable)
                              VALUES (?,?,?,?,?,?)''',
                           (d['client'], d['date'], d['description'],
                            float(d['hours']), float(rate), int(d.get('billable',1))))
        conn.commit()
        return jsonify({'ok': True, 'id': cur.lastrowid, 'rate': rate,
                        'total': round(float(d['hours']) * float(rate), 2)})

@app.route('/api/billing/time/<int:entry_id>', methods=['DELETE'])
@login_required
def billing_time_delete(entry_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('DELETE FROM time_entries WHERE id=? AND invoiced=0', (entry_id,))
        conn.commit()
    return jsonify({'ok': True})

# ── MRR summary ───────────────────────────────────────────────────────────────

@app.route('/api/billing/mrr')
@login_required
def billing_mrr():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rates  = {r['client']: dict(r) for r in
                  conn.execute('SELECT * FROM client_rates').fetchall()}
        # count seats (agents) per client
        agents = conn.execute('SELECT client, COUNT(*) as cnt FROM agents '
                              'WHERE client IS NOT NULL AND client != "" '
                              'GROUP BY client').fetchall()
        # unbilled time totals
        unbilled = conn.execute('''SELECT client, SUM(hours*rate) as total
                                   FROM time_entries WHERE invoiced=0 AND billable=1
                                   GROUP BY client''').fetchall()
    unbilled_map = {r['client']: round(r['total'],2) for r in unbilled}
    result = []
    total_mrr = 0
    for client, info in rates.items():
        seat_count = next((r['cnt'] for r in agents if r['client']==client), 0)
        mrr = info['monthly_fee'] + (info['per_seat'] * seat_count)
        total_mrr += mrr
        result.append({
            'client':      client,
            'monthly_fee': info['monthly_fee'],
            'per_seat':    info['per_seat'],
            'seat_count':  seat_count,
            'mrr':         round(mrr, 2),
            'hourly_rate': info['hourly_rate'],
            'unbilled':    unbilled_map.get(client, 0),
        })
    result.sort(key=lambda x: x['mrr'], reverse=True)
    return jsonify({'clients': result, 'total_mrr': round(total_mrr, 2)})

# ── Invoice create + PDF ──────────────────────────────────────────────────────

def _generate_invoice_pdf(inv_id, client, issued, due, entries, subtotal, tax_rate, total, notes=''):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_RIGHT, TA_LEFT, TA_CENTER

    pdf_path = os.path.join(INVOICE_DIR, f'invoice-{inv_id}.pdf')
    doc = SimpleDocTemplate(pdf_path, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    PRIMARY   = colors.HexColor('#1D6FFF')
    DARK      = colors.HexColor('#0a0a0a')
    GRAY      = colors.HexColor('#6b7280')
    LIGHTGRAY = colors.HexColor('#f3f4f6')
    WHITE     = colors.white

    h1 = ParagraphStyle('h1', fontSize=26, textColor=PRIMARY,    fontName='Helvetica-Bold')
    h2 = ParagraphStyle('h2', fontSize=11, textColor=DARK,       fontName='Helvetica-Bold')
    sm = ParagraphStyle('sm', fontSize=9,  textColor=GRAY,       fontName='Helvetica')
    rt = ParagraphStyle('rt', fontSize=9,  textColor=DARK,       fontName='Helvetica', alignment=TA_RIGHT)

    story = []

    # Header
    header_data = [[
        Paragraph(COMPANY_NAME,  h1),
        Paragraph(f'<b>INVOICE</b>', ParagraphStyle('inv', fontSize=20, textColor=GRAY,
                  fontName='Helvetica-Bold', alignment=TA_RIGHT))
    ]]
    header_tbl = Table(header_data, colWidths=[4*inch, 3*inch])
    header_tbl.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(header_tbl)
    story.append(Spacer(1, 6))

    # Company info + invoice meta
    meta_data = [[
        Paragraph(f'{COMPANY_ADDR}<br/>{COMPANY_EMAIL}<br/>{COMPANY_PHONE}<br/>{COMPANY_WEBSITE}', sm),
        Paragraph(
            f'<b>Invoice #:</b> {inv_id}<br/>'
            f'<b>Issued:</b>    {issued}<br/>'
            f'<b>Due:</b>       {due}<br/>'
            f'<b>Bill To:</b>   {client}', rt)
    ]]
    meta_tbl = Table(meta_data, colWidths=[4*inch, 3*inch])
    meta_tbl.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(meta_tbl)
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width='100%', thickness=2, color=PRIMARY))
    story.append(Spacer(1, 12))

    # Line items table
    col_headers = ['Date', 'Description', 'Hours', 'Rate', 'Amount']
    rows = [col_headers]
    for e in entries:
        rows.append([
            e['date'],
            e['description'],
            f"{e['hours']:.2f}",
            f"${e['rate']:.2f}",
            f"${e['hours']*e['rate']:.2f}"
        ])

    items_tbl = Table(rows, colWidths=[0.85*inch, 3.5*inch, 0.7*inch, 0.8*inch, 0.85*inch])
    ts = TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  PRIMARY),
        ('TEXTCOLOR',    (0,0), (-1,0),  WHITE),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,-1), 9),
        ('ALIGN',        (2,0), (-1,-1), 'RIGHT'),
        ('ALIGN',        (0,0), (1,-1),  'LEFT'),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LIGHTGRAY]),
        ('GRID',         (0,0), (-1,-1), 0.25, colors.HexColor('#e5e7eb')),
        ('TOPPADDING',   (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0), (-1,-1), 5),
        ('LEFTPADDING',  (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ])
    items_tbl.setStyle(ts)
    story.append(items_tbl)
    story.append(Spacer(1, 16))

    # Totals
    tax_amt = round(subtotal * tax_rate / 100, 2)
    totals = [['', '', '', 'Subtotal:', f'${subtotal:.2f}']]
    if tax_rate:
        totals.append(['','','', f'Tax ({tax_rate}%):', f'${tax_amt:.2f}'])
    totals.append(['','','', 'TOTAL DUE:', f'${total:.2f}'])
    tot_tbl = Table(totals, colWidths=[0.85*inch, 3.5*inch, 0.7*inch, 0.8*inch, 0.85*inch])
    tot_tbl.setStyle(TableStyle([
        ('FONTNAME',  (3,-1),(-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',  (0,0), (-1,-1), 9),
        ('ALIGN',     (3,0), (-1,-1), 'RIGHT'),
        ('LINEABOVE', (3,-1),(-1,-1), 1.5, PRIMARY),
        ('TEXTCOLOR', (3,-1),(-1,-1), PRIMARY),
        ('FONTSIZE',  (3,-1),(-1,-1), 11),
    ]))
    story.append(tot_tbl)

    if notes:
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width='100%', thickness=0.5, color=LIGHTGRAY))
        story.append(Spacer(1, 8))
        story.append(Paragraph(f'<b>Notes:</b> {notes}', sm))

    # Footer
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width='100%', thickness=0.5, color=LIGHTGRAY))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f'Thank you for your business! | {COMPANY_NAME} | {COMPANY_EMAIL} | {COMPANY_PHONE}',
        ParagraphStyle('ft', fontSize=8, textColor=GRAY, fontName='Helvetica',
                       alignment=TA_CENTER)))

    doc.build(story)
    return pdf_path


@app.route('/api/billing/invoices', methods=['POST'])
@login_required
def billing_invoice_create():
    d = request.get_json(force=True)
    client   = d.get('client','').strip()
    tax_rate = float(d.get('tax_rate', 0))
    notes    = d.get('notes','')
    if not client:
        return jsonify({'ok': False, 'error': 'client required'}), 400

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        # Grab all unbilled billable entries for this client
        entries = [dict(r) for r in conn.execute(
            'SELECT * FROM time_entries WHERE client=? AND invoiced=0 AND billable=1 '
            'ORDER BY date', (client,)).fetchall()]
        if not entries:
            return jsonify({'ok': False, 'error': 'No unbilled time entries for this client'}), 400

        subtotal  = round(sum(e['hours'] * e['rate'] for e in entries), 2)
        tax_amt   = round(subtotal * tax_rate / 100, 2)
        total     = round(subtotal + tax_amt, 2)
        issued    = datetime.now().strftime('%Y-%m-%d')
        due       = (datetime.now().replace(day=1) if False else
                     datetime.now().strftime('%Y-') +
                     f"{int(datetime.now().strftime('%m'))+1:02d}-01"
                     if int(datetime.now().strftime('%m')) < 12
                     else datetime.now().strftime('%Y+1-01-01'))
        inv_id    = f"INV-{datetime.now().strftime('%Y%m')}-{client[:4].upper()}-{secrets.token_hex(3).upper()}"

        pdf_path  = _generate_invoice_pdf(inv_id, client, issued, issued, entries,
                                          subtotal, tax_rate, total, notes)

        conn.execute('''INSERT INTO invoices
                        (id,client,issued_date,due_date,subtotal,tax_rate,total,status,notes,pdf_path)
                        VALUES (?,?,?,?,?,?,?,"draft",?,?)''',
                     (inv_id, client, issued, issued, subtotal, tax_rate, total, notes, pdf_path))
        conn.execute('UPDATE time_entries SET invoiced=1, invoice_id=? '
                     'WHERE client=? AND invoiced=0 AND billable=1', (inv_id, client))
        conn.commit()

    return jsonify({'ok': True, 'invoice_id': inv_id, 'total': total,
                    'entries': len(entries), 'subtotal': subtotal})


@app.route('/api/billing/invoices', methods=['GET'])
@login_required
def billing_invoices_list():
    client = request.args.get('client','')
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        q = 'SELECT * FROM invoices'
        params = []
        if client:
            q += ' WHERE client=?'; params.append(client)
        q += ' ORDER BY created_at DESC'
        rows = conn.execute(q, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/billing/invoices/<inv_id>/pdf')
@login_required
def billing_invoice_pdf(inv_id):
    from flask import send_file
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute('SELECT pdf_path FROM invoices WHERE id=?', (inv_id,)).fetchone()
    if not row or not os.path.exists(row[0]):
        return jsonify({'error': 'PDF not found'}), 404
    return send_file(row[0], mimetype='application/pdf',
                     download_name=f'{inv_id}.pdf', as_attachment=True)


@app.route('/api/billing/invoices/<inv_id>/email', methods=['POST'])
@login_required
def billing_invoice_email(inv_id):
    if not SMTP_HOST:
        return jsonify({'ok': False, 'error': 'SMTP not configured'}), 400
    d = request.get_json(force=True) or {}
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        inv = conn.execute('SELECT * FROM invoices WHERE id=?', (inv_id,)).fetchone()
    if not inv:
        return jsonify({'ok': False, 'error': 'Invoice not found'}), 404
    inv = dict(inv)
    to_addr = d.get('to', SMTP_TO)

    msg = MIMEMultipart()
    msg['Subject'] = f"Invoice {inv_id} from {COMPANY_NAME} — ${inv['total']:.2f} due"
    msg['From']    = SMTP_FROM
    msg['To']      = to_addr
    body = f"""
Hi,

Please find attached invoice {inv_id} for {inv['client']}.

  Amount Due:  ${inv['total']:.2f}
  Issued:      {inv['issued_date']}
  Invoice #:   {inv_id}

Thank you for your business!

{COMPANY_NAME}
{COMPANY_PHONE}
{COMPANY_EMAIL}
{COMPANY_WEBSITE}
""".strip()
    msg.attach(MIMEText(body, 'plain'))

    if os.path.exists(inv['pdf_path']):
        with open(inv['pdf_path'], 'rb') as f:
            part = MIMEBase('application','octet-stream')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{inv_id}.pdf"')
        msg.attach(part)

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls(context=ctx)
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, to_addr, msg.as_string())
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE invoices SET status='sent', emailed_at=datetime('now') WHERE id=?",
                         (inv_id,))
            conn.commit()
        return jsonify({'ok': True, 'sent_to': to_addr})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/billing/invoices/<inv_id>/status', methods=['POST'])
@login_required
def billing_invoice_status(inv_id):
    status = request.get_json(force=True).get('status','')
    if status not in ('draft','sent','paid','void'):
        return jsonify({'ok': False, 'error': 'invalid status'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('UPDATE invoices SET status=? WHERE id=?', (status, inv_id))
        conn.commit()
    return jsonify({'ok': True})


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT EMAIL AUTOMATION — drip campaigns, security tips, welcome sequences
# ═══════════════════════════════════════════════════════════════════════════════

def _render_template_str(text, contact, client='', extra={}):
    """Simple {var} substitution for email templates."""
    from datetime import datetime as _dt
    subs = {
        'contact_name': contact.get('name', 'there'),
        'client':       client or contact.get('client', ''),
        'email':        contact.get('email', ''),
        'month':        _dt.now().strftime('%B %Y'),
        'threats_blocked': extra.get('threats_blocked', '0'),
        'backups_ok':   extra.get('backups_ok', '0'),
        'company':      COMPANY_NAME,
        'phone':        COMPANY_PHONE,
        'company_email': COMPANY_EMAIL,
    }
    for k, v in subs.items():
        text = text.replace('{'+k+'}', str(v))
    return text

def _send_email_html(to_addr, to_name, subject, body_html, body_text):
    """Send HTML email. Returns (ok, error_str)."""
    if not SMTP_HOST:
        return False, 'SMTP not configured'
    try:
        import smtplib, ssl
        from email.mime.multipart import MIMEMultipart as _MP
        from email.mime.text import MIMEText as _MT
        msg = _MP('alternative')
        msg['Subject'] = subject
        msg['From']    = f'{COMPANY_NAME} <{SMTP_FROM}>'
        msg['To']      = f'{to_name} <{to_addr}>'
        msg.attach(_MT(body_text, 'plain'))
        msg.attach(_MT(body_html, 'html'))
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls(context=ctx)
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, to_addr, msg.as_string())
        return True, ''
    except Exception as e:
        return False, str(e)

def _enqueue_sequence_for_contact(contact_id, sequence_id=1):
    """Queue all steps of a sequence for a new contact."""
    from datetime import datetime as _dt, timedelta
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        steps = conn.execute(
            'SELECT * FROM email_sequence_steps WHERE sequence_id=? ORDER BY step_order',
            (sequence_id,)).fetchall()
        contact = conn.execute('SELECT * FROM client_contacts WHERE id=?',
                               (contact_id,)).fetchone()
        if not contact or not steps:
            return
        for step in steps:
            tmpl = conn.execute('SELECT subject FROM email_templates WHERE id=?',
                                (step['template_id'],)).fetchone()
            if not tmpl:
                continue
            subj = step['subject_override'] or tmpl['subject']
            scheduled = (_dt.now() + timedelta(days=step['delay_days'])).strftime('%Y-%m-%d %H:%M:%S')
            conn.execute('''INSERT INTO email_queue
                            (contact_id,template_id,subject,scheduled_at,sequence_id,step_id)
                            VALUES (?,?,?,?,?,?)''',
                         (contact_id, step['template_id'], subj,
                          scheduled, sequence_id, step['id']))
        conn.commit()

def _process_email_queue():
    """Background worker: send any due emails in the queue."""
    from datetime import datetime as _dt
    now = _dt.now().strftime('%Y-%m-%d %H:%M:%S')
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        due = conn.execute(
            "SELECT q.*,c.name,c.email,c.client,c.subscribed "
            "FROM email_queue q JOIN client_contacts c ON q.contact_id=c.id "
            "WHERE q.status='pending' AND q.scheduled_at<=? AND c.subscribed=1",
            (now,)).fetchall()
        for row in due:
            tmpl = conn.execute('SELECT * FROM email_templates WHERE id=?',
                                (row['template_id'],)).fetchone()
            if not tmpl:
                conn.execute("UPDATE email_queue SET status='skip' WHERE id=?", (row['id'],))
                continue
            contact = {'name': row['name'], 'email': row['email'], 'client': row['client']}
            subject  = _render_template_str(row['subject'], contact, row['client'])
            html     = _render_template_str(tmpl['body_html'], contact, row['client'])
            txt      = _render_template_str(tmpl['body_text'], contact, row['client'])
            ok, err  = _send_email_html(row['email'], row['name'], subject, html, txt)
            status   = 'sent' if ok else 'failed'
            sent_at  = now if ok else ''
            conn.execute("UPDATE email_queue SET status=?,sent_at=? WHERE id=?",
                         (status, sent_at, row['id']))
            conn.execute("INSERT INTO email_log (contact_id,email,subject,status,error) VALUES (?,?,?,?,?)",
                         (row['contact_id'], row['email'], subject, status, err))
        conn.commit()

# Background email sender — runs every 15 minutes
def _email_queue_loop():
    while True:
        try:
            _process_email_queue()
        except Exception as e:
            app.logger.warning(f'Email queue error: {e}')
        time.sleep(900)

# ── Email automation routes ───────────────────────────────────────────────────

@app.route('/outreach')
@login_required
def outreach_page():
    return render_template('outreach.html')

@app.route('/api/outreach/contacts', methods=['GET'])
@login_required
def outreach_contacts_get():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM client_contacts ORDER BY client,name').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/outreach/contacts', methods=['POST'])
@login_required
def outreach_contacts_add():
    d = request.get_json(force=True)
    name   = d.get('name','').strip()
    email  = d.get('email','').strip().lower()
    client = d.get('client','').strip()
    if not name or not email or not client:
        return jsonify({'ok': False, 'error': 'name, email, client required'}), 400
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute(
                'INSERT INTO client_contacts (client,name,email) VALUES (?,?,?)',
                (client, name, email))
            conn.commit()
            contact_id = cur.lastrowid
        # Kick off welcome sequence
        _enqueue_sequence_for_contact(contact_id, sequence_id=1)
        return jsonify({'ok': True, 'id': contact_id,
                        'message': f'Added {name} — welcome sequence queued (email 1 sends now)'})
    except sqlite3.IntegrityError:
        return jsonify({'ok': False, 'error': f'{email} already exists'}), 409

@app.route('/api/outreach/contacts/<int:cid>', methods=['DELETE'])
@login_required
def outreach_contacts_delete(cid):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('DELETE FROM client_contacts WHERE id=?', (cid,))
        conn.execute('DELETE FROM email_queue WHERE contact_id=? AND status="pending"', (cid,))
        conn.commit()
    return jsonify({'ok': True})

@app.route('/api/outreach/contacts/<int:cid>/unsubscribe', methods=['POST'])
@login_required
def outreach_unsubscribe(cid):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('UPDATE client_contacts SET subscribed=0 WHERE id=?', (cid,))
        conn.commit()
    return jsonify({'ok': True})

@app.route('/api/outreach/contacts/<int:cid>/resubscribe', methods=['POST'])
@login_required
def outreach_resubscribe(cid):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('UPDATE client_contacts SET subscribed=1 WHERE id=?', (cid,))
        conn.commit()
    return jsonify({'ok': True})

@app.route('/api/outreach/queue', methods=['GET'])
@login_required
def outreach_queue_get():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('''SELECT q.*,c.name,c.email,c.client,t.name as tpl_name
                               FROM email_queue q
                               JOIN client_contacts c ON q.contact_id=c.id
                               JOIN email_templates t ON q.template_id=t.id
                               ORDER BY q.scheduled_at''').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/outreach/log', methods=['GET'])
@login_required
def outreach_log_get():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT l.*,c.name,c.client FROM email_log l '
            'JOIN client_contacts c ON l.contact_id=c.id '
            'ORDER BY l.sent_at DESC LIMIT 200').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/outreach/templates', methods=['GET'])
@login_required
def outreach_templates_get():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT id,name,subject,category FROM email_templates ORDER BY id').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/outreach/send-now', methods=['POST'])
@login_required
def outreach_send_now():
    """Send a specific template to a contact immediately."""
    d = request.get_json(force=True)
    contact_id  = d.get('contact_id')
    template_id = d.get('template_id')
    if not contact_id or not template_id:
        return jsonify({'ok': False, 'error': 'contact_id and template_id required'}), 400
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        contact = conn.execute('SELECT * FROM client_contacts WHERE id=?', (contact_id,)).fetchone()
        tmpl    = conn.execute('SELECT * FROM email_templates WHERE id=?', (template_id,)).fetchone()
        if not contact or not tmpl:
            return jsonify({'ok': False, 'error': 'Not found'}), 404
        c = dict(contact)
        subject = _render_template_str(tmpl['subject'], c, c['client'])
        html    = _render_template_str(tmpl['body_html'], c, c['client'])
        txt     = _render_template_str(tmpl['body_text'], c, c['client'])
        ok, err = _send_email_html(c['email'], c['name'], subject, html, txt)
        conn.execute("INSERT INTO email_log (contact_id,email,subject,status,error) VALUES (?,?,?,?,?)",
                     (contact_id, c['email'], subject, 'sent' if ok else 'failed', err))
        conn.commit()
    if ok:
        return jsonify({'ok': True, 'sent_to': c['email']})
    return jsonify({'ok': False, 'error': err}), 500

@app.route('/api/outreach/process-queue', methods=['POST'])
@login_required
def outreach_process_now():
    """Force-run the queue processor (for testing)."""
    _process_email_queue()
    return jsonify({'ok': True})

# Start email queue background thread
import threading as _et
_et.Thread(target=_email_queue_loop, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════════
# SMS CHAT — Two-way SMS via Telnyx. Clients text in, you reply from SOC.
# Telnyx webhook URL: https://soc.somotechs.com/api/sms/inbound
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/sms')
@login_required
def sms_page():
    return render_template('sms.html')

@app.route('/api/sms/inbound', methods=['POST'])
def sms_inbound():
    """Telnyx webhook — fires when someone texts your number."""
    try:
        data = request.get_json(force=True) or {}
        # Telnyx v2 webhook envelope
        payload = data.get('data', {}).get('payload', data)
        from_num = payload.get('from', {}).get('phone_number') or payload.get('from','')
        to_num   = payload.get('to',   [{}])[0].get('phone_number', '') if isinstance(payload.get('to'), list) else payload.get('to','')
        body     = payload.get('text') or payload.get('body','')
        if not from_num or not body:
            return jsonify({'ok': True})   # ack but ignore malformed
        # Look up contact name
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            contact = conn.execute('SELECT * FROM sms_contacts WHERE phone=?', (from_num,)).fetchone()
            name   = contact['name']   if contact else from_num
            client = contact['client'] if contact else ''
            conn.execute('''INSERT INTO sms_messages
                            (direction,from_num,to_num,body,contact_name,client,read)
                            VALUES ("inbound",?,?,?,?,?,0)''',
                         (from_num, to_num, body, name, client))
            conn.commit()
        # Email notify disabled — see soc.somotechs.com/sms for messages
        # _send_email_notify(
        #     f'📱 SMS from {name} ({from_num})',
        #     f'From: {name} ({from_num})\nClient: {client or "unknown"}\n\n{body}\n\nReply at soc.somotechs.com/sms'
        # )
    except Exception as e:
        app.logger.warning(f'SMS inbound error: {e}')
    return jsonify({'ok': True})

@app.route('/api/sms/messages')
@login_required
def sms_messages():
    phone = request.args.get('phone', '')
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if phone:
            rows = conn.execute(
                'SELECT * FROM sms_messages WHERE from_num=? OR to_num=? ORDER BY created_at',
                (phone, phone)).fetchall()
            conn.execute('UPDATE sms_messages SET read=1 WHERE from_num=? AND read=0', (phone,))
        else:
            # Conversation list — latest per number
            rows = conn.execute('''
                SELECT m.*, MAX(m.created_at) as last_msg
                FROM sms_messages m
                GROUP BY CASE WHEN m.direction="inbound" THEN m.from_num ELSE m.to_num END
                ORDER BY last_msg DESC''').fetchall()
        conn.commit()
    return jsonify([dict(r) for r in rows])

@app.route('/api/sms/unread')
@login_required
def sms_unread():
    with sqlite3.connect(DB_PATH) as conn:
        count = conn.execute(
            'SELECT COUNT(*) FROM sms_messages WHERE read=0 AND direction="inbound"').fetchone()[0]
    return jsonify({'unread': count})

@app.route('/api/sms/send', methods=['POST'])
@login_required
def sms_send():
    d = request.get_json(force=True)
    to   = d.get('to','').strip()
    body = d.get('body','').strip()
    if not to or not body:
        return jsonify({'ok': False, 'error': 'to and body required'}), 400
    if not (TELNYX_API_KEY and TELNYX_FROM):
        return jsonify({'ok': False, 'error': 'Telnyx not configured — add TELNYX_API_KEY and TELNYX_FROM to .env'}), 400
    try:
        r = requests.post(
            'https://api.telnyx.com/v2/messages',
            headers={'Authorization': f'Bearer {TELNYX_API_KEY}', 'Content-Type': 'application/json'},
            json={'from': TELNYX_FROM, 'to': to, 'text': body},
            timeout=8
        )
        r.raise_for_status()
        # Look up contact
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            contact = conn.execute('SELECT name,client FROM sms_contacts WHERE phone=?', (to,)).fetchone()
            name   = contact['name']   if contact else to
            client = contact['client'] if contact else ''
            conn.execute('''INSERT INTO sms_messages
                            (direction,from_num,to_num,body,contact_name,client,read)
                            VALUES ("outbound",?,?,?,?,?,1)''',
                         (TELNYX_FROM, to, body, name, client))
            conn.commit()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/sms/contacts', methods=['GET'])
@login_required
def sms_contacts_get():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM sms_contacts ORDER BY name').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/sms/contacts', methods=['POST'])
@login_required
def sms_contacts_add():
    d = request.get_json(force=True)
    phone  = d.get('phone','').strip()
    name   = d.get('name','').strip()
    client = d.get('client','').strip()
    if not phone or not name:
        return jsonify({'ok': False, 'error': 'phone and name required'}), 400
    if not phone.startswith('+'):
        phone = '+1' + phone.replace('-','').replace('(','').replace(')','').replace(' ','')
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute('INSERT INTO sms_contacts (phone,name,client) VALUES (?,?,?)',
                         (phone, name, client))
            conn.commit()
        return jsonify({'ok': True})
    except sqlite3.IntegrityError:
        return jsonify({'ok': False, 'error': 'number already exists'}), 409

@app.route('/api/sms/contacts/<int:cid>', methods=['DELETE'])
@login_required
def sms_contacts_delete(cid):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('DELETE FROM sms_contacts WHERE id=?', (cid,))
        conn.commit()
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
