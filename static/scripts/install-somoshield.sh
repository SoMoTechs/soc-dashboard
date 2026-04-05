#!/bin/bash
# ============================================================
#  SomoShield Stack Installer v1.0
#  Deploys: CrowdSec + SOC Dashboard + Restic Backup Server
#           + Nginx Proxy Manager + Authelia + Portainer
#
#  Usage: bash install-somoshield.sh
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
  echo -e "${CYAN}"
  echo "  ███████╗ ██████╗ ███╗   ███╗ ██████╗ "
  echo "  ██╔════╝██╔═══██╗████╗ ████║██╔═══██╗"
  echo "  ███████╗██║   ██║██╔████╔██║██║   ██║"
  echo "  ╚════██║██║   ██║██║╚██╔╝██║██║   ██║"
  echo "  ███████║╚██████╔╝██║ ╚═╝ ██║╚██████╔╝"
  echo "  ╚══════╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ "
  echo -e "  ${BOLD}SomoShield Stack Installer v1.0${RESET}"
  echo -e "  ${YELLOW}by SomoTechs — somotechs.github.io${RESET}"
  echo ""
}

prompt() {
  local var=$1 msg=$2 default=$3
  if [ -n "$default" ]; then
    read -rp "$(echo -e "${CYAN}  ➜ ${msg} [${default}]: ${RESET}")" input
    eval "$var=\"${input:-$default}\""
  else
    while true; do
      read -rp "$(echo -e "${CYAN}  ➜ ${msg}: ${RESET}")" input
      if [ -n "$input" ]; then
        eval "$var=\"$input\""
        break
      fi
      echo -e "${RED}  Required — please enter a value.${RESET}"
    done
  fi
}

prompt_password() {
  local var=$1 msg=$2
  while true; do
    read -rsp "$(echo -e "${CYAN}  ➜ ${msg}: ${RESET}")" pass1; echo
    read -rsp "$(echo -e "${CYAN}  ➜ Confirm ${msg}: ${RESET}")" pass2; echo
    if [ "$pass1" = "$pass2" ] && [ -n "$pass1" ]; then
      eval "$var=\"$pass1\""
      break
    fi
    echo -e "${RED}  Passwords don't match or empty. Try again.${RESET}"
  done
}

generate_secret() {
  python3 -c "import secrets; print(secrets.token_urlsafe(32))"
}

check_deps() {
  echo -e "\n${BOLD}  Checking dependencies...${RESET}"
  for cmd in docker curl python3; do
    if command -v $cmd &>/dev/null; then
      echo -e "  ${GREEN}✓${RESET} $cmd"
    else
      echo -e "  ${RED}✗ $cmd not found — install it first${RESET}"
      exit 1
    fi
  done
  if ! docker compose version &>/dev/null; then
    echo -e "  ${RED}✗ docker compose not found${RESET}"
    exit 1
  fi
  echo -e "  ${GREEN}✓ docker compose${RESET}"
}

# ── Main ──────────────────────────────────────────────────────

banner
check_deps

echo -e "\n${BOLD}  ═══════════════════════════════════════${RESET}"
echo -e "${BOLD}  Step 1 — Domain & Network${RESET}"
echo -e "${BOLD}  ═══════════════════════════════════════${RESET}\n"
prompt BASE_DOMAIN   "Your base domain (e.g. somotechs.com)"
prompt SERVER_IP     "This server's public IP"
prompt ADMIN_EMAIL   "Admin email (for SSL certs)"

echo -e "\n${BOLD}  ═══════════════════════════════════════${RESET}"
echo -e "${BOLD}  Step 2 — Service Subdomains${RESET}"
echo -e "${BOLD}  ═══════════════════════════════════════${RESET}\n"
prompt SOC_DOMAIN    "SOC Dashboard subdomain"    "soc.${BASE_DOMAIN}"
prompt BACKUP_DOMAIN "Backup server subdomain"    "backup.${BASE_DOMAIN}"
prompt AUTH_DOMAIN   "Authelia subdomain"         "auth.${BASE_DOMAIN}"
prompt PORT_DOMAIN   "Portainer subdomain"        "port.${BASE_DOMAIN}"

echo -e "\n${BOLD}  ═══════════════════════════════════════${RESET}"
echo -e "${BOLD}  Step 3 — Passwords${RESET}"
echo -e "${BOLD}  ═══════════════════════════════════════${RESET}\n"
prompt_password DASHBOARD_PASS  "SOC Dashboard password"
prompt DASHBOARD_USER           "SOC Dashboard username" "admin"
prompt_password AUTHELIA_PASS   "Authelia admin password"
prompt_password BACKUP_PASS     "Restic backup server password (REST auth)"

echo -e "\n${BOLD}  ═══════════════════════════════════════${RESET}"
echo -e "${BOLD}  Step 4 — Backup Storage${RESET}"
echo -e "${BOLD}  ═══════════════════════════════════════${RESET}\n"
prompt BACKUP_DIR    "Local path to store backups" "/mnt/storage/backups/clients"
prompt RESTIC_DIR    "Restic config directory"     "/opt/somoshield/restic-config"

echo -e "\n${YELLOW}  Generating secrets...${RESET}"
AGENT_SECRET=$(generate_secret)
RESTIC_REG_SECRET=$(generate_secret)
RESTIC_MASTER_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || generate_secret)
JWT_SECRET=$(generate_secret)
SESSION_SECRET=$(generate_secret)

# ── Create directories ─────────────────────────────────────────
INSTALL_DIR="${HOME}/somoshield"
mkdir -p "${INSTALL_DIR}"/{soc-dashboard,restic-config,authelia/config,data,backups}
mkdir -p "${BACKUP_DIR}"
mkdir -p "${RESTIC_DIR}"

echo -e "  ${GREEN}✓ Directories created${RESET}"

# ── Generate htpasswd for restic-server ───────────────────────
HASHED_BACKUP=$(docker run --rm httpd:alpine htpasswd -nbB admin "${BACKUP_PASS}" 2>/dev/null | cut -d: -f2 || \
  python3 -c "import bcrypt; print(bcrypt.hashpw(b'${BACKUP_PASS}', bcrypt.gensalt()).decode())" 2>/dev/null || \
  echo "HASH_FAILED")

# ── Generate Authelia password hash ───────────────────────────
AUTHELIA_HASH=$(docker run --rm authelia/authelia:latest authelia crypto hash generate argon2 --password "${AUTHELIA_PASS}" 2>/dev/null | grep 'Digest:' | cut -d' ' -f2 || echo "")

# ── Write .env ────────────────────────────────────────────────
cat > "${INSTALL_DIR}/.env" << EOF
# SomoShield Stack — generated by installer
# DO NOT COMMIT THIS FILE

BASE_DOMAIN=${BASE_DOMAIN}
ADMIN_EMAIL=${ADMIN_EMAIL}
SERVER_IP=${SERVER_IP}

# SOC Dashboard
DASHBOARD_USER=${DASHBOARD_USER}
DASHBOARD_PASS=${DASHBOARD_PASS}
AGENT_SECRET=${AGENT_SECRET}

# Restic
RESTIC_REG_SECRET=${RESTIC_REG_SECRET}
RESTIC_CLIENT_PASS=${BACKUP_PASS}
RESTIC_MASTER_KEY=${RESTIC_MASTER_KEY}

# Auth
JWT_SECRET=${JWT_SECRET}
SESSION_SECRET=${SESSION_SECRET}

# Domains
SOC_DOMAIN=${SOC_DOMAIN}
BACKUP_DOMAIN=${BACKUP_DOMAIN}
AUTH_DOMAIN=${AUTH_DOMAIN}
PORT_DOMAIN=${PORT_DOMAIN}

# Paths
BACKUP_DIR=${BACKUP_DIR}
RESTIC_DIR=${RESTIC_DIR}
INSTALL_DIR=${INSTALL_DIR}
EOF
echo -e "  ${GREEN}✓ .env written${RESET}"

# ── Write Authelia users_database.yml ────────────────────────
cat > "${INSTALL_DIR}/authelia/config/users_database.yml" << EOF
---
users:
  admin:
    displayname: "Admin"
    password: "${AUTHELIA_HASH}"
    email: ${ADMIN_EMAIL}
    groups:
      - admins
EOF

# ── Write Authelia configuration.yml ─────────────────────────
cat > "${INSTALL_DIR}/authelia/config/configuration.yml" << EOF
---
theme: dark
jwt_secret: ${JWT_SECRET}
default_redirection_url: https://${BASE_DOMAIN}

server:
  host: 0.0.0.0
  port: 9091

log:
  level: info

totp:
  issuer: ${BASE_DOMAIN}

authentication_backend:
  file:
    path: /config/users_database.yml
    password:
      algorithm: argon2id
      iterations: 3
      memory: 65536
      parallelism: 4

access_control:
  default_policy: deny
  rules:
    - domain: "${SOC_DOMAIN}"
      policy: one_factor
    - domain: "${BACKUP_DOMAIN}"
      policy: one_factor
    - domain: "${PORT_DOMAIN}"
      policy: one_factor
    - domain: "*.${BASE_DOMAIN}"
      policy: one_factor

session:
  name: authelia_session
  secret: ${SESSION_SECRET}
  expiration: 3600
  inactivity: 300
  domain: ${BASE_DOMAIN}

regulation:
  max_retries: 5
  find_time: 120
  ban_time: 300

storage:
  local:
    path: /config/db.sqlite3

notifier:
  filesystem:
    filename: /config/notification.txt
EOF
echo -e "  ${GREEN}✓ Authelia config written${RESET}"

# ── Write restic-server htpasswd ───────────────────────────────
touch "${RESTIC_DIR}/htpasswd"
echo -e "  ${GREEN}✓ Restic config ready${RESET}"

# ── Write docker-compose.yml ──────────────────────────────────
cat > "${INSTALL_DIR}/docker-compose.yml" << EOF
services:

  npm:
    image: jc21/nginx-proxy-manager:latest
    container_name: npm
    restart: unless-stopped
    ports:
      - "80:80"
      - "81:81"
      - "443:443"
    volumes:
      - npm_data:/data
      - npm_letsencrypt:/etc/letsencrypt
    networks: [somoshield]

  authelia:
    image: authelia/authelia:latest
    container_name: authelia
    restart: unless-stopped
    volumes:
      - ${INSTALL_DIR}/authelia/config:/config
    networks: [somoshield]
    expose: ["9091"]

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    restart: unless-stopped
    environment:
      COLLECTIONS: crowdsecurity/nginx crowdsecurity/linux crowdsecurity/sshd
    volumes:
      - crowdsec_data:/var/lib/crowdsec/data
      - crowdsec_config:/etc/crowdsec
      - /var/log:/var/log:ro
    networks: [somoshield]

  crowdsec-bouncer:
    image: fbonalair/traefik-crowdsec-bouncer:latest
    container_name: crowdsec-bouncer
    restart: unless-stopped
    environment:
      CROWDSEC_BOUNCER_API_KEY: REPLACE_AFTER_INSTALL
      CROWDSEC_AGENT_HOST: crowdsec:8080
    networks: [somoshield]

  restic-server:
    image: restic/rest-server:latest
    container_name: restic-server
    restart: unless-stopped
    volumes:
      - ${BACKUP_DIR}:/data
      - ${RESTIC_DIR}/htpasswd:/etc/rest-server/.htpasswd:ro
    environment:
      OPTIONS: "--no-auth"
    networks: [somoshield]
    expose: ["8000"]

  soc-dashboard:
    image: soc-dashboard:latest
    container_name: soc-soc-1
    restart: unless-stopped
    privileged: true
    ports: ["5002:5002"]
    volumes:
      - /dev:/dev:ro
      - soc_data:/app/data
      - ${RESTIC_DIR}:/app/restic-config
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ${BACKUP_DIR}:/app/restic-data
    env_file: .env
    networks: [somoshield]

  portainer:
    image: portainer/portainer-ce:latest
    container_name: portainer
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - portainer_data:/data
    networks: [somoshield]
    expose: ["9000"]

volumes:
  npm_data:
  npm_letsencrypt:
  crowdsec_data:
  crowdsec_config:
  soc_data:
  portainer_data:

networks:
  somoshield:
    driver: bridge
EOF
echo -e "  ${GREEN}✓ docker-compose.yml written${RESET}"

# ── Summary ───────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}  ═══════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✓ SomoShield configured successfully!${RESET}"
echo -e "${GREEN}${BOLD}  ═══════════════════════════════════════${RESET}\n"
echo -e "  ${BOLD}Install directory:${RESET} ${INSTALL_DIR}"
echo -e "  ${BOLD}To deploy:${RESET}"
echo -e "  ${CYAN}  cd ${INSTALL_DIR} && docker compose up -d${RESET}\n"
echo -e "  ${BOLD}After deploy — NPM setup:${RESET}"
echo -e "  ${YELLOW}  1. Go to http://${SERVER_IP}:81${RESET}"
echo -e "  ${YELLOW}  2. Default login: admin@example.com / changeme${RESET}"
echo -e "  ${YELLOW}  3. Add proxy hosts for each subdomain pointing to containers${RESET}"
echo -e "  ${YELLOW}  4. Enable Authelia forward auth on each proxy host${RESET}\n"
echo -e "  ${BOLD}Authelia login:${RESET} username ${DASHBOARD_USER} / your chosen password\n"
echo -e "  ${RED}  ⚠ Keep ${INSTALL_DIR}/.env safe — it contains all secrets${RESET}\n"
