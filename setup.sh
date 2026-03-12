#!/usr/bin/env bash
# =============================================================================
# OpenClaw Pi 5 Security Setup
# =============================================================================
# Implements defense-in-depth security across 5 layers for running OpenClaw
# AI agent on a Raspberry Pi 5 (ARM64, Pi OS Lite 64-bit).
#
# Usage:
#   sudo ./setup.sh
#
# Sources:
#   - OpenClaw Security Checklist (OWASP ASI01-ASI10)
#   - https://docs.openclaw.ai/gateway/security
#   - https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# Colors & Output
# =============================================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

pass()  { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }
info()  { echo -e "${CYAN}[→]${RESET} $*"; }
header() {
  echo ""
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo -e "${BOLD}${CYAN}  $*${RESET}"
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo ""
}

# =============================================================================
# Pre-flight Checks
# =============================================================================
preflight_checks() {
  header "Pre-flight Checks"

  # Must run as root
  if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root. Use: sudo ./setup.sh"
  fi
  pass "Running as root"

  # Verify ARM64
  ARCH=$(uname -m)
  if [[ "$ARCH" != "aarch64" ]]; then
    fail "Expected ARM64 (aarch64) architecture. Got: $ARCH. This script is for Raspberry Pi 5."
  fi
  pass "Architecture: $ARCH"

  # Check for Raspberry Pi model
  if [[ -f /proc/device-tree/model ]]; then
    PI_MODEL=$(cat /proc/device-tree/model | tr -d '\0')
    info "Detected: $PI_MODEL"
    if ! echo "$PI_MODEL" | grep -qi "raspberry pi 5"; then
      warn "Expected Raspberry Pi 5 but got: $PI_MODEL"
      warn "This script is optimized for Pi 5. Proceed with caution on other models."
      echo ""
      read -rp "Continue anyway? (y/N): " CONTINUE_ANYWAY
      if [[ "$CONTINUE_ANYWAY" != "y" && "$CONTINUE_ANYWAY" != "Y" ]]; then
        fail "Aborted."
      fi
    else
      pass "Raspberry Pi 5 confirmed"
    fi
  else
    warn "Could not read /proc/device-tree/model — not on a Pi or running in a VM"
  fi

  # Check RAM
  TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
  if [[ $TOTAL_RAM_MB -lt 3500 ]]; then
    fail "Minimum 4GB RAM required. Detected: ${TOTAL_RAM_MB}MB. Use the 4GB or 8GB Pi 5 model."
  elif [[ $TOTAL_RAM_MB -lt 7000 ]]; then
    warn "4GB RAM detected (${TOTAL_RAM_MB}MB). 8GB is strongly recommended for OpenClaw + Docker."
  else
    pass "RAM: ${TOTAL_RAM_MB}MB — sufficient"
  fi

  # Check OS
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    info "OS: $PRETTY_NAME"
    if ! echo "$ID" | grep -qi "raspbian\|debian"; then
      warn "Expected Raspberry Pi OS (Debian-based). Got: $ID"
      warn "This script is tested on Raspberry Pi OS Lite 64-bit."
    fi
  fi

  # Check internet connectivity
  info "Checking internet connectivity..."
  if ! curl -s --max-time 10 https://8.8.8.8 &>/dev/null && ! ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
    fail "No internet connectivity. Connect to the internet and retry."
  fi
  pass "Internet connectivity confirmed"

  pass "Pre-flight checks complete"
}

# =============================================================================
# Interactive Config Gathering
# =============================================================================
gather_config() {
  header "Configuration Setup"

  echo "Answer the following questions. Press Enter to accept defaults."
  echo ""

  # Hostname
  read -rp "Hostname for this Pi [openclaw-pi]: " INPUT_HOSTNAME
  HOSTNAME_VAL="${INPUT_HOSTNAME:-openclaw-pi}"

  # SSH public key
  echo ""
  echo "Paste your SSH public key (starts with ssh-rsa, ssh-ed25519, etc.):"
  echo "Or enter a path to your public key file (e.g., /tmp/id_ed25519.pub):"
  read -rp "SSH public key or file path: " SSH_KEY_INPUT
  if [[ -f "$SSH_KEY_INPUT" ]]; then
    SSH_PUBKEY=$(cat "$SSH_KEY_INPUT")
  else
    SSH_PUBKEY="$SSH_KEY_INPUT"
  fi
  if [[ -z "$SSH_PUBKEY" ]]; then
    fail "SSH public key is required. Password auth will be disabled."
  fi
  pass "SSH public key accepted"

  # Deployment mode
  echo ""
  echo "Deployment mode:"
  echo "  1) Docker (recommended — stronger isolation)"
  echo "  2) Host systemd (lighter — uses systemd sandboxing)"
  read -rp "Choose [1/2, default: 1]: " DEPLOY_MODE_INPUT
  case "${DEPLOY_MODE_INPUT:-1}" in
    2) DEPLOY_MODE="host" ;;
    *) DEPLOY_MODE="docker" ;;
  esac
  pass "Deployment mode: $DEPLOY_MODE"

  # SSH allowlist IP/CIDR
  echo ""
  echo "Your IP or CIDR for SSH access (e.g., 192.168.1.0/24 or 10.0.0.5/32):"
  echo "This will be the ONLY IP allowed to SSH into this Pi."
  read -rp "SSH allowlist IP/CIDR: " SSH_ALLOWLIST_IP
  if [[ -z "$SSH_ALLOWLIST_IP" ]]; then
    fail "SSH allowlist IP is required. Cannot leave SSH open to all IPs."
  fi
  pass "SSH restricted to: $SSH_ALLOWLIST_IP"

  # Generate gateway auth token
  GATEWAY_TOKEN=$(openssl rand -hex 32)
  pass "Gateway auth token generated (32-byte random)"

  # Tailscale auth key (optional)
  echo ""
  echo "Tailscale auth key (optional — leave blank to auth manually after setup):"
  echo "Find this at: https://login.tailscale.com/admin/settings/keys"
  read -rp "Tailscale auth key [leave blank to skip]: " TAILSCALE_AUTH_KEY

  # Create operator user for SSH
  echo ""
  read -rp "SSH operator username (the user YOU will SSH in as) [pi-admin]: " OPERATOR_USER_INPUT
  OPERATOR_USER="${OPERATOR_USER_INPUT:-pi-admin}"

  # Confirm before proceeding
  echo ""
  echo -e "${BOLD}Configuration Summary:${RESET}"
  echo "  Hostname:        $HOSTNAME_VAL"
  echo "  Deployment mode: $DEPLOY_MODE"
  echo "  SSH allowlist:   $SSH_ALLOWLIST_IP"
  echo "  SSH operator:    $OPERATOR_USER"
  echo "  Tailscale:       ${TAILSCALE_AUTH_KEY:+"auth key provided"}"
  echo "  Tailscale:       ${TAILSCALE_AUTH_KEY:-"manual auth (will prompt after setup)"}"
  echo "  Gateway token:   [generated — stored in setup.conf]"
  echo ""
  read -rp "Proceed with setup? (y/N): " CONFIRM
  if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    fail "Aborted by user."
  fi

  # Write config
  mkdir -p /opt/openclaw/config
  cat > /opt/openclaw/config/setup.conf << EOF
# OpenClaw Pi Setup Config — generated by setup.sh on $(date)
# chmod 600 — do not share this file
HOSTNAME_VAL="${HOSTNAME_VAL}"
DEPLOY_MODE="${DEPLOY_MODE}"
SSH_ALLOWLIST_IP="${SSH_ALLOWLIST_IP}"
OPERATOR_USER="${OPERATOR_USER}"
GATEWAY_TOKEN="${GATEWAY_TOKEN}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY}"
EOF
  chmod 600 /opt/openclaw/config/setup.conf
  pass "Config saved to /opt/openclaw/config/setup.conf (chmod 600)"
}

# =============================================================================
# Layer 1 — Hardware & OS Hardening
# =============================================================================
layer1_os_hardening() {
  header "Layer 1 — Hardware & OS Hardening"
  info "Addresses: ASI05 (Unexpected Code Execution), ASI10 (Rogue Agents)"

  # System update
  info "Running full system upgrade..."
  apt update -qq
  apt full-upgrade -y -qq
  pass "System updated"

  # Set hostname
  info "Setting hostname to $HOSTNAME_VAL..."
  hostnamectl set-hostname "$HOSTNAME_VAL"
  if ! grep -q "$HOSTNAME_VAL" /etc/hosts; then
    echo "127.0.1.1  $HOSTNAME_VAL" >> /etc/hosts
  fi
  pass "Hostname set: $HOSTNAME_VAL"

  # Create operator user (for SSH access) if not exists
  if ! id "$OPERATOR_USER" &>/dev/null; then
    info "Creating operator user: $OPERATOR_USER..."
    adduser --disabled-password --gecos "" "$OPERATOR_USER"
    usermod -aG sudo "$OPERATOR_USER"
    pass "Operator user created: $OPERATOR_USER"
  else
    pass "Operator user already exists: $OPERATOR_USER"
  fi

  # Install operator user's SSH key
  OPERATOR_HOME=$(eval echo ~"$OPERATOR_USER")
  mkdir -p "$OPERATOR_HOME/.ssh"
  chmod 700 "$OPERATOR_HOME/.ssh"
  echo "$SSH_PUBKEY" >> "$OPERATOR_HOME/.ssh/authorized_keys"
  chmod 600 "$OPERATOR_HOME/.ssh/authorized_keys"
  chown -R "$OPERATOR_USER:$OPERATOR_USER" "$OPERATOR_HOME/.ssh"
  pass "SSH public key installed for $OPERATOR_USER"

  # Create openclaw service user (no login, no sudo)
  if ! id "openclaw" &>/dev/null; then
    info "Creating openclaw service user..."
    adduser --system --no-create-home --shell /usr/sbin/nologin --group openclaw
    pass "openclaw service user created"
  else
    pass "openclaw service user already exists"
  fi

  # Add to docker group if Docker mode
  if [[ "$DEPLOY_MODE" == "docker" ]]; then
    usermod -aG docker openclaw 2>/dev/null || true
  fi

  # Lock / disable default pi user if it exists
  if id "pi" &>/dev/null; then
    info "Locking default pi user..."
    passwd -l pi
    # Remove from sudo group
    deluser pi sudo 2>/dev/null || true
    pass "pi user locked and removed from sudo"
  else
    pass "No default pi user found (already removed or fresh install)"
  fi

  # Unattended upgrades
  info "Installing unattended-upgrades..."
  apt install -y -qq unattended-upgrades apt-listchanges
  cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  pass "Unattended security upgrades enabled"

  # Apply sysctl hardening
  info "Applying kernel hardening parameters..."
  cp "$SCRIPT_DIR/config/sysctl-hardening.conf" /etc/sysctl.d/99-openclaw-hardening.conf
  sysctl -p /etc/sysctl.d/99-openclaw-hardening.conf &>/dev/null || true
  pass "Kernel hardening applied"

  # Disable bluetooth and avahi-daemon
  info "Disabling unnecessary services..."
  for svc in bluetooth avahi-daemon; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      systemctl stop "$svc"
    fi
    systemctl disable "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
  done
  pass "Bluetooth and avahi-daemon disabled"

  # Install watchdog
  info "Installing hardware watchdog..."
  apt install -y -qq watchdog
  # Enable the Pi's hardware watchdog
  # Pi OS Bookworm (64-bit) uses /boot/firmware/config.txt; older uses /boot/config.txt
  BOOT_CONFIG="/boot/firmware/config.txt"
  if [[ ! -f "$BOOT_CONFIG" ]]; then
    BOOT_CONFIG="/boot/config.txt"
  fi
  if [[ -f "$BOOT_CONFIG" ]] && ! grep -q "dtparam=watchdog=on" "$BOOT_CONFIG"; then
    echo "dtparam=watchdog=on" >> "$BOOT_CONFIG"
  elif [[ ! -f "$BOOT_CONFIG" ]]; then
    warn "Could not find boot config.txt — skipping watchdog dtparam (add 'dtparam=watchdog=on' manually)"
  fi
  cat > /etc/watchdog.conf << 'EOF'
watchdog-device = /dev/watchdog
watchdog-timeout = 15
max-load-1 = 24
min-memory = 1
interval = 10
EOF
  systemctl enable --now watchdog 2>/dev/null || true
  pass "Hardware watchdog configured"

  echo ""
  warn "HARDWARE NOTE: Monitor temperature with: vcgencmd measure_temp"
  warn "Alert threshold: > 80°C sustained. Ensure proper heatsink/fan cooling."

  pass "Layer 1 complete"
}

# =============================================================================
# Layer 2 — Isolation & Containment
# =============================================================================
layer2_isolation() {
  header "Layer 2 — Isolation & Containment"
  info "Addresses: ASI05, ASI10"

  # Create workspace directories
  info "Creating OpenClaw directory structure..."
  mkdir -p /opt/openclaw/{workspace,config,logs}
  chown -R openclaw:openclaw /opt/openclaw
  chmod 700 /opt/openclaw
  chmod 750 /opt/openclaw/workspace
  chmod 700 /opt/openclaw/config
  chmod 750 /opt/openclaw/logs
  pass "Directory structure created at /opt/openclaw/"

  if [[ "$DEPLOY_MODE" == "docker" ]]; then
    # Install Docker
    if ! command -v docker &>/dev/null; then
      info "Installing Docker (official script)..."
      curl -fsSL https://get.docker.com | sh
      pass "Docker installed"
    else
      pass "Docker already installed"
    fi

    # Verify ARM64
    DOCKER_ARCH=$(docker info 2>/dev/null | grep Architecture | awk '{print $2}')
    info "Docker architecture: $DOCKER_ARCH"
    if [[ "$DOCKER_ARCH" != "aarch64" ]]; then
      warn "Unexpected Docker architecture: $DOCKER_ARCH (expected aarch64)"
    else
      pass "Docker ARM64 confirmed"
    fi

    # Add operator user to docker group
    usermod -aG docker "$OPERATOR_USER" 2>/dev/null || true

    # Install docker-compose plugin
    if ! docker compose version &>/dev/null; then
      info "Installing docker-compose plugin..."
      apt install -y -qq docker-compose-plugin
    fi
    pass "Docker Compose available"

    # Copy docker-compose.yml
    cp "$SCRIPT_DIR/config/docker-compose.yml" /opt/openclaw/docker-compose.yml
    chown openclaw:openclaw /opt/openclaw/docker-compose.yml
    pass "Docker Compose config installed"

    # Configure DOCKER-USER iptables chain for UFW bypass fix
    info "Configuring DOCKER-USER iptables chain to fix UFW bypass..."
    UFW_AFTER_RULES="/etc/ufw/after.rules"
    if ! grep -q "DOCKER-USER" "$UFW_AFTER_RULES" 2>/dev/null; then
      cat >> "$UFW_AFTER_RULES" << 'DOCKERRULES'

# OpenClaw Pi — DOCKER-USER chain rules
# Prevents Docker-published ports from bypassing UFW rules
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A DOCKER-USER -s 127.0.0.0/8 -j RETURN
-A DOCKER-USER -m conntrack --ctstate NEW -j DROP
-A DOCKER-USER -j RETURN
COMMIT
DOCKERRULES
      pass "DOCKER-USER chain rules added to UFW after.rules"
    else
      pass "DOCKER-USER chain already configured"
    fi

    pass "Docker mode isolation configured"

  else
    # Host mode — systemd sandboxing
    info "Configuring host mode systemd sandboxing..."

    # Remove openclaw from sudo (already system user, but confirm)
    deluser openclaw sudo 2>/dev/null || true

    # Install systemd service
    cp "$SCRIPT_DIR/config/openclaw.service" /etc/systemd/system/openclaw.service
    systemctl daemon-reload
    pass "Systemd service unit installed (not yet started — install OpenClaw first)"

    pass "Host mode isolation configured"
  fi

  pass "Layer 2 complete"
}

# =============================================================================
# Layer 3 — Network Security
# =============================================================================
layer3_network() {
  header "Layer 3 — Network Security"
  info "Addresses: ASI01 (Goal Hijacking), ASI04 (Supply Chain)"

  # Install UFW
  info "Installing and configuring UFW firewall..."
  apt install -y -qq ufw

  # Reset UFW to defaults (idempotent)
  ufw --force reset

  # Default policies
  ufw default deny incoming
  ufw default deny outgoing
  pass "UFW defaults: deny incoming, deny outgoing"

  # Allow SSH from specified IP only
  ufw allow from "$SSH_ALLOWLIST_IP" to any port 22 proto tcp
  pass "SSH allowed from: $SSH_ALLOWLIST_IP"

  # Allow essential outbound
  ufw allow out to any port 53          # DNS
  ufw allow out to any port 443 proto tcp  # HTTPS
  ufw allow out to any port 123 proto udp  # NTP
  pass "Outbound allowed: DNS (53), HTTPS (443), NTP (123)"

  # Install Fail2Ban
  info "Installing Fail2Ban..."
  apt install -y -qq fail2ban
  cp "$SCRIPT_DIR/config/fail2ban-jail.local" /etc/fail2ban/jail.local
  systemctl enable --now fail2ban
  pass "Fail2Ban installed and configured"

  # Harden SSH config
  info "Applying hardened SSH configuration..."
  SSHD_BACKUP_DATE=$(date +%Y%m%d)
  cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.${SSHD_BACKUP_DATE}"
  cp "$SCRIPT_DIR/config/sshd_config.hardened" /etc/ssh/sshd_config
  # Populate AllowUsers with the operator username (restricts SSH to this user only)
  echo "" >> /etc/ssh/sshd_config
  echo "AllowUsers $OPERATOR_USER" >> /etc/ssh/sshd_config
  chmod 600 /etc/ssh/sshd_config
  # Detect SSH service name (Pi OS Bookworm uses 'ssh', older uses 'sshd')
  SSH_SVC="ssh"
  if systemctl list-units --type=service --all 2>/dev/null | grep -q "^  sshd.service"; then
    SSH_SVC="sshd"
  fi
  # Validate config before restart
  if sshd -t; then
    systemctl restart "$SSH_SVC"
    pass "Hardened SSH config applied and $SSH_SVC restarted"
  else
    warn "sshd config test failed — restoring backup"
    cp "/etc/ssh/sshd_config.backup.${SSHD_BACKUP_DATE}" /etc/ssh/sshd_config
    fail "SSH hardening failed — check config manually"
  fi

  # Install Tailscale
  info "Installing Tailscale..."
  if ! command -v tailscale &>/dev/null; then
    curl -fsSL https://tailscale.com/install.sh | sh
    pass "Tailscale installed"
  else
    pass "Tailscale already installed"
  fi

  # Allow Tailscale through UFW
  ufw allow in on tailscale0
  ufw allow out on tailscale0
  pass "Tailscale interface allowed in UFW"

  # Start Tailscale auth
  # tailscale up can block for browser auth in a headless environment — always run in background
  if [[ -n "$TAILSCALE_AUTH_KEY" ]]; then
    info "Starting Tailscale with auth key..."
    tailscale up --auth-key="$TAILSCALE_AUTH_KEY" --hostname="$HOSTNAME_VAL" 2>&1 || \
      warn "Tailscale auth failed — run 'sudo tailscale up' manually after setup"
  else
    info "Starting Tailscale — interactive auth required..."
    warn "Tailscale needs browser auth. Running in background."
    warn "After setup completes: run 'sudo tailscale up' and follow the URL."
    tailscale up --hostname="$HOSTNAME_VAL" 2>&1 &
    TAILSCALE_PID=$!
    sleep 3
    # If it printed a URL, capture and show it; then let it run in background
    kill "$TAILSCALE_PID" 2>/dev/null || true
    warn "Complete Tailscale auth manually: sudo tailscale up"
  fi

  # Enable UFW
  info "Enabling UFW..."
  ufw --force enable
  pass "UFW enabled"

  pass "Layer 3 complete"

  echo ""
  info "UFW status:"
  ufw status verbose
}

# =============================================================================
# Layer 4 — Least Privilege & Credentials
# =============================================================================
layer4_least_privilege() {
  header "Layer 4 — Least Privilege & Credentials"
  info "Addresses: ASI02 (Tool Misuse), ASI03 (Privilege Abuse), ASI09 (Trust Exploitation)"

  # Remove any lingering sudo access for openclaw
  deluser openclaw sudo 2>/dev/null || true
  SUDOERS_FILE="/etc/sudoers.d/openclaw"
  if [[ -f "$SUDOERS_FILE" ]]; then
    rm -f "$SUDOERS_FILE"
  fi
  pass "openclaw user has no sudo privileges"

  # Write hardened openclaw.json config from template
  info "Writing hardened OpenClaw configuration..."
  OPENCLAW_CONFIG="/opt/openclaw/config/openclaw.json"
  # Replace token placeholder with generated token
  sed "s/REPLACE_WITH_GENERATED_TOKEN/${GATEWAY_TOKEN}/" \
    "$SCRIPT_DIR/config/openclaw.json.template" > "$OPENCLAW_CONFIG"
  chmod 600 "$OPENCLAW_CONFIG"
  chown openclaw:openclaw "$OPENCLAW_CONFIG"
  pass "Hardened openclaw.json written (token set, chmod 600)"

  # Write .env template
  info "Writing credential .env template..."
  ENV_FILE="/opt/openclaw/config/.env"
  if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" << 'EOF'
# OpenClaw Agent Credentials
# Fill in your actual API keys and credentials
# chmod 600 — never commit this file

# AI Provider (use only one per deployment)
ANTHROPIC_API_KEY=sk-ant-REPLACE_ME
# OPENAI_API_KEY=sk-REPLACE_ME

# Messaging integrations (only add what you actually use)
# TELEGRAM_BOT_TOKEN=REPLACE_ME

# Set spending limits on all API keys before adding them here
EOF
    chmod 600 "$ENV_FILE"
    chown openclaw:openclaw "$ENV_FILE"
    pass ".env template written (chmod 600)"
  else
    pass ".env already exists — not overwriting"
    chmod 600 "$ENV_FILE"
    chown openclaw:openclaw "$ENV_FILE"
  fi

  # Set up weekly credential rotation reminder cron
  CRON_ROTATE="/etc/cron.d/openclaw-credential-rotation"
  if [[ ! -f "$CRON_ROTATE" ]]; then
    cat > "$CRON_ROTATE" << EOF
# Monthly credential rotation reminder for OpenClaw
# See /opt/openclaw/KILL-SWITCH.txt for rotation procedure
0 9 1 * * $OPERATOR_USER echo "[OpenClaw] Monthly credential rotation due. See /opt/openclaw/KILL-SWITCH.txt" | wall
EOF
    pass "Monthly credential rotation reminder cron installed"
  fi

  # Final permissions sweep
  chown -R openclaw:openclaw /opt/openclaw
  chmod 700 /opt/openclaw
  chmod 700 /opt/openclaw/config
  chmod 600 /opt/openclaw/config/openclaw.json
  chmod 600 /opt/openclaw/config/setup.conf
  chmod 600 /opt/openclaw/config/.env
  chmod 750 /opt/openclaw/workspace
  chmod 750 /opt/openclaw/logs
  pass "Permissions hardened on /opt/openclaw/"

  pass "Layer 4 complete"
}

# =============================================================================
# Layer 5 — Monitoring, Alerting & Service
# =============================================================================
layer5_monitoring() {
  header "Layer 5 — Monitoring, Alerting & Service"
  info "Addresses: ASI08 (Cascading Failures), ASI10 (Rogue Agents)"

  # Install systemd service (Docker mode uses compose, not service unit directly,
  # but we still install the service for host-mode start and health watcher)
  if [[ "$DEPLOY_MODE" == "host" ]]; then
    systemctl enable openclaw 2>/dev/null || true
    info "OpenClaw systemd service enabled (will start after you install OpenClaw)"
    pass "Systemd service enabled"
  fi

  # Weekly security audit cron
  CRON_AUDIT="/etc/cron.d/openclaw-security-audit"
  if [[ ! -f "$CRON_AUDIT" ]]; then
    cat > "$CRON_AUDIT" << 'EOF'
# Weekly OpenClaw security audit — every Monday at 6am
0 6 * * 1 openclaw /usr/local/bin/openclaw security audit --deep >> /opt/openclaw/logs/audit.log 2>&1
EOF
    pass "Weekly security audit cron installed"
  fi

  # Resource monitoring cron
  CRON_HEALTH="/etc/cron.d/openclaw-health-monitor"
  if [[ ! -f "$CRON_HEALTH" ]]; then
    cat > "$CRON_HEALTH" << 'HEALTHEOF'
# OpenClaw health monitoring — every 15 minutes
*/15 * * * * root /usr/local/sbin/openclaw-health-check.sh >> /opt/openclaw/logs/health.log 2>&1
HEALTHEOF

    # Write health check script
    cat > /usr/local/sbin/openclaw-health-check.sh << 'SCRIPT'
#!/usr/bin/env bash
# OpenClaw Pi health monitor
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
TEMP=$(vcgencmd measure_temp 2>/dev/null | grep -oP '[0-9.]+' || echo "N/A")
MEM_USED=$(free -m | awk '/^Mem:/{print $3}')
MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
MEM_PCT=$(( MEM_USED * 100 / MEM_TOTAL ))
DISK_PCT=$(df /opt/openclaw 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')

echo "$TIMESTAMP | temp=${TEMP}C | mem=${MEM_PCT}% (${MEM_USED}/${MEM_TOTAL}MB) | disk=${DISK_PCT}%"

# Alert thresholds
if (( $(echo "$TEMP > 80" | bc -l 2>/dev/null || echo 0) )); then
  echo "$TIMESTAMP | ALERT: Temperature > 80C (${TEMP}C) — check cooling!" | wall
fi
if [[ -n "$MEM_PCT" && "$MEM_PCT" -gt 90 ]]; then
  echo "$TIMESTAMP | ALERT: Memory > 90% (${MEM_PCT}%) — possible runaway agent!" | wall
fi
if [[ -n "$DISK_PCT" && "$DISK_PCT" -gt 85 ]]; then
  echo "$TIMESTAMP | ALERT: Disk > 85% (${DISK_PCT}%) — check logs!" | wall
fi
SCRIPT
    chmod 755 /usr/local/sbin/openclaw-health-check.sh
    pass "Health monitoring cron installed (15-minute checks)"
  fi

  # Configure journald retention limits
  info "Configuring journald log retention..."
  mkdir -p /etc/systemd/journald.conf.d/
  cat > /etc/systemd/journald.conf.d/openclaw-retention.conf << 'EOF'
[Journal]
SystemMaxUse=200M
SystemMaxFileSize=50M
MaxRetentionSec=30day
EOF
  systemctl restart systemd-journald 2>/dev/null || true
  pass "journald retention: 200MB max, 30-day retention"

  # Write kill switch documentation
  KILL_SWITCH_FILE="/opt/openclaw/KILL-SWITCH.txt"
  cat > "$KILL_SWITCH_FILE" << KILLEOF
OpenClaw Pi — Emergency Kill Switch Procedures
===============================================
Generated: $(date)
Hostname:  $HOSTNAME_VAL

QUICK STOP
----------
# Stop the service
sudo systemctl stop openclaw

# Kill the Docker container (Docker mode)
docker stop openclaw && docker rm openclaw

# Nuclear — stop everything and block all outbound
sudo systemctl stop openclaw docker 2>/dev/null
sudo ufw deny out to any

# Disconnect from Tailscale
sudo tailscale down


CONTAINMENT PROCEDURE (from OpenClaw docs)
-------------------------------------------
1. Stop gateway:   sudo systemctl stop openclaw
2. Set loopback:   gateway.bind = "loopback" in openclaw.json
3. Freeze access:  Set dmPolicy: "disabled" in openclaw.json


CREDENTIAL ROTATION (monthly or after incident)
-------------------------------------------------
1. Generate new token:  openssl rand -hex 32
2. Update /opt/openclaw/config/openclaw.json  gateway.auth.token
3. Restart gateway:     sudo systemctl restart openclaw
4. Update remote client credentials (Mac, phone, etc.)
5. VERIFY old token no longer works


FORENSIC AUDIT (after incident)
--------------------------------
journalctl -u openclaw --since "24 hours ago"
cat /tmp/openclaw/openclaw-$(date +%Y-%m-%d).log 2>/dev/null
crontab -l -u openclaw 2>/dev/null
ps aux | grep openclaw
ls ~/.openclaw/agents/ 2>/dev/null


CONTACTS & REFERENCES
---------------------
OpenClaw security docs: https://docs.openclaw.ai/gateway/security
OWASP Agentic Top 10:   https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
CVE tracker:            https://nvd.nist.gov
KILLEOF
  chmod 600 "$KILL_SWITCH_FILE"
  chown openclaw:openclaw "$KILL_SWITCH_FILE"
  pass "Kill switch documentation written to /opt/openclaw/KILL-SWITCH.txt"

  pass "Layer 5 complete"
}

# =============================================================================
# Final Summary
# =============================================================================
print_summary() {
  header "Setup Complete"

  echo -e "${BOLD}Configuration Summary${RESET}"
  echo "  Hostname:         $HOSTNAME_VAL"
  echo "  Deployment mode:  $DEPLOY_MODE"
  echo "  SSH allowlist:    $SSH_ALLOWLIST_IP"
  echo "  SSH operator:     $OPERATOR_USER"
  echo "  Gateway token:    [stored in /opt/openclaw/config/setup.conf — chmod 600]"
  echo ""

  echo -e "${BOLD}SSH tunnel command (run from your Mac):${RESET}"
  echo "  ssh -L 3000:localhost:3000 ${OPERATOR_USER}@${HOSTNAME_VAL}.local"
  echo "  Then open: http://localhost:3000"
  echo ""

  echo -e "${BOLD}Kill switch:${RESET}"
  echo "  sudo systemctl stop openclaw"
  echo "  See: /opt/openclaw/KILL-SWITCH.txt"
  echo ""

  echo -e "${BOLD}Next steps:${RESET}"
  echo "  1. Install OpenClaw: npm install -g @openclaw/openclaw (Node.js 22.12.0+ required)"
  echo "  2. Edit credentials: sudo nano /opt/openclaw/config/.env"
  echo "  3. Review tool policy: /opt/openclaw/config/openclaw.json"
  echo "  4. Run security tests: sudo ./security-tests.sh"
  echo ""

  echo -e "${BOLD}Manual checklist items (not automated):${RESET}"
  warn "Define your threat model (what the agent will/won't access)"
  warn "Read OpenClaw security docs: https://docs.openclaw.ai/gateway/security"
  warn "Review OWASP Top 10 for Agentic Applications"
  warn "Test in non-production first before connecting real integrations"
  warn "Verify Node.js version: node --version (must be >= 22.12.0)"
  warn "Inventory all service integrations (each one is an attack surface)"
  warn "Pin and audit all ClawHub skills before installing (36% had flaws)"
  warn "Consider full-disk encryption (LUKS) for physically accessible Pi"
  echo ""

  pass "OpenClaw Pi 5 security setup complete."
  pass "Run sudo ./security-tests.sh to verify all controls."
}

# =============================================================================
# Main
# =============================================================================
main() {
  echo ""
  echo -e "${BOLD}${CYAN}OpenClaw Pi 5 Security Setup${RESET}"
  echo -e "${CYAN}5-layer defense-in-depth for AI agent hosting${RESET}"
  echo ""

  preflight_checks
  gather_config

  # Load config for use across layers
  source /opt/openclaw/config/setup.conf

  layer1_os_hardening
  layer2_isolation
  layer3_network
  layer4_least_privilege
  layer5_monitoring
  print_summary
}

main "$@"
