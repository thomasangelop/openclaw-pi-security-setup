#!/usr/bin/env bash
# =============================================================================
# OpenClaw Pi 5 Security Tests — Attacker Simulation
# =============================================================================
# Runs 4 categories of attacker simulation tests to verify the setup.sh
# security lockdown holds.
#
# Usage:
#   sudo ./security-tests.sh
#
# Run AFTER setup.sh AND after installing OpenClaw.
# Some tests are marked SKIP if not applicable to your deployment mode.
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# Colors & Counters
# =============================================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_COUNT=0

# =============================================================================
# Test Helpers
# =============================================================================
header() {
  echo ""
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo -e "${BOLD}${CYAN}  $*${RESET}"
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo ""
}

test_pass() {
  local name="$1"
  local detail="${2:-}"
  echo -e "${GREEN}[PASS]${RESET} $name${detail:+ — $detail}"
  (( PASS_COUNT++ )) || true
  (( TOTAL_COUNT++ )) || true
}

test_fail() {
  local name="$1"
  local detail="${2:-}"
  local remediation="${3:-}"
  echo -e "${RED}[FAIL]${RESET} $name${detail:+ — $detail}"
  if [[ -n "$remediation" ]]; then
    echo -e "       ${YELLOW}→ Remediation: $remediation${RESET}"
  fi
  (( FAIL_COUNT++ )) || true
  (( TOTAL_COUNT++ )) || true
}

test_skip() {
  local name="$1"
  local reason="${2:-not applicable}"
  echo -e "${YELLOW}[SKIP]${RESET} $name — $reason"
  (( SKIP_COUNT++ )) || true
  (( TOTAL_COUNT++ )) || true
}

# =============================================================================
# Pre-flight
# =============================================================================
preflight() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[✗]${RESET} Must run as root: sudo ./security-tests.sh"
    exit 1
  fi

  # Load deploy mode from setup config
  DEPLOY_MODE="unknown"
  if [[ -f /opt/openclaw/config/setup.conf ]]; then
    source /opt/openclaw/config/setup.conf
  else
    echo -e "${YELLOW}[!]${RESET} /opt/openclaw/config/setup.conf not found — run setup.sh first"
    echo -e "${YELLOW}[!]${RESET} Continuing with best-effort detection..."
    if command -v docker &>/dev/null && docker ps -q 2>/dev/null | grep -q .; then
      DEPLOY_MODE="docker"
    else
      DEPLOY_MODE="host"
    fi
  fi

  echo -e "${BOLD}Deployment mode detected: $DEPLOY_MODE${RESET}"
  echo ""
}

# =============================================================================
# Test Category 1 — SSH Brute-Force Defense
# =============================================================================
test_ssh_bruteforce() {
  header "Test 1 — SSH Brute-Force Defense"

  # 1.1 Verify PasswordAuthentication is disabled
  SSHD_CFG="/etc/ssh/sshd_config"
  if grep -qiE "^PasswordAuthentication\s+no" "$SSHD_CFG" 2>/dev/null; then
    test_pass "1.1 PasswordAuthentication disabled in sshd_config"
  else
    test_fail "1.1 PasswordAuthentication disabled" \
      "Not found or not set to 'no' in $SSHD_CFG" \
      "Add 'PasswordAuthentication no' to $SSHD_CFG and restart sshd"
  fi

  # 1.2 Verify PermitRootLogin is disabled
  if grep -qiE "^PermitRootLogin\s+no" "$SSHD_CFG" 2>/dev/null; then
    test_pass "1.2 PermitRootLogin disabled"
  else
    test_fail "1.2 PermitRootLogin disabled" \
      "Not found or not set to 'no'" \
      "Add 'PermitRootLogin no' to $SSHD_CFG and restart sshd"
  fi

  # 1.3 Verify MaxAuthTries is set
  MAX_AUTH=$(grep -iE "^MaxAuthTries" "$SSHD_CFG" 2>/dev/null | awk '{print $2}')
  if [[ -n "$MAX_AUTH" && "$MAX_AUTH" -le 3 ]]; then
    test_pass "1.3 MaxAuthTries set to $MAX_AUTH (≤ 3)"
  else
    test_fail "1.3 MaxAuthTries set" \
      "Current value: ${MAX_AUTH:-not set} (should be ≤ 3)" \
      "Add 'MaxAuthTries 3' to $SSHD_CFG"
  fi

  # 1.4 Verify PubkeyAuthentication is enabled
  if grep -qiE "^PubkeyAuthentication\s+yes" "$SSHD_CFG" 2>/dev/null; then
    test_pass "1.4 PubkeyAuthentication enabled"
  else
    test_fail "1.4 PubkeyAuthentication enabled" \
      "Not found or disabled in $SSHD_CFG" \
      "Add 'PubkeyAuthentication yes' to $SSHD_CFG"
  fi

  # 1.5 Verify Fail2Ban is running
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    test_pass "1.5 Fail2Ban service running"
  else
    test_fail "1.5 Fail2Ban service running" \
      "fail2ban is not active" \
      "Run: sudo apt install fail2ban && sudo systemctl enable --now fail2ban"
  fi

  # 1.6 Verify Fail2Ban SSH jail is enabled
  if fail2ban-client status sshd 2>/dev/null | grep -q "Status for the jail"; then
    test_pass "1.6 Fail2Ban sshd jail active"
    # Show current ban stats
    BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk -F: '{print $2}' | xargs)
    TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk -F: '{print $2}' | xargs)
    echo "       Currently banned: $BANNED | Total banned: $TOTAL_BANNED"
  else
    test_fail "1.6 Fail2Ban sshd jail active" \
      "sshd jail not found or inactive" \
      "Check /etc/fail2ban/jail.local has [sshd] enabled = true"
  fi

  # 1.7 Verify jail config maxretry
  if [[ -f /etc/fail2ban/jail.local ]]; then
    MAX_RETRY=$(grep -A10 "^\[sshd\]" /etc/fail2ban/jail.local 2>/dev/null | grep "maxretry" | head -1 | awk -F= '{print $2}' | xargs)
    if [[ -n "$MAX_RETRY" && "$MAX_RETRY" -le 3 ]]; then
      test_pass "1.7 Fail2Ban maxretry = $MAX_RETRY (≤ 3)"
    else
      test_fail "1.7 Fail2Ban maxretry" \
        "Current: ${MAX_RETRY:-not set} (should be ≤ 3)" \
        "Set maxretry = 3 in [sshd] section of /etc/fail2ban/jail.local"
    fi
  else
    test_fail "1.7 Fail2Ban maxretry configured" \
      "/etc/fail2ban/jail.local not found" \
      "Run setup.sh to install jail configuration"
  fi

  # 1.8 Simulate ban: attempt multiple failed logins via ssh-keyscan to trigger
  # Note: We test that iptables/nftables has a fail2ban chain, not actual login
  echo "       [→] Checking Fail2Ban iptables chain exists..."
  if iptables -L f2b-sshd 2>/dev/null | grep -q "Chain f2b-sshd\|DROP\|REJECT" || \
     iptables -L -n 2>/dev/null | grep -q "f2b-sshd\|fail2ban"; then
    test_pass "1.8 Fail2Ban iptables chain present"
  else
    test_skip "1.8 Fail2Ban iptables chain" \
      "chain not yet created (no bans have occurred — normal on fresh setup)"
  fi
}

# =============================================================================
# Test Category 2 — Firewall Egress Controls
# =============================================================================
test_firewall_egress() {
  header "Test 2 — Firewall Egress Controls"

  # 2.1 Verify UFW is active
  if ufw status 2>/dev/null | grep -q "Status: active"; then
    test_pass "2.1 UFW is active"
  else
    test_fail "2.1 UFW is active" \
      "UFW is not running" \
      "Run: sudo ufw enable"
  fi

  # 2.2 Verify default deny incoming
  UFW_STATUS=$(ufw status verbose 2>/dev/null)
  if echo "$UFW_STATUS" | grep -q "Default: deny (incoming)"; then
    test_pass "2.2 Default deny incoming"
  else
    test_fail "2.2 Default deny incoming" \
      "UFW default incoming is not deny" \
      "Run: sudo ufw default deny incoming"
  fi

  # 2.3 Verify default deny outgoing
  if echo "$UFW_STATUS" | grep -q "Default: deny (outgoing)"; then
    test_pass "2.3 Default deny outgoing"
  else
    test_fail "2.3 Default deny outgoing" \
      "UFW default outgoing is not deny" \
      "Run: sudo ufw default deny outgoing"
  fi

  # 2.4 Test non-whitelisted egress port 80 is blocked
  echo "       [→] Testing egress on port 80 (should be blocked)..."
  if timeout 5 curl -s --max-time 4 http://example.com &>/dev/null; then
    test_fail "2.4 Port 80 egress blocked" \
      "Connection to port 80 succeeded — should be blocked" \
      "Verify UFW outgoing deny default. Port 80 (HTTP) should not be whitelisted."
  else
    test_pass "2.4 Port 80 egress blocked (curl to port 80 rejected)"
  fi

  # 2.5 Test whitelisted DNS works
  echo "       [→] Testing DNS resolution (should succeed)..."
  if nslookup google.com 8.8.8.8 &>/dev/null || host google.com &>/dev/null; then
    test_pass "2.5 DNS resolution works (port 53 whitelisted)"
  else
    test_fail "2.5 DNS resolution" \
      "DNS lookup failed — port 53 may not be whitelisted" \
      "Run: sudo ufw allow out to any port 53"
  fi

  # 2.6 Test whitelisted HTTPS works
  echo "       [→] Testing HTTPS egress (should succeed)..."
  if timeout 10 curl -s --max-time 8 https://example.com &>/dev/null; then
    test_pass "2.6 HTTPS egress works (port 443 whitelisted)"
  else
    test_fail "2.6 HTTPS egress" \
      "HTTPS connection failed — port 443 may not be whitelisted" \
      "Run: sudo ufw allow out to any port 443 proto tcp"
  fi

  # 2.7 Test NTP is accessible
  echo "       [→] Testing NTP sync (port 123)..."
  if timedatectl status 2>/dev/null | grep -q "synchronized: yes\|NTP synchronized: yes"; then
    test_pass "2.7 NTP synchronized (port 123 whitelisted)"
  else
    # NTP not yet synced might just mean it's too early
    test_skip "2.7 NTP synchronized" \
      "timedatectl shows not synced — may still be initializing; check: timedatectl status"
  fi

  # 2.8 Docker mode: verify DOCKER-USER chain exists
  if [[ "$DEPLOY_MODE" == "docker" ]]; then
    if iptables -L DOCKER-USER 2>/dev/null | grep -q "Chain DOCKER-USER"; then
      test_pass "2.8 DOCKER-USER iptables chain present (Docker UFW bypass fix)"
    else
      test_fail "2.8 DOCKER-USER iptables chain" \
        "DOCKER-USER chain not found — published Docker ports may bypass UFW" \
        "Check /etc/ufw/after.rules for DOCKER-USER rules and reload UFW"
    fi
  else
    test_skip "2.8 DOCKER-USER iptables chain" "host mode deployment"
  fi
}

# =============================================================================
# Test Category 3 — Docker Breakout Prevention
# =============================================================================
test_docker_breakout() {
  header "Test 3 — Docker Breakout Prevention"

  if [[ "$DEPLOY_MODE" != "docker" ]]; then
    test_skip "3.1 Docker socket not mounted" "host mode deployment"
    test_skip "3.2 cap-drop ALL (no NET_RAW ping)" "host mode deployment"
    test_skip "3.3 Read-only filesystem" "host mode deployment"
    test_skip "3.4 No new privileges" "host mode deployment"
    test_skip "3.5 /proc restricted" "host mode deployment"
    test_skip "3.6 Memory limit enforced" "host mode deployment"
    return
  fi

  # Check if container is running
  if ! docker ps 2>/dev/null | grep -q "openclaw"; then
    echo -e "${YELLOW}[!]${RESET} openclaw container is not running — tests 3.x will be limited"
    CONTAINER_RUNNING=false
  else
    CONTAINER_RUNNING=true
  fi

  # 3.1 Docker socket NOT mounted in container
  if [[ "$CONTAINER_RUNNING" == "true" ]]; then
    if docker exec openclaw ls /var/run/docker.sock &>/dev/null; then
      test_fail "3.1 Docker socket not mounted in container" \
        "/var/run/docker.sock is accessible inside the container" \
        "Remove docker.sock volume mount from docker-compose.yml — this allows container escape"
    else
      test_pass "3.1 Docker socket not mounted in container"
    fi
  else
    # Check docker-compose config instead
    COMPOSE_FILE="/opt/openclaw/docker-compose.yml"
    if [[ -f "$COMPOSE_FILE" ]] && grep -q "docker.sock" "$COMPOSE_FILE"; then
      test_fail "3.1 Docker socket not mounted" \
        "docker.sock found in docker-compose.yml volumes" \
        "Remove the /var/run/docker.sock mount from docker-compose.yml"
    else
      test_pass "3.1 Docker socket not in docker-compose.yml"
    fi
  fi

  # 3.2 cap-drop ALL (no NET_RAW — ping should fail)
  if [[ "$CONTAINER_RUNNING" == "true" ]]; then
    if docker exec openclaw ping -c 1 8.8.8.8 &>/dev/null 2>&1; then
      test_fail "3.2 cap-drop ALL (NET_RAW blocked)" \
        "ping succeeded inside container — NET_RAW capability is available" \
        "Ensure cap_drop: [ALL] is set in docker-compose.yml"
    else
      test_pass "3.2 cap-drop ALL effective (ping fails inside container — NET_RAW dropped)"
    fi
  else
    COMPOSE_FILE="/opt/openclaw/docker-compose.yml"
    if [[ -f "$COMPOSE_FILE" ]] && grep -q "cap_drop" "$COMPOSE_FILE" && grep -q "ALL" "$COMPOSE_FILE"; then
      test_pass "3.2 cap_drop ALL in docker-compose.yml"
    else
      test_fail "3.2 cap_drop ALL configured" \
        "cap_drop: [ALL] not found in docker-compose.yml" \
        "Add 'cap_drop: [ALL]' under the openclaw service in docker-compose.yml"
    fi
  fi

  # 3.3 Read-only filesystem
  if [[ "$CONTAINER_RUNNING" == "true" ]]; then
    if docker exec openclaw touch /test-rw-check 2>/dev/null; then
      docker exec openclaw rm -f /test-rw-check 2>/dev/null || true
      test_fail "3.3 Read-only filesystem" \
        "Was able to write to / inside the container" \
        "Add 'read_only: true' to docker-compose.yml. Ensure /tmp is tmpfs."
    else
      test_pass "3.3 Read-only filesystem (write to / fails inside container)"
    fi
  else
    COMPOSE_FILE="/opt/openclaw/docker-compose.yml"
    if [[ -f "$COMPOSE_FILE" ]] && grep -q "read_only: true" "$COMPOSE_FILE"; then
      test_pass "3.3 read_only: true in docker-compose.yml"
    else
      test_fail "3.3 Read-only filesystem configured" \
        "read_only: true not found in docker-compose.yml" \
        "Add 'read_only: true' under the openclaw service"
    fi
  fi

  # 3.4 no-new-privileges
  if [[ "$CONTAINER_RUNNING" == "true" ]]; then
    # Attempt su inside container — should fail with no-new-privileges
    if docker exec openclaw su -c "id" root &>/dev/null 2>&1; then
      test_fail "3.4 No new privileges (su blocked)" \
        "su succeeded inside container — privilege escalation possible" \
        "Add security_opt: [no-new-privileges:true] to docker-compose.yml"
    else
      test_pass "3.4 No new privileges (su fails inside container)"
    fi
  else
    COMPOSE_FILE="/opt/openclaw/docker-compose.yml"
    if [[ -f "$COMPOSE_FILE" ]] && grep -q "no-new-privileges:true" "$COMPOSE_FILE"; then
      test_pass "3.4 no-new-privileges in docker-compose.yml"
    else
      test_fail "3.4 no-new-privileges configured" \
        "security_opt: no-new-privileges not found in docker-compose.yml" \
        "Add \"no-new-privileges:true\" to security_opt in docker-compose.yml"
    fi
  fi

  # 3.5 PIDs limit
  COMPOSE_FILE="/opt/openclaw/docker-compose.yml"
  if [[ -f "$COMPOSE_FILE" ]] && grep -q "pids_limit" "$COMPOSE_FILE"; then
    PIDS_LIMIT=$(grep "pids_limit" "$COMPOSE_FILE" | awk -F: '{print $2}' | xargs)
    test_pass "3.5 PIDs limit set to $PIDS_LIMIT in docker-compose.yml"
  else
    test_fail "3.5 PIDs limit configured" \
      "pids_limit not found in docker-compose.yml" \
      "Add 'pids_limit: 100' under the openclaw service"
  fi

  # 3.6 Memory limit
  if [[ -f "$COMPOSE_FILE" ]] && grep -q "memory:" "$COMPOSE_FILE"; then
    MEM_LIMIT=$(grep "memory:" "$COMPOSE_FILE" | head -1 | awk '{print $2}' | xargs)
    test_pass "3.6 Memory limit set: $MEM_LIMIT"
  else
    test_fail "3.6 Memory limit configured" \
      "memory limit not found in docker-compose.yml" \
      "Add 'memory: 4g' under deploy.resources.limits"
  fi

  # 3.7 Port binding — must be localhost only
  if docker ps 2>/dev/null | grep -q "openclaw"; then
    PORT_BINDING=$(docker port openclaw 3000 2>/dev/null || echo "")
    if echo "$PORT_BINDING" | grep -q "127.0.0.1"; then
      test_pass "3.7 Container port bound to 127.0.0.1 only"
    elif [[ -z "$PORT_BINDING" ]]; then
      test_skip "3.7 Container port binding" "port 3000 not exposed or container not running"
    else
      test_fail "3.7 Container port bound to localhost only" \
        "Port binding: $PORT_BINDING (should be 127.0.0.1:3000)" \
        "Change ports in docker-compose.yml to '127.0.0.1:3000:3000'"
    fi
  else
    if [[ -f "$COMPOSE_FILE" ]] && grep -q "127.0.0.1:3000" "$COMPOSE_FILE"; then
      test_pass "3.7 Port bound to 127.0.0.1 in docker-compose.yml"
    else
      test_fail "3.7 Port bound to localhost" \
        "docker-compose.yml ports section not restricted to 127.0.0.1" \
        "Change ports to '127.0.0.1:3000:3000' in docker-compose.yml"
    fi
  fi
}

# =============================================================================
# Test Category 4 — OpenClaw Gateway & Injection
# =============================================================================
test_gateway_injection() {
  header "Test 4 — OpenClaw Gateway & Injection"

  # 4.1 Verify gateway config binds to loopback
  OPENCLAW_JSON="/opt/openclaw/config/openclaw.json"
  if [[ -f "$OPENCLAW_JSON" ]]; then
    if grep -q '"loopback"' "$OPENCLAW_JSON" || grep -q 'loopback' "$OPENCLAW_JSON"; then
      test_pass "4.1 Gateway bound to loopback in openclaw.json"
    else
      test_fail "4.1 Gateway loopback binding" \
        "gateway.bind not set to loopback in $OPENCLAW_JSON" \
        "Set gateway.bind = \"loopback\" in openclaw.json"
    fi
  else
    test_fail "4.1 openclaw.json exists" \
      "$OPENCLAW_JSON not found" \
      "Run setup.sh or manually create openclaw.json from template"
  fi

  # 4.2 Gateway only listening on localhost (if service running)
  if command -v openclaw &>/dev/null && systemctl is-active --quiet openclaw 2>/dev/null; then
    LISTEN_ADDRS=$(ss -tlnp 2>/dev/null | grep openclaw || true)
    if echo "$LISTEN_ADDRS" | grep -qvE "127\.0\.0\.1|::1"; then
      EXTERNAL=$(echo "$LISTEN_ADDRS" | grep -vE "127\.0\.0\.1|::1")
      test_fail "4.2 Gateway listening on localhost only" \
        "Gateway found listening on non-localhost address: $EXTERNAL" \
        "Set gateway.bind = \"loopback\" in openclaw.json and restart"
    elif echo "$LISTEN_ADDRS" | grep -qE "127\.0\.0\.1"; then
      test_pass "4.2 Gateway listening on 127.0.0.1 only"
    else
      test_skip "4.2 Gateway listening address" "OpenClaw service not running — install and start first"
    fi
  else
    test_skip "4.2 Gateway listening address" "OpenClaw not installed or not running"
  fi

  # 4.3 Gateway auth token configured
  if [[ -f "$OPENCLAW_JSON" ]]; then
    if grep -q '"token"' "$OPENCLAW_JSON" && ! grep -q "REPLACE_WITH_GENERATED_TOKEN" "$OPENCLAW_JSON"; then
      test_pass "4.3 Gateway auth token configured (placeholder replaced)"
    elif grep -q "REPLACE_WITH_GENERATED_TOKEN" "$OPENCLAW_JSON"; then
      test_fail "4.3 Gateway auth token configured" \
        "Token is still the placeholder value" \
        "Run setup.sh to generate and set the token, or set it manually"
    else
      test_fail "4.3 Gateway auth token configured" \
        "No token found in gateway.auth.token" \
        "Add gateway.auth.token to openclaw.json"
    fi
  else
    test_skip "4.3 Gateway auth token" "openclaw.json not found"
  fi

  # 4.4 Tool deny list configured
  if [[ -f "$OPENCLAW_JSON" ]]; then
    DENIED_TOOLS=$(grep -o '"group:automation"\|"group:runtime"\|"group:fs"\|"sessions_spawn"\|"sessions_send"' "$OPENCLAW_JSON" 2>/dev/null | wc -l)
    if [[ "$DENIED_TOOLS" -ge 4 ]]; then
      test_pass "4.4 Tool deny list configured ($DENIED_TOOLS high-risk entries denied)"
    else
      test_fail "4.4 Tool deny list configured" \
        "Only $DENIED_TOOLS/5 expected tool denies found in openclaw.json" \
        "Add all of: group:automation, group:runtime, group:fs, sessions_spawn, sessions_send to tools.deny"
    fi
  else
    test_skip "4.4 Tool deny list" "openclaw.json not found"
  fi

  # 4.5 SSRF protection configured
  if [[ -f "$OPENCLAW_JSON" ]]; then
    if grep -q "dangerouslyAllowPrivateNetwork.*false" "$OPENCLAW_JSON"; then
      test_pass "4.5 SSRF protection: dangerouslyAllowPrivateNetwork = false"
    else
      test_fail "4.5 SSRF protection configured" \
        "dangerouslyAllowPrivateNetwork not set to false" \
        "Add browser.ssrfPolicy.dangerouslyAllowPrivateNetwork = false to openclaw.json"
    fi
  else
    test_skip "4.5 SSRF protection" "openclaw.json not found"
  fi

  # 4.6 Log redaction configured
  if [[ -f "$OPENCLAW_JSON" ]]; then
    if grep -q "redactSensitive.*tools" "$OPENCLAW_JSON"; then
      test_pass "4.6 Log redaction enabled (redactSensitive: tools)"
    else
      test_fail "4.6 Log redaction configured" \
        "logging.redactSensitive not set to 'tools'" \
        "Add logging.redactSensitive = \"tools\" to openclaw.json"
    fi
  else
    test_skip "4.6 Log redaction" "openclaw.json not found"
  fi

  # 4.7 Test kill switch
  echo "       [→] Testing kill switch (stop/start openclaw service)..."
  if systemctl is-active --quiet openclaw 2>/dev/null; then
    systemctl stop openclaw
    sleep 2
    if systemctl is-active --quiet openclaw 2>/dev/null; then
      test_fail "4.7 Kill switch (systemctl stop openclaw)" \
        "Service is still running after systemctl stop" \
        "Investigate service restart policy; check ExecStop and KillMode in unit file"
    else
      test_pass "4.7 Kill switch: systemctl stop openclaw works"
      # Restart for user
      systemctl start openclaw 2>/dev/null || true
    fi
  else
    test_skip "4.7 Kill switch" "OpenClaw service not running"
  fi

  # 4.8 .env file permissions
  ENV_FILE="/opt/openclaw/config/.env"
  if [[ -f "$ENV_FILE" ]]; then
    PERMS=$(stat -c "%a" "$ENV_FILE")
    if [[ "$PERMS" == "600" ]]; then
      test_pass "4.8 .env file permissions: 600 (owner-only read/write)"
    else
      test_fail "4.8 .env file permissions" \
        "Expected 600, got $PERMS" \
        "Run: chmod 600 $ENV_FILE"
    fi
    # Check for placeholder values
    if grep -q "REPLACE_ME" "$ENV_FILE"; then
      echo -e "       ${YELLOW}[!]${RESET} .env contains placeholder values — fill in real credentials before use"
    fi
  else
    test_fail "4.8 .env file exists" \
      "$ENV_FILE not found" \
      "Run setup.sh to create the .env template"
  fi

  # 4.9 openclaw.json permissions
  if [[ -f "$OPENCLAW_JSON" ]]; then
    CONFIG_PERMS=$(stat -c "%a" "$OPENCLAW_JSON")
    if [[ "$CONFIG_PERMS" == "600" ]]; then
      test_pass "4.9 openclaw.json permissions: 600"
    else
      test_fail "4.9 openclaw.json permissions" \
        "Expected 600, got $CONFIG_PERMS" \
        "Run: chmod 600 $OPENCLAW_JSON"
    fi
  else
    test_skip "4.9 openclaw.json permissions" "file not found"
  fi

  # 4.10 Adversarial prompt / outbound connection test
  # Verify that a curl to an external host on a non-whitelisted port fails
  echo "       [→] Testing adversarial egress block (curl on non-whitelisted port 8080)..."
  if timeout 5 curl -s --max-time 4 http://example.com:8080 &>/dev/null; then
    test_fail "4.10 Adversarial egress blocked" \
      "Connection on port 8080 succeeded — outbound filtering is incomplete" \
      "Ensure UFW denies outgoing by default and only port 443/53/123 are allowed"
  else
    test_pass "4.10 Adversarial egress blocked (non-whitelisted port 8080 rejected)"
  fi
}

# =============================================================================
# Final Score
# =============================================================================
print_score() {
  echo ""
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo -e "${BOLD}${CYAN}  Security Test Results${RESET}"
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo ""

  echo -e "  ${GREEN}PASS:${RESET} $PASS_COUNT"
  echo -e "  ${RED}FAIL:${RESET} $FAIL_COUNT"
  echo -e "  ${YELLOW}SKIP:${RESET} $SKIP_COUNT"
  echo -e "  Total: $TOTAL_COUNT"
  echo ""

  SCORED=$((TOTAL_COUNT - SKIP_COUNT))
  if [[ $SCORED -gt 0 ]]; then
    echo -e "  Score: ${BOLD}$PASS_COUNT / $SCORED${RESET} tests passed (excluding skips)"
  fi

  echo ""
  if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All tests passed. Security controls verified.${RESET}"
  else
    echo -e "${RED}${BOLD}$FAIL_COUNT test(s) failed. Review remediation hints above.${RESET}"
    echo -e "${YELLOW}Re-run after fixes: sudo ./security-tests.sh${RESET}"
  fi
  echo ""
}

# =============================================================================
# Main
# =============================================================================
main() {
  echo ""
  echo -e "${BOLD}${CYAN}OpenClaw Pi 5 — Security Verification Tests${RESET}"
  echo -e "${CYAN}Attacker simulation across 4 categories${RESET}"
  echo ""

  preflight

  test_ssh_bruteforce
  test_firewall_egress
  test_docker_breakout
  test_gateway_injection
  print_score
}

main "$@"
