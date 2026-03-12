# OpenClaw Pi 5 Security Setup

Automated defense-in-depth security setup for running [OpenClaw](https://docs.openclaw.ai) AI agent on a Raspberry Pi 5.

One script. Five layers. Locked down against real attacker scenarios.

---

## What This Does

OpenClaw is an AI agent framework capable of browser control, file access, shell execution, and service integrations. Running it 24/7 on a Pi creates a substantial attack surface — documented CVEs (CVSS 8.8), prompt injection, Docker breakout, gateway exposure, and plaintext credential leaks are all real risks with tens of thousands of misconfigured instances found exposed on the public internet.

This program implements all security layers from the OWASP Top 10 for Agentic Applications (2026) adapted for Pi 5 + ARM64:

- **Layer 1** — OS hardening, kernel parameters, watchdog
- **Layer 2** — Docker isolation or systemd sandboxing (your choice)
- **Layer 3** — UFW egress filtering, hardened SSH, Fail2Ban, Tailscale
- **Layer 4** — Tool deny policy, least-privilege user, credential scoping
- **Layer 5** — Monitoring, automated security audits, kill switch

---

## Security Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Raspberry Pi 5                        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Layer 5: Monitoring + Kill Switch               │   │
│  │  └─ systemd service, health cron, audit cron    │   │
│  │                                                 │   │
│  │  ┌───────────────────────────────────────────┐ │   │
│  │  │  Layer 4: Least Privilege                  │ │   │
│  │  │  └─ tool deny, openclaw user, .env 600    │ │   │
│  │  │                                           │ │   │
│  │  │  ┌─────────────────────────────────────┐ │ │   │
│  │  │  │  Layer 3: Network                    │ │ │   │
│  │  │  │  └─ UFW deny-all, SSH key-only,     │ │ │   │
│  │  │  │     Fail2Ban, Tailscale             │ │ │   │
│  │  │  │                                     │ │ │   │
│  │  │  │  ┌───────────────────────────────┐ │ │ │   │
│  │  │  │  │  Layer 2: Isolation            │ │ │ │   │
│  │  │  │  │  └─ Docker hardened flags     │ │ │ │   │
│  │  │  │  │     OR systemd sandboxing     │ │ │ │   │
│  │  │  │  │                               │ │ │ │   │
│  │  │  │  │  ┌─────────────────────────┐ │ │ │ │   │
│  │  │  │  │  │  Layer 1: OS Hardening   │ │ │ │ │   │
│  │  │  │  │  │  └─ sysctl, watchdog,    │ │ │ │ │   │
│  │  │  │  │  │     unattended upgrades  │ │ │ │ │   │
│  │  │  │  │  └─────────────────────────┘ │ │ │ │   │
│  │  │  │  └───────────────────────────────┘ │ │ │   │
│  │  │  └─────────────────────────────────────┘ │ │   │
│  │  └───────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         ↑ SSH (key only, from allowlisted IP)
         ↑ Tailscale (VPN — keeps gateway on loopback)
```

---

## Prerequisites

- **Raspberry Pi 5** — 8GB model strongly recommended; 4GB is minimum
- **Pi OS Lite 64-bit** — fresh flash via Raspberry Pi Imager (no desktop)
- **SSH key pair** — you need your public key ready before running setup
- **Internet connection** — Pi must be online during setup
- **Node.js 22.12.0+** — required for OpenClaw (CVE-2025-59466 / CVE-2026-21636)
- **A defined threat model** — before you start, document what the agent *will and will not* have access to

---

## Quick Start

```bash
# 1. Copy the project to your Pi
scp -r openclaw-pi-security-setup/ pi@<your-pi-ip>:~/

# 2. Make scripts executable
chmod +x setup.sh security-tests.sh

# 3. Run setup as root
sudo ./setup.sh
```

The script will prompt you for:
- Hostname (default: `openclaw-pi`)
- Your SSH public key
- Deployment mode (Docker or host systemd)
- Your IP/CIDR for SSH access
- Optional Tailscale auth key

No changes are made until you confirm the configuration summary.

---

## Deployment Modes

### Docker (Recommended)

Runs OpenClaw in a hardened container with:
- `--read-only` filesystem
- `--cap-drop ALL`
- `--security-opt=no-new-privileges`
- `--user 1000:1000` (non-root)
- Resource limits: 2 CPUs, 4GB RAM, 100 PIDs
- `DOCKER-USER` iptables chain to prevent UFW bypass (critical — Docker published ports bypass host firewall rules by default)
- No Docker socket mount

**Best for:** Maximum isolation, production use.

### Host Systemd

Runs OpenClaw directly on the host under the `openclaw` system user with systemd security directives:
- `ProtectSystem=strict`
- `NoNewPrivileges=true`
- `ProtectHome=true`
- `PrivateTmp=true`
- `MemoryDenyWriteExecute=true`

**Best for:** Lower overhead, simpler debugging.

---

## Running Security Tests

After `setup.sh` completes and after you've installed OpenClaw:

```bash
sudo ./security-tests.sh
```

Tests cover 4 attacker simulation categories:

| Category | What Gets Tested |
|----------|-----------------|
| 1. SSH Brute-Force | PasswordAuth disabled, MaxAuthTries, Fail2Ban jail, ban effectiveness |
| 2. Firewall Egress | Default deny, port 80 blocked, DNS/HTTPS/NTP whitelisted, Docker UFW bypass fix |
| 3. Docker Breakout | Socket mount, cap-drop, read-only FS, no-new-privileges, PIDs/memory limits |
| 4. Gateway & Injection | Loopback binding, auth token, tool deny list, SSRF, adversarial egress, kill switch |

Each test prints `PASS`, `FAIL` (with remediation hint), or `SKIP` (not applicable to your mode). Final score shown at the end.

---

## After Setup

1. **Install OpenClaw** (Node.js 22.12.0+ required):
   ```bash
   npm install -g @openclaw/openclaw
   # Verify: openclaw --version
   ```

2. **Configure credentials**:
   ```bash
   sudo nano /opt/openclaw/config/.env
   # Fill in API keys — use keys with minimal scopes and spending limits
   ```

3. **Review and customize tool policy**:
   ```bash
   sudo nano /opt/openclaw/config/openclaw.json
   # Enable only the tools your agent actually needs
   ```

4. **Start the service**:
   ```bash
   # Host mode:
   sudo systemctl start openclaw

   # Docker mode:
   cd /opt/openclaw && sudo docker compose up -d
   ```

5. **Access via SSH tunnel from your Mac**:
   ```bash
   ssh -L 3000:localhost:3000 pi-admin@openclaw-pi.local
   # Then open: http://localhost:3000
   ```

6. **Run security tests**:
   ```bash
   sudo ./security-tests.sh
   ```

---

## Ongoing Operations

| Task | Frequency | How |
|------|-----------|-----|
| Security audit | Weekly (automated) | Cron runs `openclaw security audit --deep` every Monday 6am |
| OS updates | Promptly | Unattended upgrades enabled; emergency fixes within 24-48h |
| Credential rotation | Monthly | See `/opt/openclaw/KILL-SWITCH.txt` for procedure |
| Skill re-audit | After every update | Manual — 36% of ClawHub skills have security flaws |
| Breakout testing | After major updates | Re-run `security-tests.sh` |
| Backup | Weekly | `rsync -av /opt/openclaw/ /mnt/backup/openclaw/ --exclude='*.log'` |
| Hardware health | Continuous (automated) | `vcgencmd measure_temp` — alerts if > 80°C |

Log locations:
- OpenClaw: `journalctl -u openclaw -f`
- Security audit: `/opt/openclaw/logs/audit.log`
- Health monitor: `/opt/openclaw/logs/health.log`
- Fail2Ban: `sudo fail2ban-client status sshd`

---

## Kill Switch

Emergency stop procedures are documented in `/opt/openclaw/KILL-SWITCH.txt` after setup. Quick reference:

```bash
# Stop service
sudo systemctl stop openclaw

# Kill Docker container
docker stop openclaw && docker rm openclaw

# Nuclear — block all outbound and stop everything
sudo systemctl stop openclaw docker
sudo ufw deny out to any

# Disconnect Tailscale
sudo tailscale down
```

**Test this before going live.**

---

## Known CVEs (as of March 2026)

| CVE | Severity | Description | Mitigation |
|-----|----------|-------------|------------|
| CVE-2026-25253 | CVSS 8.8 | RCE via browser — malicious JS leaks gateway auth token | Bind gateway to loopback, rotate token, disable browser tool if not needed |
| CVE-2025-59466 | High | Node.js vulnerability | Requires **Node.js 22.12.0+** |
| CVE-2026-21636 | High | Node.js vulnerability | Requires **Node.js 22.12.0+** |

Also: 36% of ClawHub skills had security flaws (Cisco, Feb 2026). Audit every skill before installation.

---

## File Reference

```
openclaw-pi-security-setup/
├── setup.sh                    # Main security setup (Layers 1-5)
├── security-tests.sh           # Attacker simulation tests
├── config/
│   ├── openclaw.json.template  # Hardened OpenClaw baseline (Appendix B)
│   ├── sysctl-hardening.conf   # Kernel hardening parameters
│   ├── sshd_config.hardened    # Hardened SSH configuration
│   ├── fail2ban-jail.local     # Fail2Ban SSH jail
│   ├── openclaw.service        # Systemd unit (host mode)
│   └── docker-compose.yml      # Docker deployment (hardened)
└── .gitignore                  # Excludes all secrets
```

At runtime, setup creates `/opt/openclaw/`:
```
/opt/openclaw/
├── workspace/        # Agent working directory (chmod 750)
├── config/
│   ├── openclaw.json # Hardened config with generated token (chmod 600)
│   ├── .env          # Credentials template (chmod 600)
│   └── setup.conf    # Setup answers (chmod 600)
├── logs/             # Audit and health logs
├── docker-compose.yml # (Docker mode)
└── KILL-SWITCH.txt   # Emergency procedures
```

---

## Sources

This setup implements guidance from:

- [OpenClaw Security Docs](https://docs.openclaw.ai/gateway/security) — gateway config, tool policy, credential management, incident response
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — ASI01-ASI10 risk framework
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) — alert thresholds, memory security, output validation
- [CrowdStrike — What Security Teams Need to Know About OpenClaw](https://www.crowdstrike.com/en-us/blog/what-security-teams-need-to-know-about-openclaw-ai-super-agent/) — CVE-2026-25253, attack vectors
- [Cisco — Personal AI Agents Are a Security Nightmare](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare) — 36% skill flaw rate, supply chain risks
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) — container hardening
- [Contabo — OpenClaw Security Guide 2026](https://contabo.com/blog/openclaw-security-guide-2026/) — Node.js version requirement
