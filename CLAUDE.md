# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ORDR Integration Status Tool — a read-only CLI diagnostic suite for checking customer integration status by SSHing through a jump server (`remotesupport.ordr.net`) to ORDR SCE (Security Control Engine) appliances.

**Critical constraint: This tool must never modify anything on the SCE, containers, or jump server.** All operations are read-only (no service restarts, no config changes, no write commands).

## Running the Tools

### `check` — quick single-command status+errors+connectivity (new)

```bash
./check <customer> <integration>                    # Status + errors + auto-detect connectivity target
./check <customer> <integration> --host HOST        # Provide connectivity target explicitly
./check <customer> <integration> --host HOST --port PORT
./check <customer> <integration> --hours 48         # Look back further for errors
```

Runs all three phases in sequence: service status on SCE → recent error logs → TCP connectivity test from inside the POC container. Auto-detects the integration's target host from the service's ExecStart config flag, common config file paths, or recent journald URLs. Exit code 2 if service is failed or connectivity unreachable.

### `ordr-status` — detailed SCE inspection

```bash
# Bootstrap venv and run (first run creates .venv and installs deps automatically)
./ordr-status --init           # Initialize ~/.ordr/config.yaml
./ordr-status --list           # List customer aliases from jump server
./ordr-status <customer>       # Quick health check
./ordr-status <customer> --integration <name>  # Check specific integration
./ordr-status <customer> --errors              # Show recent log errors
./ordr-status <customer> --full                # Full diagnostic
./ordr-status <customer> --shell               # Interactive shell

# Integration tester (API-level diagnostics, runs locally)
python3 integration_tester.py --customer <name> --env <dc-cloud|on-premise> \
  --integration <ad|crowdstrike|intune|vmware> --host <ip> --port <port> \
  --username <user> --password <pass> --domain <domain> --output <file.json>

# Web UI (port 5001)
python3 integrations_diagnostics_web.py
```

## Installing Dependencies

```bash
pip install -r requirements.txt
# or
pip install .
```

The `ordr-status` shell wrapper auto-creates `.venv/` and installs deps on first run.

## Architecture

Three separate tools with distinct roles:

### `ordr_status.py` — SSH-Based SCE Diagnostics
SSHes through the jump server to run read-only commands on customer SCE appliances.

Key classes:
- **`ConfigManager`** — Loads/creates `~/.ordr/config.yaml` (SSH user, key path, jump host, customer aliases)
- **`JumpSSH`** — Manages paramiko SSH connections: jump server → customer alias → SCE cpnadmin shell. Supports RSA/Ed25519/ECDSA keys.
- **`SCEChecker`** — Executes read-only commands (`sudo lxc list`, `systemctl status`, log tailing) and parses their output
- **`Reporter`** — Rich terminal tables with color-coded status (✓/✗/○). Falls back to plain text if `rich` is unavailable.

Network flow: `local → remotesupport.ordr.net → customer alias → SCE`

### `integration_tester.py` — API-Level Integration Health Checks
Runs layered health checks (DNS → Network → SSL → Auth → API → Data) directly against integration endpoints, optionally tunneled through the jump server.

Key classes:
- **`IntegrationHealthChecker`** (base) — Common tests: DNS, TCP connectivity, SSL cert validation, rate limits
- Subclasses: `ActiveDirectoryChecker` (LDAP/ldap3), `CrowdStrikeChecker` (OAuth2), `IntuneChecker` (Azure AD + Graph API), `VMwareChecker` (vSphere API)
- **`DiagnosticRunner`** — Orchestrates checks, generates `DiagnosticReport` with recommendations, exports JSON
- **`JumpServerManager`** — Parses rVPN aliases and creates SSH tunnels for remote testing

### `integrations_diagnostics_web.py` — Flask Web UI
Thin Flask wrapper around `integration_tester.py`. Runs on port 5001. Keeps up to 50 recent results in memory. Routes: `/`, `/api/customers`, `/api/test`, `/api/recent`, `/api/export/<id>`, `/health`.

## Known Integration Service Names (used in `--integration` flag)

`crowdstrikeapp`, `iseapp`, `merakiapp`, `tenableapi`, `VulnerabilityScannerApp`, `panapp`, `nsxapp`, `snow`, `nuvolo`, `mistapp`, `fortinacapp`, `fnetapp`, `checkpoint`, `mds2api`, `Mds2App`, `dba-data-agent`, `splunk-update`

## Configuration

User config lives at `~/.ordr/config.yaml`:
```yaml
ssh:
  user: your_username
  key: ~/.ssh/rVPN.key
  jump_host: remotesupport.ordr.net
customers:
  rtc-prod:
    notes: "RTC Production"
```
