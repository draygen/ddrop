# ORDR Integration Status Tool

CLI tool to check customer integration status by SSHing through jump servers to ORDR SCE appliances.

> **NOTE: This tool is READ-ONLY.** It only gathers diagnostic data and does not modify any settings on the SCE, containers, or jump server.

## Network Flow

```
Mac (Corporate VPN) → remotesupport.ordr.net → customer alias → SCE (cpnadmin)
```

## Installation

### Option 1: Direct Run (Recommended)

Just clone and run - the wrapper script handles everything:

```bash
git clone <repo-url> ordr-status
cd ordr-status
./ordr-status --init
```

The first run automatically creates a Python virtual environment and installs dependencies.

### Option 2: Install with pip

```bash
pip install .
# or from git:
pip install git+https://github.com/ordr/ordr-status.git
```

### Option 3: Install with pipx (isolated)

```bash
pipx install .
```

## Configuration

Initialize the config file:

```bash
ordr-status --init
```

Edit `~/.ordr/config.yaml` with your SSH settings:

```yaml
ssh:
  user: your_username        # Your remotesupport username
  key: ~/.ssh/rVPN.key       # Path to your SSH private key
  jump_host: remotesupport.ordr.net
```

## Usage

```bash
# List available customer aliases (fetches from jump server)
ordr-status --list

# Quick health check - container status + integration summary
ordr-status rtc-prod

# Check specific integration
ordr-status rtc-prod --integration crowdstrike

# Show integration errors from logs
ordr-status rtc-prod --errors

# Full diagnostic (all containers, all integrations, recent logs)
ordr-status rtc-prod --full

# Interactive mode - connect and run commands manually
ordr-status rtc-prod --shell
```

## Sample Output

```
$ ordr-status rtc-prod

ORDR Status: rtc-prod
═══════════════════════════════════════════════════════════

CONTAINERS                           STATUS
─────────────────────────────────────────────────────────
DBA                                  ✓ RUNNING
ILC                                  ✓ RUNNING
POC                                  ✓ RUNNING
KAFKA                                ✓ RUNNING
NGINX                                ✓ RUNNING
ML                                   ○ STOPPED (expected)

INTEGRATIONS (POC Container)         STATUS        LAST UPDATE
─────────────────────────────────────────────────────────
crowdstrikeapp                       ✓ active      2h ago
iseapp                               ✓ active      1h ago
merakiapp                            ✗ failed      3d ago
tenableapi                           ✓ active      30m ago

RECENT ERRORS (last 24h)
─────────────────────────────────────────────────────────
[merakiapp] API rate limit exceeded - 429 response
```

## What Commands Are Run on SCE

This tool executes the following **read-only** commands:

```bash
# Container status (read-only)
sudo lxc list

# Service status checks (read-only)
sudo lxc exec POC -- systemctl status <service> --no-pager

# Log inspection (read-only)
sudo lxc exec POC -- tail -100 /var/log/<service>/<service>.log | grep -i error

# List running services (read-only)
sudo lxc exec POC -- systemctl list-units --type=service --state=running
```

**No write operations, no configuration changes, no service restarts.**

## Dependencies

- Python 3.8+
- paramiko (SSH connections)
- pyyaml (config file)
- rich (terminal formatting)

## Files

| File | Purpose |
|------|---------|
| `ordr-status` | Shell wrapper (auto-setup) |
| `ordr_status.py` | Main Python tool |
| `~/.ordr/config.yaml` | User configuration |
