#!/usr/bin/env python3
"""
ORDR Integration Status Tool
CLI tool to check customer integration status via SSH through jump servers.

NOTE: This tool is READ-ONLY. It only executes diagnostic commands
(lxc list, systemctl status, log tails) and does not modify any
settings, restart services, or make changes to the SCE or containers.
"""

import argparse
import os
import sys
import re
import getpass
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta

import yaml

try:
    import paramiko
    from paramiko import SSHClient, AutoAddPolicy, RSAKey, Ed25519Key, ECDSAKey
except ImportError:
    print("Error: paramiko is required. Install with: pip install paramiko")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ============================================================================
# Constants
# ============================================================================

CONFIG_DIR = Path.home() / ".ordr"
CONFIG_FILE = CONFIG_DIR / "config.yaml"

DEFAULT_CONFIG = {
    "ssh": {
        "user": "",
        "key": "~/.ssh/rVPN.key",
        "jump_host": "remotesupport.ordr.net",
    },
    "customers": {},
}

# Known integration services in POC container
INTEGRATION_SERVICES = [
    "crowdstrikeapp",
    "iseapp",
    "merakiapp",
    "tenableapi",
    "VulnerabilityScannerApp",
    "panapp",
    "nsxapp",
    "snow",
    "nuvolo",
    "mistapp",
    "fortinacapp",
    "fnetapp",
    "checkpoint",
    "mds2api",
    "Mds2App",
    "dba-data-agent",
    "splunk-update",
]

# Containers that are expected to be stopped
EXPECTED_STOPPED = ["ML"]


# ============================================================================
# ConfigManager
# ============================================================================

class ConfigManager:
    """Handles loading and saving ~/.ordr/config.yaml"""

    def __init__(self):
        self.config = DEFAULT_CONFIG.copy()
        self.load()

    def load(self) -> Dict:
        """Load config from file if it exists."""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r") as f:
                loaded = yaml.safe_load(f) or {}
                # Merge with defaults
                for key in DEFAULT_CONFIG:
                    if key in loaded:
                        if isinstance(DEFAULT_CONFIG[key], dict):
                            self.config[key] = {**DEFAULT_CONFIG[key], **loaded[key]}
                        else:
                            self.config[key] = loaded[key]
        return self.config

    def save(self):
        """Save config to file."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)

    def init_config(self) -> bool:
        """Initialize config file with defaults."""
        if CONFIG_FILE.exists():
            return False
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        # Create config with helpful comments
        config_content = """# ORDR Status Tool Configuration

# Your SSH settings for jump server
ssh:
  user: ""  # Your username for remotesupport.ordr.net
  key: ~/.ssh/rVPN.key  # Path to your SSH private key
  jump_host: remotesupport.ordr.net

# Customer aliases (matches what's on remotesupport)
# These are auto-populated when you run --list
# You can add notes to help remember what each customer is
customers:
  # example-prod:
  #   notes: "Example Customer Production"
"""
        with open(CONFIG_FILE, "w") as f:
            f.write(config_content)
        return True

    def get_ssh_user(self) -> str:
        return self.config["ssh"].get("user", "")

    def get_ssh_key(self) -> str:
        key_path = self.config["ssh"].get("key", "~/.ssh/rVPN.key")
        return os.path.expanduser(key_path)

    def get_jump_host(self) -> str:
        return self.config["ssh"].get("jump_host", "remotesupport.ordr.net")

    def get_customers(self) -> Dict:
        return self.config.get("customers", {})

    def add_customer(self, alias: str, notes: str = ""):
        """Add or update a customer alias."""
        if "customers" not in self.config:
            self.config["customers"] = {}
        if alias not in self.config["customers"]:
            self.config["customers"][alias] = {"notes": notes}
        self.save()


# ============================================================================
# JumpSSH
# ============================================================================

class JumpSSH:
    """Handles SSH connections through jump server to SCE."""

    def __init__(self, config: ConfigManager):
        self.config = config
        self.client: Optional[SSHClient] = None
        self.channel = None
        self.cpnadmin_password: Optional[str] = None

    def _load_key(self, key_path: str):
        """Load SSH private key, trying different key types."""
        key_path = os.path.expanduser(key_path)

        if not os.path.exists(key_path):
            raise FileNotFoundError(f"SSH key not found: {key_path}")

        # Try different key types
        key_types = [RSAKey, Ed25519Key, ECDSAKey]
        last_error = None

        for key_type in key_types:
            try:
                return key_type.from_private_key_file(key_path)
            except Exception as e:
                last_error = e
                continue

        raise Exception(f"Could not load SSH key {key_path}: {last_error}")

    def connect_to_jump(self) -> bool:
        """Connect to the jump server (remotesupport.ordr.net)."""
        user = self.config.get_ssh_user()
        if not user:
            print("Error: SSH user not configured. Run --init and edit ~/.ordr/config.yaml")
            return False

        key_path = self.config.get_ssh_key()
        jump_host = self.config.get_jump_host()

        try:
            key = self._load_key(key_path)
        except Exception as e:
            print(f"Error loading SSH key: {e}")
            return False

        self.client = SSHClient()
        self.client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            self.client.connect(
                jump_host,
                username=user,
                pkey=key,
                timeout=30,
            )
            return True
        except Exception as e:
            print(f"Error connecting to {jump_host}: {e}")
            return False

    def list_customer_aliases(self) -> List[str]:
        """Fetch available customer aliases from jump server."""
        if not self.client:
            if not self.connect_to_jump():
                return []

        try:
            # Common locations for aliases/scripts on jump servers
            commands = [
                "compgen -A alias 2>/dev/null | grep -E '(prod|stage|dev|test)' || true",
                "ls -1 ~/bin/ 2>/dev/null | grep -E '(prod|stage|dev|test)' || true",
                "alias 2>/dev/null | grep -oP \"alias \\K[^=]+\" || true",
            ]

            aliases = set()
            for cmd in commands:
                stdin, stdout, stderr = self.client.exec_command(cmd)
                output = stdout.read().decode().strip()
                if output:
                    for line in output.split("\n"):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Clean up alias names
                            if "=" in line:
                                line = line.split("=")[0]
                            aliases.add(line)

            return sorted(list(aliases))
        except Exception as e:
            print(f"Error fetching aliases: {e}")
            return []

    def connect_to_customer(self, customer_alias: str) -> bool:
        """Connect to customer SCE via alias."""
        if not self.client:
            if not self.connect_to_jump():
                return False

        try:
            # Get an interactive shell
            self.channel = self.client.invoke_shell()
            self.channel.settimeout(60)

            # Wait for initial prompt
            time.sleep(1)
            self._read_until_prompt()

            # Execute customer alias
            self.channel.send(f"{customer_alias}\n")
            time.sleep(2)

            # Check for password prompt (cpnadmin)
            output = self._read_available()

            if "password" in output.lower():
                if not self.cpnadmin_password:
                    self.cpnadmin_password = getpass.getpass("cpnadmin password: ")
                self.channel.send(f"{self.cpnadmin_password}\n")
                time.sleep(2)
                output = self._read_available()

            # Verify we're connected (look for prompt)
            if "@" in output or "$" in output or "#" in output:
                return True

            # Try sending a test command
            self.channel.send("echo 'CONNECTED'\n")
            time.sleep(1)
            output = self._read_available()

            return "CONNECTED" in output

        except Exception as e:
            print(f"Error connecting to {customer_alias}: {e}")
            return False

    def _read_until_prompt(self, timeout: int = 30) -> str:
        """Read from channel until we see a prompt."""
        output = ""
        end_time = time.time() + timeout

        while time.time() < end_time:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096).decode("utf-8", errors="ignore")
                output += chunk
                # Check for common prompts
                if output.rstrip().endswith(("$", "#", ">", "~]")):
                    break
            else:
                time.sleep(0.1)

        return output

    def _read_available(self) -> str:
        """Read whatever is available in the channel buffer."""
        output = ""
        while self.channel.recv_ready():
            output += self.channel.recv(4096).decode("utf-8", errors="ignore")
        return output

    def run_command(self, command: str, timeout: int = 60) -> str:
        """Run a command on the connected SCE and return output."""
        if not self.channel:
            raise Exception("Not connected to SCE")

        # Clear any pending output
        self._read_available()

        # Send command
        self.channel.send(f"{command}\n")

        # Wait for output
        time.sleep(1)

        output = ""
        end_time = time.time() + timeout

        while time.time() < end_time:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096).decode("utf-8", errors="ignore")
                output += chunk
                # If we see a prompt after the output, we're done
                lines = output.strip().split("\n")
                if len(lines) > 1:
                    last_line = lines[-1].strip()
                    if last_line.endswith(("$", "#", ">")):
                        break
            else:
                time.sleep(0.2)

        # Remove the command echo and trailing prompt
        lines = output.split("\n")
        if lines and command in lines[0]:
            lines = lines[1:]
        if lines and lines[-1].strip().endswith(("$", "#", ">")):
            lines = lines[:-1]

        return "\n".join(lines)

    def run_command_direct(self, command: str) -> Tuple[str, str]:
        """Run a command directly on jump server (not through alias)."""
        if not self.client:
            if not self.connect_to_jump():
                return "", "Not connected"

        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=60)
            return stdout.read().decode(), stderr.read().decode()
        except Exception as e:
            return "", str(e)

    def close(self):
        """Close all connections."""
        if self.channel:
            self.channel.close()
        if self.client:
            self.client.close()

    def interactive_shell(self):
        """Start an interactive shell session."""
        if not self.channel:
            raise Exception("Not connected to SCE")

        import select
        import termios
        import tty

        # Save terminal settings
        old_tty = termios.tcgetattr(sys.stdin)

        try:
            # Set terminal to raw mode
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            self.channel.settimeout(0.0)

            print("\r\nInteractive shell started. Press Ctrl+] to exit.\r\n")

            while True:
                r, w, e = select.select([self.channel, sys.stdin], [], [])

                if self.channel in r:
                    try:
                        data = self.channel.recv(1024)
                        if not data:
                            break
                        sys.stdout.write(data.decode("utf-8", errors="ignore"))
                        sys.stdout.flush()
                    except Exception:
                        break

                if sys.stdin in r:
                    char = sys.stdin.read(1)
                    if not char:
                        break
                    # Ctrl+] to exit
                    if char == "\x1d":
                        break
                    self.channel.send(char)
        finally:
            # Restore terminal settings
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
            print("\nExited interactive shell.")


# ============================================================================
# SCEChecker
# ============================================================================

@dataclass
class ContainerStatus:
    name: str
    state: str
    ipv4: str
    ipv6: str

@dataclass
class ServiceStatus:
    name: str
    active: bool
    status: str
    last_update: Optional[str] = None

@dataclass
class LogEntry:
    service: str
    message: str
    timestamp: Optional[str] = None


class SCEChecker:
    """Runs diagnostic commands on SCE and parses results."""

    def __init__(self, ssh: JumpSSH):
        self.ssh = ssh

    def get_container_status(self) -> List[ContainerStatus]:
        """Get status of all LXC containers."""
        output = self.ssh.run_command("sudo lxc list")
        containers = []

        # Parse lxc list output
        # Format: | NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
        for line in output.split("\n"):
            if "|" not in line or "NAME" in line or "---" in line:
                continue

            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 5:
                name = parts[1]
                state = parts[2]
                ipv4 = parts[3] if len(parts) > 3 else ""
                ipv6 = parts[4] if len(parts) > 4 else ""

                if name:  # Skip empty rows
                    containers.append(ContainerStatus(
                        name=name,
                        state=state,
                        ipv4=ipv4,
                        ipv6=ipv6
                    ))

        return containers

    def get_integration_status(self, integration: Optional[str] = None) -> List[ServiceStatus]:
        """Get status of integration services in POC container."""
        services = []

        if integration:
            # Check specific integration
            services_to_check = [integration]
        else:
            # Check all known integrations
            services_to_check = INTEGRATION_SERVICES

        for service in services_to_check:
            try:
                output = self.ssh.run_command(
                    f"sudo lxc exec POC -- systemctl status {service} --no-pager 2>/dev/null || echo 'NOT_FOUND'"
                )

                if "NOT_FOUND" in output or "could not be found" in output.lower():
                    continue  # Service doesn't exist, skip

                # Parse systemctl status output
                active = "active (running)" in output.lower() or "active (exited)" in output.lower()

                # Get status line
                status = "unknown"
                if "active (running)" in output.lower():
                    status = "active"
                elif "active (exited)" in output.lower():
                    status = "active (exited)"
                elif "inactive" in output.lower():
                    status = "inactive"
                elif "failed" in output.lower():
                    status = "failed"

                # Try to get last activity time
                last_update = None
                time_match = re.search(r"Active:.*since\s+(.+);", output)
                if time_match:
                    # Calculate relative time
                    last_update = self._parse_relative_time(output)

                services.append(ServiceStatus(
                    name=service,
                    active=active,
                    status=status,
                    last_update=last_update
                ))
            except Exception:
                continue

        return services

    def _parse_relative_time(self, systemctl_output: str) -> Optional[str]:
        """Extract relative time from systemctl output."""
        # Look for patterns like "2h 30min ago" or "30min 15s ago"
        match = re.search(r";\s*([\d]+[dhms][\d\w\s]*)\s*ago", systemctl_output)
        if match:
            return match.group(1).strip() + " ago"
        return None

    def get_all_poc_services(self) -> List[str]:
        """Get list of all running services in POC container."""
        output = self.ssh.run_command(
            "sudo lxc exec POC -- systemctl list-units --type=service --state=running --no-pager"
        )

        services = []
        for line in output.split("\n"):
            if ".service" in line:
                # Extract service name
                match = re.search(r"^\s*(\S+\.service)", line)
                if match:
                    service_name = match.group(1).replace(".service", "")
                    services.append(service_name)

        return services

    def get_integration_errors(self, service: Optional[str] = None, hours: int = 24) -> List[LogEntry]:
        """Get recent errors from integration logs."""
        errors = []

        if service:
            services = [service]
        else:
            # Check all known integrations
            services = INTEGRATION_SERVICES

        for svc in services:
            try:
                # Try common log locations
                log_paths = [
                    f"/var/log/{svc}/{svc}.log",
                    f"/var/log/{svc}/error.log",
                    f"/var/log/{svc}.log",
                ]

                for log_path in log_paths:
                    output = self.ssh.run_command(
                        f"sudo lxc exec POC -- tail -500 {log_path} 2>/dev/null | grep -i error | tail -20 || true"
                    )

                    if output.strip():
                        for line in output.strip().split("\n"):
                            if line.strip():
                                errors.append(LogEntry(
                                    service=svc,
                                    message=line.strip()[:200],  # Truncate long messages
                                    timestamp=self._extract_timestamp(line)
                                ))
                        break  # Found logs, no need to check other paths

            except Exception:
                continue

        return errors

    def _extract_timestamp(self, log_line: str) -> Optional[str]:
        """Try to extract timestamp from log line."""
        # Common timestamp patterns
        patterns = [
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})",
            r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
        ]

        for pattern in patterns:
            match = re.search(pattern, log_line)
            if match:
                return match.group(1)

        return None

    def get_service_status(self, container: str, service: str) -> ServiceStatus:
        """Check status of a specific service in a container."""
        output = self.ssh.run_command(
            f"sudo lxc exec {container} -- systemctl status {service} --no-pager 2>/dev/null || echo 'NOT_FOUND'"
        )

        if "NOT_FOUND" in output or "could not be found" in output.lower():
            return ServiceStatus(name=service, active=False, status="not found")

        active = "active (running)" in output.lower()

        status = "unknown"
        if "active (running)" in output.lower():
            status = "active"
        elif "inactive" in output.lower():
            status = "inactive"
        elif "failed" in output.lower():
            status = "failed"

        return ServiceStatus(
            name=service,
            active=active,
            status=status,
            last_update=self._parse_relative_time(output)
        )


# ============================================================================
# Reporter
# ============================================================================

class Reporter:
    """Formats and displays terminal output."""

    def __init__(self):
        self.use_rich = RICH_AVAILABLE
        if self.use_rich:
            self.console = Console()

    def print_header(self, customer: str):
        """Print the main header."""
        if self.use_rich:
            self.console.print()
            self.console.print(Panel(
                f"[bold blue]ORDR Status: {customer}[/bold blue]",
                border_style="blue"
            ))
        else:
            print()
            print(f"ORDR Status: {customer}")
            print("=" * 60)

    def print_containers(self, containers: List[ContainerStatus]):
        """Print container status table."""
        if self.use_rich:
            table = Table(title="CONTAINERS", show_header=True)
            table.add_column("NAME", style="cyan")
            table.add_column("STATUS", style="white")
            table.add_column("IP", style="dim")

            for c in containers:
                status_style = "green" if c.state == "RUNNING" else "yellow"
                icon = "[green]✓[/green]" if c.state == "RUNNING" else "[yellow]○[/yellow]"

                status_text = f"{icon} {c.state}"
                if c.name in EXPECTED_STOPPED and c.state != "RUNNING":
                    status_text += " [dim](expected)[/dim]"

                table.add_row(c.name, status_text, c.ipv4.split()[0] if c.ipv4 else "")

            self.console.print(table)
        else:
            print()
            print("CONTAINERS                           STATUS")
            print("-" * 60)
            for c in containers:
                icon = "✓" if c.state == "RUNNING" else "○"
                status = f"{icon} {c.state}"
                if c.name in EXPECTED_STOPPED and c.state != "RUNNING":
                    status += " (expected)"
                ip = c.ipv4.split()[0] if c.ipv4 else ""
                print(f"{c.name:<36} {status:<20} {ip}")

    def print_integrations(self, services: List[ServiceStatus]):
        """Print integration status table."""
        if not services:
            print("\nNo integration services found.")
            return

        if self.use_rich:
            table = Table(title="INTEGRATIONS (POC Container)", show_header=True)
            table.add_column("SERVICE", style="cyan")
            table.add_column("STATUS", style="white")
            table.add_column("LAST UPDATE", style="dim")

            for s in services:
                if s.status == "active":
                    icon = "[green]✓[/green]"
                    status_style = "green"
                elif s.status == "failed":
                    icon = "[red]✗[/red]"
                    status_style = "red"
                else:
                    icon = "[yellow]○[/yellow]"
                    status_style = "yellow"

                status_text = f"{icon} {s.status}"
                last_update = s.last_update or ""

                table.add_row(s.name, status_text, last_update)

            self.console.print(table)
        else:
            print()
            print("INTEGRATIONS (POC Container)         STATUS        LAST UPDATE")
            print("-" * 60)
            for s in services:
                if s.status == "active":
                    icon = "✓"
                elif s.status == "failed":
                    icon = "✗"
                else:
                    icon = "○"

                status = f"{icon} {s.status}"
                last_update = s.last_update or ""
                print(f"{s.name:<36} {status:<14} {last_update}")

    def print_errors(self, errors: List[LogEntry], hours: int = 24):
        """Print recent errors."""
        if self.use_rich:
            self.console.print()
            self.console.print(f"[bold]RECENT ERRORS (last {hours}h)[/bold]")
            self.console.print("-" * 60)

            if not errors:
                self.console.print("[dim]No errors found[/dim]")
            else:
                for e in errors[:20]:  # Limit to 20 errors
                    self.console.print(f"[yellow][{e.service}][/yellow] {e.message}")
        else:
            print()
            print(f"RECENT ERRORS (last {hours}h)")
            print("-" * 60)

            if not errors:
                print("No errors found")
            else:
                for e in errors[:20]:
                    print(f"[{e.service}] {e.message}")

    def print_customer_list(self, aliases: List[str], customer_notes: Dict):
        """Print list of customer aliases."""
        if self.use_rich:
            table = Table(title="Available Customer Aliases", show_header=True)
            table.add_column("ALIAS", style="cyan")
            table.add_column("NOTES", style="dim")

            for alias in aliases:
                notes = customer_notes.get(alias, {}).get("notes", "")
                table.add_row(alias, notes)

            self.console.print(table)
        else:
            print()
            print("Available Customer Aliases")
            print("-" * 40)
            for alias in aliases:
                notes = customer_notes.get(alias, {}).get("notes", "")
                if notes:
                    print(f"  {alias:<20} {notes}")
                else:
                    print(f"  {alias}")

    def print_error(self, message: str):
        """Print an error message."""
        if self.use_rich:
            self.console.print(f"[red]Error:[/red] {message}")
        else:
            print(f"Error: {message}")

    def print_success(self, message: str):
        """Print a success message."""
        if self.use_rich:
            self.console.print(f"[green]✓[/green] {message}")
        else:
            print(f"✓ {message}")

    def print_info(self, message: str):
        """Print an info message."""
        if self.use_rich:
            self.console.print(f"[blue]ℹ[/blue] {message}")
        else:
            print(f"ℹ {message}")


# ============================================================================
# Main CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ORDR Integration Status Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ordr-status --init                    Initialize configuration
  ordr-status --list                    List available customer aliases
  ordr-status rtc-prod                  Quick health check
  ordr-status rtc-prod --integration crowdstrike  Check specific integration
  ordr-status rtc-prod --errors         Show integration errors
  ordr-status rtc-prod --full           Full diagnostic
  ordr-status rtc-prod --shell          Interactive shell
        """
    )

    parser.add_argument("customer", nargs="?", help="Customer alias to check")
    parser.add_argument("--init", action="store_true", help="Initialize config file")
    parser.add_argument("--list", action="store_true", help="List available customer aliases")
    parser.add_argument("--integration", "-i", help="Check specific integration service")
    parser.add_argument("--errors", "-e", action="store_true", help="Show recent integration errors")
    parser.add_argument("--full", "-f", action="store_true", help="Full diagnostic (all details)")
    parser.add_argument("--shell", "-s", action="store_true", help="Interactive shell mode")

    args = parser.parse_args()

    config = ConfigManager()
    reporter = Reporter()

    # Handle --init
    if args.init:
        if config.init_config():
            reporter.print_success(f"Created config file: {CONFIG_FILE}")
            reporter.print_info(f"Edit {CONFIG_FILE} to add your SSH username and key path")
        else:
            reporter.print_info(f"Config file already exists: {CONFIG_FILE}")
        return 0

    # Validate SSH config
    if not config.get_ssh_user():
        reporter.print_error(f"SSH user not configured. Run --init and edit {CONFIG_FILE}")
        return 1

    ssh = JumpSSH(config)

    try:
        # Handle --list
        if args.list:
            reporter.print_info("Connecting to jump server...")
            if not ssh.connect_to_jump():
                return 1

            reporter.print_info("Fetching customer aliases...")
            aliases = ssh.list_customer_aliases()

            if aliases:
                # Update config with discovered aliases
                for alias in aliases:
                    config.add_customer(alias)

                reporter.print_customer_list(aliases, config.get_customers())
            else:
                reporter.print_info("No aliases found. You may need to add them manually to config.")

            ssh.close()
            return 0

        # Require customer for other operations
        if not args.customer:
            parser.print_help()
            return 1

        customer = args.customer

        # Connect to jump server
        reporter.print_info(f"Connecting to {config.get_jump_host()}...")
        if not ssh.connect_to_jump():
            return 1

        # Connect to customer SCE
        reporter.print_info(f"Connecting to {customer}...")
        if not ssh.connect_to_customer(customer):
            reporter.print_error(f"Failed to connect to {customer}")
            return 1

        reporter.print_success(f"Connected to {customer}")

        # Handle --shell (interactive mode)
        if args.shell:
            ssh.interactive_shell()
            ssh.close()
            return 0

        checker = SCEChecker(ssh)

        # Print header
        reporter.print_header(customer)

        # Get container status (always)
        containers = checker.get_container_status()
        reporter.print_containers(containers)

        # Get integration status
        if args.integration:
            services = checker.get_integration_status(args.integration)
        elif args.full:
            services = checker.get_integration_status()
        else:
            # Quick check - only show active/failed services
            all_services = checker.get_integration_status()
            services = [s for s in all_services if s.status in ("active", "failed")]

        reporter.print_integrations(services)

        # Show errors if requested
        if args.errors or args.full:
            errors = checker.get_integration_errors(args.integration)
            reporter.print_errors(errors)

        print()  # Final newline

    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as e:
        reporter.print_error(str(e))
        return 1
    finally:
        ssh.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
