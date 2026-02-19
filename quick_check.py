#!/usr/bin/env python3
"""
Quick integration health check: status + errors + connectivity in one shot.

Usage: ./check <customer> <integration> [--host HOST] [--port PORT] [--hours N]

Examples:
  ./check rtc-prod crowdstrike
  ./check rtc-prod iseapp --host 10.1.2.3
  ./check rtc-prod panapp --host 10.1.2.3 --port 9090
  ./check rtc-prod crowdstrike --hours 48
"""

import sys
import os
import re
import argparse
from typing import Optional, Tuple, List

# Import shared SSH/config machinery from ordr_status.py (same directory)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ordr_status import ConfigManager, JumpSSH, SCEChecker

try:
    from rich.console import Console
    from rich.rule import Rule
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


# ============================================================================
# Quick Checker
# ============================================================================

class IntegrationQuickCheck:
    """Combines service status, log errors, and connectivity into one check."""

    def __init__(self, ssh: JumpSSH):
        self.ssh = ssh
        self.sce = SCEChecker(ssh)

    def get_recent_errors(self, service: str, hours: int = 24) -> List[str]:
        """Pull recent error lines. Tries journald first, falls back to log files."""
        # journald is most reliable for systemd-managed services
        output = self.ssh.run_command(
            f'sudo lxc exec POC -- journalctl -u {service} --no-pager -n 200 '
            f'--since "{hours} hours ago" 2>/dev/null '
            f'| grep -iE "error|fail|exception|warn" | tail -20 || true'
        )
        if output.strip():
            return [l for l in output.strip().split('\n') if l.strip()]

        # Fallback: common log file paths
        for path in [
            f'/var/log/{service}/{service}.log',
            f'/var/log/{service}/error.log',
            f'/var/log/{service}.log',
        ]:
            output = self.ssh.run_command(
                f'sudo lxc exec POC -- tail -500 {path} 2>/dev/null '
                f'| grep -iE "error|fail|exception" | tail -20 || true'
            )
            if output.strip():
                return [l for l in output.strip().split('\n') if l.strip()]

        return []

    def find_integration_target(self, service: str) -> Optional[Tuple[str, int]]:
        """
        Try to auto-detect the integration's target host:port from:
          1. The service's ExecStart line (looking for a --config flag)
          2. Common config file paths on the SCE
          3. Recent journald logs (grep for URLs)
        Returns (host, port) or None if not found.
        """
        # 1. Check systemctl ExecStart for a --config flag pointing to a config file
        show_out = self.ssh.run_command(
            f'sudo lxc exec POC -- systemctl show {service} '
            f'--property=ExecStart --no-pager 2>/dev/null || true'
        )
        cfg_match = re.search(r'--config[= ]+(\S+)', show_out)
        if cfg_match:
            config_path = cfg_match.group(1)
            content = self.ssh.run_command(
                f'sudo lxc exec POC -- cat {config_path} 2>/dev/null || true'
            )
            found = self._extract_host_port(content)
            if found:
                return found

        # 2. Common config file locations
        for path in [
            f'/etc/{service}/config.yaml',
            f'/etc/{service}/config.json',
            f'/etc/ordr/{service}.yaml',
            f'/var/lib/{service}/config.yaml',
            f'/opt/{service}/config.yaml',
        ]:
            content = self.ssh.run_command(
                f'sudo lxc exec POC -- cat {path} 2>/dev/null || true'
            )
            if content.strip():
                found = self._extract_host_port(content)
                if found:
                    return found

        # 3. Grep recent logs for URLs (e.g. "connecting to https://api.example.com")
        log_out = self.ssh.run_command(
            f'sudo lxc exec POC -- journalctl -u {service} --no-pager -n 300 2>/dev/null '
            f'| grep -Eo "https?://[a-zA-Z0-9._-]+" | sort -u | head -5 || true'
        )
        for url in log_out.strip().split('\n'):
            url = url.strip()
            if url:
                found = self._extract_host_port(url)
                if found:
                    return found

        return None

    def _extract_host_port(self, text: str) -> Optional[Tuple[str, int]]:
        """Parse host and port out of a config blob or URL string."""
        if not text:
            return None

        # URL pattern: https://hostname or https://hostname:port
        url_m = re.search(r'https?://([a-zA-Z0-9._-]+)(?::(\d+))?', text)
        if url_m:
            host = url_m.group(1)
            port = int(url_m.group(2)) if url_m.group(2) else 443
            if '.' in host or len(host) > 4:  # skip single-word non-FQDN junk
                return host, port

        # YAML/JSON key patterns: host: value, server: value, endpoint: value
        for pattern in [
            r'(?:host|server|endpoint|api_host|api_url)\s*[:=]\s*["\']?([a-zA-Z0-9._-]{5,})',
            r'"(?:host|server|endpoint)"\s*:\s*"([a-zA-Z0-9._-]{5,})"',
        ]:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                host = m.group(1).strip('\'"')
                port_m = re.search(r'(?:port)\s*[:=]\s*["\']?(\d{2,5})', text, re.IGNORECASE)
                port = int(port_m.group(1)) if port_m else 443
                return host, port

        return None

    def test_tcp_from_sce(self, host: str, port: int) -> dict:
        """
        Run a TCP connectivity test from inside the POC container.
        Tries nc first; falls back to bash /dev/tcp redirect.
        Returns dict with keys: reachable (bool), output (str).
        """
        result = {'reachable': False, 'output': ''}

        # Primary: nc (netcat)
        nc_out = self.ssh.run_command(
            f'sudo lxc exec POC -- nc -zv -w5 {host} {port} 2>&1 || true'
        )
        result['output'] = nc_out.strip()

        lower = nc_out.lower()
        if ('succeeded' in lower or 'connected' in lower or ' open' in lower
                or 'ncat: connected' in lower):
            result['reachable'] = True
            return result

        # If nc produced no output it might not be installed; try bash /dev/tcp
        if not nc_out.strip() or 'not found' in lower or 'no such' in lower:
            bash_out = self.ssh.run_command(
                f'sudo lxc exec POC -- bash -c '
                f'"(echo >/dev/tcp/{host}/{port}) 2>/dev/null && echo OPEN || echo CLOSED" || true'
            )
            result['output'] = bash_out.strip()
            result['reachable'] = 'OPEN' in bash_out

        return result


# ============================================================================
# Output helpers
# ============================================================================

def _info(msg: str):
    if RICH_AVAILABLE:
        console.print(f'[dim]{msg}[/dim]')
    else:
        print(msg)


def _err(msg: str):
    if RICH_AVAILABLE:
        console.print(f'[red]{msg}[/red]')
    else:
        print(f'ERROR: {msg}', file=sys.stderr)


def _print_results(customer, integration, svc_statuses, errors, conn_result, conn_target, hours):
    if RICH_AVAILABLE:
        _print_rich(customer, integration, svc_statuses, errors, conn_result, conn_target, hours)
    else:
        _print_plain(customer, integration, svc_statuses, errors, conn_result, conn_target, hours)


def _print_rich(customer, integration, svc_statuses, errors, conn_result, conn_target, hours):
    console.print()
    console.rule(f'[bold blue]Quick Check: {customer} › {integration}[/bold blue]')

    # Service status
    console.print()
    console.print('[bold]SERVICE STATUS[/bold]')
    if svc_statuses:
        for s in svc_statuses:
            if s.status == 'active':
                badge = '[green]✓ active[/green]'
            elif s.status == 'failed':
                badge = '[red]✗ failed[/red]'
            else:
                badge = f'[yellow]○ {s.status}[/yellow]'
            since = f'  [dim](since {s.last_update})[/dim]' if s.last_update else ''
            console.print(f'  {badge}{since}')
    else:
        console.print('  [yellow]○ service not found in POC container[/yellow]')

    # Recent errors
    console.print()
    console.print(f'[bold]RECENT ERRORS[/bold] [dim](last {hours}h)[/dim]')
    if errors:
        for line in errors[:15]:
            console.print(f'  [dim]{line.strip()[:130]}[/dim]')
    else:
        console.print('  [green]No errors found[/green]')

    # Connectivity
    console.print()
    if conn_result and conn_target:
        host, port = conn_target
        console.print(f'[bold]CONNECTIVITY[/bold] [dim](from SCE → {host}:{port})[/dim]')
        if conn_result['reachable']:
            console.print(f'  [green]✓ TCP port {port} reachable[/green]')
        else:
            console.print(f'  [red]✗ TCP port {port} unreachable[/red]')
            if conn_result.get('output'):
                console.print(f'    [dim]{conn_result["output"][:120]}[/dim]')
    elif conn_target is None:
        console.print('[bold]CONNECTIVITY[/bold]')
        console.print(
            '  [dim]Could not auto-detect integration target. '
            'Run with --host HOST [--port PORT] to test.[/dim]'
        )

    # Summary line
    console.print()
    svc_ok = bool(svc_statuses) and all(s.status == 'active' for s in svc_statuses)
    conn_ok = conn_result is None or conn_result['reachable']
    has_errors = bool(errors)

    if svc_ok and conn_ok and not has_errors:
        summary = '[green]✓ HEALTHY[/green]'
    elif svc_statuses and any(s.status == 'failed' for s in svc_statuses):
        suffix = ''
        if conn_result is not None:
            suffix = ' — connectivity OK' if conn_ok else ' [red]— connectivity FAILED[/red]'
        summary = f'[red]✗ SERVICE FAILED[/red]{suffix}'
    elif not svc_statuses:
        summary = '[yellow]⚠ SERVICE NOT FOUND[/yellow]'
    elif has_errors:
        summary = '[yellow]⚠ ERRORS IN LOGS[/yellow]'
    else:
        summary = '[yellow]⚠ REVIEW OUTPUT[/yellow]'

    console.rule(f'[bold]RESULT: {summary}[/bold]')
    console.print()


def _print_plain(customer, integration, svc_statuses, errors, conn_result, conn_target, hours):
    print()
    print(f'=== Quick Check: {customer} / {integration} ===')
    print()

    print('SERVICE STATUS')
    if svc_statuses:
        for s in svc_statuses:
            icon = '✓' if s.status == 'active' else '✗'
            since = f'  (since {s.last_update})' if s.last_update else ''
            print(f'  {icon} {s.status}{since}')
    else:
        print('  ○ service not found in POC container')

    print()
    print(f'RECENT ERRORS (last {hours}h)')
    if errors:
        for line in errors[:15]:
            print(f'  {line.strip()[:130]}')
    else:
        print('  No errors found')

    print()
    if conn_result and conn_target:
        host, port = conn_target
        print(f'CONNECTIVITY (from SCE → {host}:{port})')
        icon = '✓' if conn_result['reachable'] else '✗'
        state = 'reachable' if conn_result['reachable'] else 'UNREACHABLE'
        print(f'  {icon} TCP port {port} {state}')
        if not conn_result['reachable'] and conn_result.get('output'):
            print(f'    {conn_result["output"][:120]}')
    else:
        print('CONNECTIVITY')
        print('  Could not auto-detect target. Use --host HOST [--port PORT] to test.')

    print()
    print('=' * 50)


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Quick integration health check: service status + errors + connectivity',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  ./check rtc-prod crowdstrike
  ./check rtc-prod iseapp --host 10.1.2.3
  ./check rtc-prod panapp --host 10.1.2.3 --port 9090
  ./check rtc-prod crowdstrike --hours 48
        """,
    )
    parser.add_argument('customer', help='Customer alias (e.g. rtc-prod)')
    parser.add_argument('integration', help='Integration service name (e.g. crowdstrike, iseapp)')
    parser.add_argument('--host', help='Connectivity target host (auto-detected if omitted)')
    parser.add_argument('--port', type=int, help='Connectivity target port (default: 443)')
    parser.add_argument('--hours', type=int, default=24,
                        help='How many hours back to search for errors (default: 24)')
    args = parser.parse_args()

    config = ConfigManager()
    if not config.get_ssh_user():
        _err(f'SSH user not configured. Run: ./ordr-status --init')
        sys.exit(1)

    ssh = JumpSSH(config)
    try:
        _info(f'Connecting to {config.get_jump_host()}...')
        if not ssh.connect_to_jump():
            sys.exit(1)

        _info(f'Connecting to {args.customer}...')
        if not ssh.connect_to_customer(args.customer):
            _err(f'Failed to connect to {args.customer}')
            sys.exit(1)

        checker = IntegrationQuickCheck(ssh)

        # Service status
        svc_statuses = checker.sce.get_integration_status(args.integration)

        # Recent errors
        errors = checker.get_recent_errors(args.integration, args.hours)

        # Connectivity
        conn_result = None
        conn_target = None

        if args.host:
            conn_target = (args.host, args.port or 443)
        else:
            _info('Detecting integration target from service config...')
            conn_target = checker.find_integration_target(args.integration)

        if conn_target:
            host, port = conn_target
            _info(f'Testing TCP connectivity to {host}:{port}...')
            conn_result = checker.test_tcp_from_sce(host, port)

        _print_results(
            args.customer, args.integration,
            svc_statuses, errors,
            conn_result, conn_target,
            args.hours,
        )

        # Non-zero exit if something is clearly broken
        if svc_statuses and any(s.status == 'failed' for s in svc_statuses):
            sys.exit(2)
        if conn_result and not conn_result['reachable']:
            sys.exit(2)

    except KeyboardInterrupt:
        print('\nInterrupted.')
        sys.exit(130)
    finally:
        ssh.close()


if __name__ == '__main__':
    main()
