#!/usr/bin/env python3
"""
ORDR Integration Health Diagnostic Tool
Helps troubleshoot integration issues through jump servers
"""

import os
import re
import json
import subprocess
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

import requests
from requests.auth import HTTPBasicAuth
import paramiko


# ============================================================================
# Configuration & Models
# ============================================================================

class IntegrationType(Enum):
    ACTIVE_DIRECTORY = "Active Directory"
    CROWDSTRIKE = "CrowdStrike"
    INTUNE = "Microsoft Intune"
    VMWARE_VSPHERE = "VMware vSphere"
    TENABLE = "Tenable"
    AZURE = "Azure"
    DHCP = "DHCP"


class HealthStatus(Enum):
    PASS = "✓ PASS"
    FAIL = "✗ FAIL"
    WARN = "⚠ WARN"
    SKIP = "○ SKIP"


@dataclass
class TestResult:
    test_name: str
    status: HealthStatus
    message: str
    details: Optional[Dict] = None
    duration_ms: Optional[float] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class IntegrationConfig:
    integration_type: IntegrationType
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    domain: Optional[str] = None
    tenant_id: Optional[str] = None
    use_ssl: bool = True
    verify_ssl: bool = True
    timeout: int = 30


@dataclass
class DiagnosticReport:
    customer: str
    environment: str
    integration_type: IntegrationType
    timestamp: str
    tests: List[TestResult]
    overall_status: HealthStatus
    recommendations: List[str]


# ============================================================================
# Jump Server Connection Manager
# ============================================================================

class JumpServerManager:
    """Manages connections through remotesupport and be jump servers"""
    
    def __init__(self):
        self.remotesupport_host = "remotesupport.ordr.net"
        self.remotesupport_key = Path.home() / "keys" / "rVPN.key"
        self.remotesupport_user = "brianw"
        self.be_command = "sft ssh remotesupport-ordr-net"
        
    def get_dc_cloud_aliases(self) -> Dict[str, str]:
        """Parse rVPN aliases from remotesupport server"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                self.remotesupport_host,
                username=self.remotesupport_user,
                key_filename=str(self.remotesupport_key)
            )
            
            stdin, stdout, stderr = ssh.exec_command("alias")
            alias_output = stdout.read().decode()
            ssh.close()
            
            # Parse alias output for rVPN mappings
            aliases = {}
            for line in alias_output.split('\n'):
                # Look for patterns like: alias customer='ssh -p 2222 user@host'
                match = re.search(r"alias\s+(\w+)='.*?-p\s+(\d+).*?@([\w.-]+)", line)
                if match:
                    customer_name, port, host = match.groups()
                    aliases[customer_name] = {
                        'host': host,
                        'port': port,
                        'connection': f"ssh -p {port} user@{host}"
                    }
            
            return aliases
            
        except Exception as e:
            print(f"Error getting aliases: {e}")
            return {}
    
    def connect_via_jump(self, jump_server: str, target_host: str, 
                         target_user: str = "ordr") -> paramiko.SSHClient:
        """Establish SSH connection through jump server"""
        jump_ssh = paramiko.SSHClient()
        jump_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to jump server
        if jump_server == "remotesupport":
            jump_ssh.connect(
                self.remotesupport_host,
                username=self.remotesupport_user,
                key_filename=str(self.remotesupport_key)
            )
        else:
            raise ValueError(f"Unknown jump server: {jump_server}")
        
        # Create SSH tunnel through jump server
        transport = jump_ssh.get_transport()
        dest_addr = (target_host, 22)
        local_addr = ('127.0.0.1', 0)
        channel = transport.open_channel("direct-tcpip", dest_addr, local_addr)
        
        # Connect to target through tunnel
        target_ssh = paramiko.SSHClient()
        target_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        target_ssh.connect(target_host, username=target_user, sock=channel)
        
        return target_ssh


# ============================================================================
# Integration Health Checkers
# ============================================================================

class IntegrationHealthChecker:
    """Base class for integration health checks"""
    
    def __init__(self, config: IntegrationConfig):
        self.config = config
        self.results: List[TestResult] = []
    
    def run_all_tests(self) -> List[TestResult]:
        """Run complete test suite"""
        self.results = []
        
        # Core tests
        self.test_dns_resolution()
        self.test_network_connectivity()
        self.test_ssl_certificate()
        self.test_authentication()
        self.test_api_reachability()
        self.test_data_pull()
        self.test_rate_limits()
        
        return self.results
    
    def _add_result(self, test_name: str, status: HealthStatus, 
                    message: str, details: Dict = None, duration_ms: float = None):
        """Add a test result"""
        self.results.append(TestResult(
            test_name=test_name,
            status=status,
            message=message,
            details=details,
            duration_ms=duration_ms
        ))
    
    def _timed_test(self, func):
        """Decorator to time test execution"""
        start = time.time()
        try:
            result = func()
            duration = (time.time() - start) * 1000
            return result, duration
        except Exception as e:
            duration = (time.time() - start) * 1000
            return None, duration
    
    def test_dns_resolution(self):
        """Test if hostname resolves"""
        try:
            start = time.time()
            ip = socket.gethostbyname(self.config.host)
            duration = (time.time() - start) * 1000
            
            self._add_result(
                "DNS Resolution",
                HealthStatus.PASS,
                f"Host resolves to {ip}",
                {"ip_address": ip},
                duration
            )
        except socket.gaierror as e:
            self._add_result(
                "DNS Resolution",
                HealthStatus.FAIL,
                f"Failed to resolve hostname: {e}",
                {"error": str(e)}
            )
    
    def test_network_connectivity(self):
        """Test basic network connectivity"""
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            result = sock.connect_ex((self.config.host, self.config.port))
            duration = (time.time() - start) * 1000
            sock.close()
            
            if result == 0:
                self._add_result(
                    "Network Connectivity",
                    HealthStatus.PASS,
                    f"Port {self.config.port} is reachable",
                    {"port": self.config.port, "latency_ms": duration},
                    duration
                )
            else:
                self._add_result(
                    "Network Connectivity",
                    HealthStatus.FAIL,
                    f"Port {self.config.port} is not reachable",
                    {"port": self.config.port, "error_code": result}
                )
        except Exception as e:
            self._add_result(
                "Network Connectivity",
                HealthStatus.FAIL,
                f"Connection failed: {e}",
                {"error": str(e)}
            )
    
    def test_ssl_certificate(self):
        """Test SSL certificate validity"""
        if not self.config.use_ssl:
            self._add_result(
                "SSL Certificate",
                HealthStatus.SKIP,
                "SSL not enabled"
            )
            return
        
        try:
            import ssl
            context = ssl.create_default_context()
            
            start = time.time()
            with socket.create_connection((self.config.host, self.config.port), 
                                         timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.config.host) as ssock:
                    cert = ssock.getpeercert()
                    duration = (time.time() - start) * 1000
                    
                    # Check certificate expiry
                    not_after = cert.get('notAfter')
                    self._add_result(
                        "SSL Certificate",
                        HealthStatus.PASS,
                        "SSL certificate is valid",
                        {
                            "subject": dict(x[0] for x in cert['subject']),
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "expires": not_after
                        },
                        duration
                    )
        except ssl.SSLError as e:
            self._add_result(
                "SSL Certificate",
                HealthStatus.FAIL,
                f"SSL error: {e}",
                {"error": str(e)}
            )
        except Exception as e:
            self._add_result(
                "SSL Certificate",
                HealthStatus.FAIL,
                f"Certificate check failed: {e}",
                {"error": str(e)}
            )
    
    def test_authentication(self):
        """Test authentication - override in subclass"""
        self._add_result(
            "Authentication",
            HealthStatus.SKIP,
            "Not implemented for base class"
        )
    
    def test_api_reachability(self):
        """Test API endpoint reachability - override in subclass"""
        self._add_result(
            "API Reachability",
            HealthStatus.SKIP,
            "Not implemented for base class"
        )
    
    def test_data_pull(self):
        """Test data retrieval - override in subclass"""
        self._add_result(
            "Data Pull",
            HealthStatus.SKIP,
            "Not implemented for base class"
        )
    
    def test_rate_limits(self):
        """Test rate limiting - override in subclass"""
        self._add_result(
            "Rate Limits",
            HealthStatus.SKIP,
            "Not implemented for base class"
        )


# ============================================================================
# Specific Integration Checkers
# ============================================================================

class ActiveDirectoryChecker(IntegrationHealthChecker):
    """Active Directory LDAP integration health checker"""
    
    def test_authentication(self):
        """Test LDAP bind"""
        try:
            import ldap3
            
            start = time.time()
            server = ldap3.Server(
                self.config.host,
                port=self.config.port,
                use_ssl=self.config.use_ssl,
                get_info=ldap3.ALL
            )
            
            conn = ldap3.Connection(
                server,
                user=f"{self.config.domain}\\{self.config.username}",
                password=self.config.password,
                auto_bind=True
            )
            duration = (time.time() - start) * 1000
            
            if conn.bound:
                self._add_result(
                    "Authentication",
                    HealthStatus.PASS,
                    "LDAP bind successful",
                    {"bind_dn": conn.extend.standard.who_am_i()},
                    duration
                )
                conn.unbind()
            else:
                self._add_result(
                    "Authentication",
                    HealthStatus.FAIL,
                    "LDAP bind failed"
                )
        except Exception as e:
            self._add_result(
                "Authentication",
                HealthStatus.FAIL,
                f"LDAP authentication failed: {e}",
                {"error": str(e)}
            )
    
    def test_data_pull(self):
        """Test LDAP query"""
        try:
            import ldap3
            
            server = ldap3.Server(self.config.host, port=self.config.port, 
                                 use_ssl=self.config.use_ssl)
            conn = ldap3.Connection(server, 
                                   user=f"{self.config.domain}\\{self.config.username}",
                                   password=self.config.password, 
                                   auto_bind=True)
            
            start = time.time()
            search_base = f"DC={self.config.domain.replace('.', ',DC=')}"
            conn.search(search_base, '(objectClass=computer)', 
                       attributes=['cn'], size_limit=10)
            duration = (time.time() - start) * 1000
            
            count = len(conn.entries)
            self._add_result(
                "Data Pull",
                HealthStatus.PASS,
                f"Retrieved {count} computer objects",
                {"count": count, "sample": str(conn.entries[0]) if count > 0 else None},
                duration
            )
            conn.unbind()
            
        except Exception as e:
            self._add_result(
                "Data Pull",
                HealthStatus.FAIL,
                f"LDAP query failed: {e}",
                {"error": str(e)}
            )


class CrowdStrikeChecker(IntegrationHealthChecker):
    """CrowdStrike Falcon API health checker"""
    
    def test_authentication(self):
        """Test OAuth2 authentication"""
        try:
            start = time.time()
            url = f"https://{self.config.host}/oauth2/token"
            
            response = requests.post(
                url,
                data={
                    'client_id': self.config.username,
                    'client_secret': self.config.password
                },
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
            duration = (time.time() - start) * 1000
            
            if response.status_code == 201:
                token_data = response.json()
                self._add_result(
                    "Authentication",
                    HealthStatus.PASS,
                    "OAuth2 authentication successful",
                    {"expires_in": token_data.get('expires_in')},
                    duration
                )
            else:
                self._add_result(
                    "Authentication",
                    HealthStatus.FAIL,
                    f"OAuth2 failed: {response.status_code}",
                    {"status_code": response.status_code, "body": response.text[:200]}
                )
        except Exception as e:
            self._add_result(
                "Authentication",
                HealthStatus.FAIL,
                f"Authentication error: {e}",
                {"error": str(e)}
            )
    
    def test_api_reachability(self):
        """Test CrowdStrike API endpoints"""
        try:
            # Get token first
            token_url = f"https://{self.config.host}/oauth2/token"
            token_resp = requests.post(
                token_url,
                data={'client_id': self.config.username, 
                      'client_secret': self.config.password},
                timeout=self.config.timeout
            )
            
            if token_resp.status_code != 201:
                self._add_result(
                    "API Reachability",
                    HealthStatus.FAIL,
                    "Cannot get token for API test"
                )
                return
            
            token = token_resp.json()['access_token']
            
            # Test devices API
            start = time.time()
            devices_url = f"https://{self.config.host}/devices/queries/devices/v1?limit=1"
            headers = {'Authorization': f'Bearer {token}'}
            
            response = requests.get(devices_url, headers=headers, 
                                   timeout=self.config.timeout)
            duration = (time.time() - start) * 1000
            
            if response.status_code == 200:
                self._add_result(
                    "API Reachability",
                    HealthStatus.PASS,
                    "Devices API endpoint reachable",
                    {"status_code": 200},
                    duration
                )
            else:
                self._add_result(
                    "API Reachability",
                    HealthStatus.FAIL,
                    f"API returned {response.status_code}",
                    {"status_code": response.status_code}
                )
        except Exception as e:
            self._add_result(
                "API Reachability",
                HealthStatus.FAIL,
                f"API test failed: {e}",
                {"error": str(e)}
            )


class IntuneChecker(IntegrationHealthChecker):
    """Microsoft Intune Graph API health checker"""
    
    def test_authentication(self):
        """Test Azure AD OAuth2 authentication"""
        try:
            start = time.time()
            url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
            
            response = requests.post(
                url,
                data={
                    'grant_type': 'client_credentials',
                    'client_id': self.config.username,
                    'client_secret': self.config.password,
                    'scope': 'https://graph.microsoft.com/.default'
                },
                timeout=self.config.timeout
            )
            duration = (time.time() - start) * 1000
            
            if response.status_code == 200:
                token_data = response.json()
                self._add_result(
                    "Authentication",
                    HealthStatus.PASS,
                    "Azure AD authentication successful",
                    {"expires_in": token_data.get('expires_in')},
                    duration
                )
            else:
                self._add_result(
                    "Authentication",
                    HealthStatus.FAIL,
                    f"Azure AD auth failed: {response.status_code}",
                    {"error": response.text[:200]}
                )
        except Exception as e:
            self._add_result(
                "Authentication",
                HealthStatus.FAIL,
                f"Authentication error: {e}",
                {"error": str(e)}
            )
    
    def test_api_reachability(self):
        """Test Microsoft Graph API"""
        try:
            # Get token
            token_url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
            token_resp = requests.post(
                token_url,
                data={
                    'grant_type': 'client_credentials',
                    'client_id': self.config.username,
                    'client_secret': self.config.password,
                    'scope': 'https://graph.microsoft.com/.default'
                }
            )
            
            if token_resp.status_code != 200:
                self._add_result("API Reachability", HealthStatus.FAIL, 
                               "Cannot get token")
                return
            
            token = token_resp.json()['access_token']
            
            # Test Graph API
            start = time.time()
            graph_url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1"
            headers = {'Authorization': f'Bearer {token}'}
            
            response = requests.get(graph_url, headers=headers, 
                                   timeout=self.config.timeout)
            duration = (time.time() - start) * 1000
            
            if response.status_code == 200:
                self._add_result(
                    "API Reachability",
                    HealthStatus.PASS,
                    "Graph API reachable",
                    {"status_code": 200},
                    duration
                )
            else:
                self._add_result(
                    "API Reachability",
                    HealthStatus.WARN if response.status_code == 403 else HealthStatus.FAIL,
                    f"Graph API returned {response.status_code}",
                    {"status_code": response.status_code, 
                     "hint": "403 may indicate missing permissions"}
                )
        except Exception as e:
            self._add_result(
                "API Reachability",
                HealthStatus.FAIL,
                f"API test failed: {e}",
                {"error": str(e)}
            )


class VMwareChecker(IntegrationHealthChecker):
    """VMware vSphere API health checker"""
    
    def test_authentication(self):
        """Test vSphere authentication"""
        try:
            start = time.time()
            url = f"https://{self.config.host}/rest/com/vmware/cis/session"
            
            response = requests.post(
                url,
                auth=HTTPBasicAuth(self.config.username, self.config.password),
                verify=self.config.verify_ssl,
                timeout=self.config.timeout
            )
            duration = (time.time() - start) * 1000
            
            if response.status_code == 200:
                self._add_result(
                    "Authentication",
                    HealthStatus.PASS,
                    "vSphere authentication successful",
                    {"session_id": response.json().get('value')[:20] + "..."},
                    duration
                )
            else:
                self._add_result(
                    "Authentication",
                    HealthStatus.FAIL,
                    f"vSphere auth failed: {response.status_code}",
                    {"status_code": response.status_code}
                )
        except Exception as e:
            self._add_result(
                "Authentication",
                HealthStatus.FAIL,
                f"Authentication error: {e}",
                {"error": str(e)}
            )


# ============================================================================
# Diagnostic Runner
# ============================================================================

class DiagnosticRunner:
    """Orchestrates diagnostic tests"""
    
    CHECKER_MAP = {
        IntegrationType.ACTIVE_DIRECTORY: ActiveDirectoryChecker,
        IntegrationType.CROWDSTRIKE: CrowdStrikeChecker,
        IntegrationType.INTUNE: IntuneChecker,
        IntegrationType.VMWARE_VSPHERE: VMwareChecker,
    }
    
    def __init__(self):
        self.jump_manager = JumpServerManager()
    
    def run_diagnostics(self, customer: str, environment: str,
                       config: IntegrationConfig) -> DiagnosticReport:
        """Run full diagnostic suite"""
        
        # Get appropriate checker
        checker_class = self.CHECKER_MAP.get(
            config.integration_type,
            IntegrationHealthChecker
        )
        
        checker = checker_class(config)
        tests = checker.run_all_tests()
        
        # Determine overall status
        has_fail = any(t.status == HealthStatus.FAIL for t in tests)
        has_warn = any(t.status == HealthStatus.WARN for t in tests)
        
        if has_fail:
            overall = HealthStatus.FAIL
        elif has_warn:
            overall = HealthStatus.WARN
        else:
            overall = HealthStatus.PASS
        
        # Generate recommendations
        recommendations = self._generate_recommendations(tests, config)
        
        report = DiagnosticReport(
            customer=customer,
            environment=environment,
            integration_type=config.integration_type,
            timestamp=datetime.utcnow().isoformat(),
            tests=tests,
            overall_status=overall,
            recommendations=recommendations
        )
        
        return report
    
    def _generate_recommendations(self, tests: List[TestResult], 
                                 config: IntegrationConfig) -> List[str]:
        """Generate troubleshooting recommendations"""
        recommendations = []
        
        for test in tests:
            if test.status == HealthStatus.FAIL:
                if test.test_name == "DNS Resolution":
                    recommendations.append(
                        "DNS Resolution Failed: Check /etc/resolv.conf on the ORDR instance. "
                        "Verify customer's DNS servers are reachable and have records for the integration host."
                    )
                elif test.test_name == "Network Connectivity":
                    recommendations.append(
                        f"Network Connectivity Failed: Port {config.port} is not reachable. "
                        "Check firewall rules between ORDR instance and integration host. "
                        "Verify routing and that the integration service is running."
                    )
                elif test.test_name == "SSL Certificate":
                    recommendations.append(
                        "SSL Certificate Failed: Certificate may be expired, self-signed, or hostname mismatch. "
                        "Consider using verify_ssl=False for testing (not recommended for production)."
                    )
                elif test.test_name == "Authentication":
                    recommendations.append(
                        "Authentication Failed: Verify credentials are correct and not expired. "
                        "Check account permissions and whether MFA is required. "
                        "Review integration logs for detailed error messages."
                    )
                elif test.test_name == "API Reachability":
                    recommendations.append(
                        "API Reachability Failed: Authentication may have succeeded but API endpoint is unreachable. "
                        "Check API version compatibility and ensure required API endpoints are enabled."
                    )
        
        if not recommendations:
            recommendations.append("All tests passed! Integration appears healthy.")
        
        return recommendations
    
    def print_report(self, report: DiagnosticReport):
        """Print formatted diagnostic report"""
        print("\n" + "="*80)
        print(f"INTEGRATION HEALTH DIAGNOSTIC REPORT")
        print("="*80)
        print(f"Customer:     {report.customer}")
        print(f"Environment:  {report.environment}")
        print(f"Integration:  {report.integration_type.value}")
        print(f"Timestamp:    {report.timestamp}")
        print(f"Overall:      {report.overall_status.value}")
        print("="*80)
        print()
        
        print("TEST RESULTS:")
        print("-" * 80)
        for test in report.tests:
            duration_str = f" ({test.duration_ms:.0f}ms)" if test.duration_ms else ""
            print(f"{test.status.value:8} {test.test_name:25} {test.message}{duration_str}")
            if test.details and test.status in (HealthStatus.FAIL, HealthStatus.WARN):
                for key, value in test.details.items():
                    print(f"         → {key}: {value}")
        print()
        
        print("RECOMMENDATIONS:")
        print("-" * 80)
        for i, rec in enumerate(report.recommendations, 1):
            print(f"{i}. {rec}")
            print()
        
        print("="*80)
    
    def save_report(self, report: DiagnosticReport, filepath: str):
        """Save report to JSON file"""
        report_dict = {
            'customer': report.customer,
            'environment': report.environment,
            'integration_type': report.integration_type.value,
            'timestamp': report.timestamp,
            'overall_status': report.overall_status.value,
            'tests': [asdict(t) for t in report.tests],
            'recommendations': report.recommendations
        }
        
        # Convert enums to strings
        for test in report_dict['tests']:
            test['status'] = test['status'].value if hasattr(test['status'], 'value') else str(test['status'])
        
        with open(filepath, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        print(f"\n✓ Report saved to: {filepath}")


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ORDR Integration Health Diagnostic Tool"
    )
    
    parser.add_argument('--customer', required=True, help='Customer name')
    parser.add_argument('--env', required=True, 
                       choices=['dc-cloud', 'on-premise'],
                       help='Environment type')
    parser.add_argument('--integration', required=True,
                       choices=['ad', 'crowdstrike', 'intune', 'vmware', 'tenable', 'azure', 'dhcp'],
                       help='Integration type to test')
    parser.add_argument('--host', required=True, help='Integration host/IP')
    parser.add_argument('--port', type=int, help='Port (default varies by integration)')
    parser.add_argument('--username', help='Username/Client ID')
    parser.add_argument('--password', help='Password/Client Secret')
    parser.add_argument('--domain', help='Domain (for AD)')
    parser.add_argument('--tenant-id', help='Tenant ID (for Azure/Intune)')
    parser.add_argument('--no-ssl', action='store_true', help='Disable SSL')
    parser.add_argument('--no-verify', action='store_true', help='Skip SSL verification')
    parser.add_argument('--output', help='Output JSON file path')
    
    args = parser.parse_args()
    
    # Map integration types
    integration_map = {
        'ad': IntegrationType.ACTIVE_DIRECTORY,
        'crowdstrike': IntegrationType.CROWDSTRIKE,
        'intune': IntegrationType.INTUNE,
        'vmware': IntegrationType.VMWARE_VSPHERE,
        'tenable': IntegrationType.TENABLE,
        'azure': IntegrationType.AZURE,
        'dhcp': IntegrationType.DHCP
    }
    
    # Default ports
    port_defaults = {
        'ad': 636,  # LDAPS
        'crowdstrike': 443,
        'intune': 443,
        'vmware': 443,
        'tenable': 443,
        'azure': 443,
        'dhcp': 67
    }
    
    integration_type = integration_map[args.integration]
    port = args.port or port_defaults.get(args.integration, 443)
    
    # Build configuration
    config = IntegrationConfig(
        integration_type=integration_type,
        host=args.host,
        port=port,
        username=args.username,
        password=args.password,
        domain=args.domain,
        tenant_id=args.tenant_id,
        use_ssl=not args.no_ssl,
        verify_ssl=not args.no_verify
    )
    
    # Run diagnostics
    runner = DiagnosticRunner()
    report = runner.run_diagnostics(args.customer, args.env, config)
    
    # Print report
    runner.print_report(report)
    
    # Save if requested
    if args.output:
        runner.save_report(report, args.output)


if __name__ == "__main__":
    main()