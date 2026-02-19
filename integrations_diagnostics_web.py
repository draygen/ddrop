#!/usr/bin/env python3
"""
Web UI for ORDR Integration Diagnostics
Provides an easy-to-use interface for running integration health checks
"""

import os
import json
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

# Import from the main diagnostic tool
# Assumes integration_health_tool.py is in the same directory
from integration_health_tool import (
    IntegrationType, IntegrationConfig, DiagnosticRunner,
    JumpServerManager, HealthStatus
)

load_dotenv()

app = Flask(__name__)

# Store recent test results in memory (in production, use a database)
RECENT_TESTS = []
MAX_RECENT = 50


@app.route("/")
def index():
    """Main dashboard"""
    return render_template("integration_dashboard.html")


@app.route("/api/customers")
def get_customers():
    """Get list of customers from jump server aliases"""
    try:
        jump_manager = JumpServerManager()
        aliases = jump_manager.get_dc_cloud_aliases()
        
        customers = [
            {
                'name': name,
                'host': info['host'],
                'port': info['port'],
                'type': 'dc-cloud'
            }
            for name, info in aliases.items()
        ]
        
        return jsonify({
            'success': True,
            'customers': customers
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route("/api/test", methods=['POST'])
def run_test():
    """Run integration diagnostic test"""
    try:
        data = request.json
        
        # Parse integration type
        integration_map = {
            'ad': IntegrationType.ACTIVE_DIRECTORY,
            'crowdstrike': IntegrationType.CROWDSTRIKE,
            'intune': IntegrationType.INTUNE,
            'vmware': IntegrationType.VMWARE_VSPHERE,
            'tenable': IntegrationType.TENABLE,
            'azure': IntegrationType.AZURE,
            'dhcp': IntegrationType.DHCP
        }
        
        integration_type = integration_map.get(data.get('integration_type'))
        if not integration_type:
            return jsonify({
                'success': False,
                'error': 'Invalid integration type'
            }), 400
        
        # Build configuration
        config = IntegrationConfig(
            integration_type=integration_type,
            host=data.get('host'),
            port=int(data.get('port', 443)),
            username=data.get('username'),
            password=data.get('password'),
            domain=data.get('domain'),
            tenant_id=data.get('tenant_id'),
            use_ssl=data.get('use_ssl', True),
            verify_ssl=data.get('verify_ssl', True),
            timeout=int(data.get('timeout', 30))
        )
        
        # Run diagnostics
        runner = DiagnosticRunner()
        report = runner.run_diagnostics(
            customer=data.get('customer', 'Unknown'),
            environment=data.get('environment', 'unknown'),
            config=config
        )
        
        # Convert to dict for JSON serialization
        report_dict = {
            'customer': report.customer,
            'environment': report.environment,
            'integration_type': report.integration_type.value,
            'timestamp': report.timestamp,
            'overall_status': report.overall_status.value,
            'tests': [
                {
                    'test_name': t.test_name,
                    'status': t.status.value,
                    'message': t.message,
                    'details': t.details,
                    'duration_ms': t.duration_ms,
                    'timestamp': t.timestamp
                }
                for t in report.tests
            ],
            'recommendations': report.recommendations
        }
        
        # Store in recent tests
        RECENT_TESTS.insert(0, report_dict)
        if len(RECENT_TESTS) > MAX_RECENT:
            RECENT_TESTS.pop()
        
        return jsonify({
            'success': True,
            'report': report_dict
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route("/api/recent")
def get_recent_tests():
    """Get recent test results"""
    return jsonify({
        'success': True,
        'tests': RECENT_TESTS[:20]  # Return last 20
    })


@app.route("/api/export/<int:test_id>")
def export_test(test_id):
    """Export a test result as JSON"""
    if test_id < len(RECENT_TESTS):
        report = RECENT_TESTS[test_id]
        filename = f"diagnostic_{report['customer']}_{report['timestamp'][:10]}.json"
        
        from flask import Response
        return Response(
            json.dumps(report, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment;filename={filename}'}
        )
    return jsonify({'error': 'Test not found'}), 404


@app.route("/health")
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=True)