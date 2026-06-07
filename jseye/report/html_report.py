"""HTML report generation for JSEye results."""

import os
from datetime import datetime
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape
from ..version import __version__


class HTMLReportGenerator:
    """Generate HTML reports from scan results."""
    
    def __init__(self):
        self.report_version = "1.0"
        self._setup_jinja()
    
    def _setup_jinja(self):
        """Set up Jinja2 environment."""
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    def generate_report(self, scan_results: Dict[str, Any], output_file: str = None) -> str:
        """Generate a comprehensive HTML report."""
        try:
            template = self.env.get_template('report.html')
            
            # Prepare template data
            template_data = self._prepare_template_data(scan_results)
            
            # Render HTML
            html_content = template.render(**template_data)
            
            # Save to file if specified
            if output_file:
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                except Exception as e:
                    raise Exception(f"Failed to write HTML report: {str(e)}")
            
            return html_content
            
        except Exception as e:
            # Fallback to basic HTML if template fails
            html_content = self._generate_basic_html(scan_results, str(e))
            # Still write to file if requested
            if output_file:
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                except Exception:
                    pass
            return html_content

    def generate(self, scan_results: Dict[str, Any], output_file: str = None) -> str:
        """Alias for generate_report() for backward compatibility."""
        return self.generate_report(scan_results, output_file)

    def _normalize_statistics(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure all statistics keys the template expects are always present."""
        # Build a fully-normalized copy so Jinja2 attribute access never crashes
        risk_dist = stats.get('risk_distribution', {})
        if not isinstance(risk_dist, dict):
            risk_dist = {}

        normalized = {
            'total_js_files': stats.get('total_js_files', 0),
            'total_secrets': stats.get('total_secrets', 0),
            'total_endpoints': stats.get('total_endpoints', 0),
            'total_apis_analyzed': stats.get('total_apis_analyzed', 0),
            'total_errors': stats.get('total_errors', 0),
            'total_js_size': stats.get('total_js_size', 0),
            'average_file_size': stats.get('average_file_size', 0),
            'risk_distribution': {
                'Critical': risk_dist.get('Critical', 0),
                'High': risk_dist.get('High', 0),
                'Medium': risk_dist.get('Medium', 0),
                'Low': risk_dist.get('Low', 0),
            },
            # secret_types: build from the secrets list if the engine didn't produce it
            'secret_types': stats.get('secret_types', {}),
            # file_sources: build from js_files if the engine didn't produce it
            'file_sources': stats.get('file_sources', {}),
        }
        return normalized

    def _prepare_template_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for the HTML template."""
        raw_stats = scan_results.get('statistics', {})

        # If secret_types is missing, derive it from the secrets list
        if 'secret_types' not in raw_stats:
            secret_types: Dict[str, int] = {}
            for s in scan_results.get('secrets', []):
                stype = s.get('type', 'unknown')
                secret_types[stype] = secret_types.get(stype, 0) + 1
            raw_stats = dict(raw_stats)  # shallow copy so we don't mutate caller's data
            raw_stats['secret_types'] = secret_types

        # If file_sources is missing, derive it from js_files
        if 'file_sources' not in raw_stats:
            file_sources: Dict[str, int] = {}
            for f in scan_results.get('js_files', []):
                src = f.get('source', 'direct')
                file_sources[src] = file_sources.get(src, 0) + 1
            raw_stats['file_sources'] = file_sources

        # Fully normalize so every key the template touches exists
        stats = self._normalize_statistics(raw_stats)

        # Calculate summary data
        summary = self._calculate_summary(scan_results)

        # Process secrets for display
        secrets = self._process_secrets_for_display(scan_results.get('secrets', []))

        # Process API analysis
        api_analysis = self._process_api_analysis_for_display(scan_results.get('api_analysis', []))

        # Process JavaScript files
        js_files = self._process_js_files_for_display(scan_results.get('js_files', []))

        # --- Fix 9: Full detected library/version list (no display cap) ---
        version_analysis = scan_results.get('version_analysis', {})
        if not isinstance(version_analysis, dict):
            version_analysis = {}

        # Normalise: ensure the keys the template uses always exist
        version_analysis.setdefault('total_libraries', 0)
        version_analysis.setdefault('unique_libraries', [])
        version_analysis.setdefault('by_library', {})

        # --- Fix 5: API documentation URLs ---
        api_documentation = scan_results.get('api_documentation', [])
        if not isinstance(api_documentation, list):
            api_documentation = []

        # --- Fix 6: Swagger / OpenAPI specs and endpoints ---
        swagger_specs = scan_results.get('swagger_specs', [])
        if not isinstance(swagger_specs, list):
            swagger_specs = []
        swagger_endpoints = scan_results.get('swagger_endpoints', [])
        if not isinstance(swagger_endpoints, list):
            swagger_endpoints = []

        # --- Fix 7: CVE lookup results ---
        cve_results = scan_results.get('cve_results', {})
        if not isinstance(cve_results, dict):
            cve_results = {}
        # Ensure all keys the template accesses are present
        cve_results.setdefault('total_cves', 0)
        cve_results.setdefault('critical', 0)
        cve_results.setdefault('high', 0)
        cve_results.setdefault('medium', 0)
        cve_results.setdefault('low', 0)
        cve_results.setdefault('vulnerabilities', [])

        template_data = {
            'target': scan_results.get('target', 'Unknown'),
            'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'jseye_version': __version__,
            'report_version': self.report_version,
            'summary': summary,
            'statistics': stats,
            'secrets': secrets,
            'api_analysis': api_analysis,
            'javascript_files': js_files,
            'endpoints': scan_results.get('endpoints', []),
            'vulnerabilities': scan_results.get('vulnerabilities', []),
            'errors': scan_results.get('errors', []),
            # Newly surfaced data
            'api_documentation': api_documentation,      # Fix 5
            'swagger_specs': swagger_specs,               # Fix 6
            'swagger_endpoints': swagger_endpoints,       # Fix 6
            'cve_results': cve_results,                   # Fix 7
            'version_analysis': version_analysis,         # Fix 9
        }

        return template_data
    
    def _calculate_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate summary statistics."""
        stats = scan_results.get('statistics', {})

        # Calculate risk score — capped at 100 to remain meaningful
        risk_distribution = stats.get('risk_distribution', {})
        if not isinstance(risk_distribution, dict):
            risk_distribution = {}
        raw_score = (
            risk_distribution.get('Critical', 0) * 25 +
            risk_distribution.get('High', 0) * 15 +
            risk_distribution.get('Medium', 0) * 8 +
            risk_distribution.get('Low', 0) * 3
        )
        risk_score = min(raw_score, 100)

        # Determine overall risk level
        if risk_score >= 80:
            overall_risk = 'Critical'
        elif risk_score >= 50:
            overall_risk = 'High'
        elif risk_score >= 20:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'

        return {
            'total_js_files': stats.get('total_js_files', 0),
            'total_secrets_found': stats.get('total_secrets', 0),
            'total_endpoints_discovered': stats.get('total_endpoints', 0),
            'total_apis_analyzed': stats.get('total_apis_analyzed', 0),
            'total_vulnerabilities': len(scan_results.get('vulnerabilities', [])),
            'risk_score': risk_score,
            'overall_risk_level': overall_risk,
            'file_size_analyzed_mb': round(stats.get('total_js_size', 0) / (1024 * 1024), 2),
            'scan_errors': stats.get('total_errors', 0)
        }
    
    def _process_secrets_for_display(self, secrets: list) -> list:
        """Process secrets for HTML display."""
        processed_secrets = []

        for secret in secrets:
            # Ensure all required fields exist
            processed_secret = {
                'type': secret.get('type', 'unknown'),
                'description': secret.get('description', 'Unknown secret type'),
                'value_masked': secret.get('value_masked', '***'),
                'severity': secret.get('severity', 'low'),
                'confidence': secret.get('confidence', 0),
                'risk_score': secret.get('risk_score', 0),
                'risk_level': secret.get('risk_level', 'Low'),
                'risk_factors': secret.get('risk_factors', []),
                'source_file': secret.get('source_file', 'Unknown'),
                'context': secret.get('context', '')[:200] + '...' if len(secret.get('context', '')) > 200 else secret.get('context', ''),
                'detection_method': secret.get('detection_method', 'unknown'),
                'remediation': secret.get('remediation', 'No remediation advice available'),
                'entropy': secret.get('entropy'),
                # Fix 10: surface which tool detected this secret (mantra vs built-in)
                'detection_tool': secret.get('tool', 'jseye'),
            }

            processed_secrets.append(processed_secret)

        return processed_secrets
    
    def _process_api_analysis_for_display(self, api_analysis: list) -> list:
        """Process API analysis for HTML display."""
        processed_apis = []
        
        for api in api_analysis:
            if not isinstance(api, dict):
                continue
            
            processed_api = {
                'url': api.get('url', ''),
                'api_type': api.get('api_type', 'unknown'),
                'methods_supported': list(api.get('methods', {}).keys()),
                'authentication_required': self._check_auth_required(api),
                'cors_enabled': api.get('cors_config', {}).get('enabled', False),
                'cors_vulnerabilities': api.get('cors_config', {}).get('vulnerabilities', []),
                'security_headers': api.get('security_headers', {}),
                'vulnerabilities': api.get('vulnerabilities', []),
                'parameters': api.get('parameters', [])[:10],  # Limit for display
                'response_codes': self._extract_response_codes(api)
            }
            
            processed_apis.append(processed_api)
        
        return processed_apis
    
    def _process_js_files_for_display(self, js_files: list) -> list:
        """Process JavaScript files for HTML display."""
        processed_files = []
        
        for js_file in js_files:
            processed_file = {
                'url': js_file.get('url', ''),
                'size_bytes': js_file.get('size', 0),
                'type': js_file.get('type', 'unknown'),
                'source': js_file.get('source', 'direct'),
                'hash': js_file.get('hash', ''),
                'source_map': js_file.get('source_map')
            }
            
            processed_files.append(processed_file)
        
        return processed_files
    
    def _check_auth_required(self, api: Dict[str, Any]) -> bool:
        """Check if API requires authentication."""
        methods = api.get('methods', {})
        
        for method_data in methods.values():
            if isinstance(method_data, dict):
                status_code = method_data.get('status_code', 0)
                if status_code in [401, 403]:
                    return True
        
        return False
    
    def _extract_response_codes(self, api: Dict[str, Any]) -> Dict[str, int]:
        """Extract response codes from API analysis."""
        response_codes = {}
        methods = api.get('methods', {})
        
        for method, method_data in methods.items():
            if isinstance(method_data, dict):
                status_code = method_data.get('status_code', 0)
                if status_code:
                    response_codes[method] = status_code
        
        return response_codes
    
    def _generate_basic_html(self, scan_results: Dict[str, Any], error_msg: str = "") -> str:
        """Generate a basic HTML report as fallback."""
        target = scan_results.get('target', 'Unknown')
        stats = scan_results.get('statistics', {})
        secrets = scan_results.get('secrets', [])
        endpoints = scan_results.get('endpoints', [])
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>JSEye Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #333; color: white; padding: 20px; text-align: center; }}
        .section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; }}
        .critical {{ color: #e74c3c; }}
        .high {{ color: #f39c12; }}
        .medium {{ color: #f1c40f; }}
        .low {{ color: #27ae60; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
        th {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>JSEye Security Report</h1>
        <p>Target: {target}</p>
        <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    
    {f'<div class="section"><h2>Template Error</h2><p>{error_msg}</p></div>' if error_msg else ''}
    
    <div class="section">
        <h2>Summary</h2>
        <p>JavaScript Files: {stats.get('total_js_files', 0)}</p>
        <p>Secrets Found: {stats.get('total_secrets', 0)}</p>
        <p>Endpoints: {stats.get('total_endpoints', 0)}</p>
        <p>File Size: {round(stats.get('total_js_size', 0) / (1024 * 1024), 2)} MB</p>
    </div>
    
    <div class="section">
        <h2>Secrets</h2>
        <table>
            <tr><th>Type</th><th>Risk Level</th><th>Source</th><th>Value (Masked)</th></tr>
        """
        
        for secret in secrets:  # Show all secrets — no artificial cap
            risk_level = secret.get('risk_level', 'Low')
            source = secret.get('source_file', 'Unknown')
            source_display = source[:80] + '...' if len(source) > 80 else source
            html += f"""
            <tr>
                <td>{secret.get('description', 'Unknown')}</td>
                <td class="{risk_level.lower()}">{risk_level}</td>
                <td>{source_display}</td>
                <td><code>{secret.get('value_masked', '***')}</code></td>
            </tr>
            """
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>Endpoints</h2>
        <ul>
        """
        
        for endpoint in endpoints:  # Show all endpoints — no artificial cap
            html += f"<li>{endpoint}</li>"
        
        html += """
        </ul>
    </div>
    
    <div class="section">
        <p><em>Generated by JSEye (Modified by H3RM!T) - JavaScript Intelligence & Attack Surface Discovery Engine</em></p>
    </div>
</body>
</html>
        """
        
        return html
    
    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """Generate an executive summary HTML report."""
        target = scan_results.get('target', 'Unknown')
        summary = self._calculate_summary(scan_results)
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Get critical findings
        critical_secrets = [s for s in scan_results.get('secrets', []) if s.get('risk_level') == 'Critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']]
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>JSEye Executive Summary - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        .number {{ font-size: 2em; font-weight: bold; margin: 10px 0; }}
        .critical {{ color: #e74c3c; }}
        .high {{ color: #f39c12; }}
        .medium {{ color: #f1c40f; }}
        .low {{ color: #27ae60; }}
        .section {{ margin: 30px 0; padding: 20px; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .risk-indicator {{ padding: 10px; border-radius: 5px; margin: 10px 0; }}
        .risk-critical {{ background: #ffe6e6; border-left: 5px solid #e74c3c; }}
        .risk-high {{ background: #fff3e0; border-left: 5px solid #f39c12; }}
        .risk-medium {{ background: #fffbf0; border-left: 5px solid #f1c40f; }}
        .risk-low {{ background: #f0fff4; border-left: 5px solid #27ae60; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>[*] JSEye Executive Summary</h1>
        <h2>{target}</h2>
        <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    
    <div class="summary-grid">
        <div class="summary-card">
            <div class="number {summary['overall_risk_level'].lower()}">{summary['risk_score']}</div>
            <div>Risk Score</div>
            <div><strong>{summary['overall_risk_level']} Risk</strong></div>
        </div>
        <div class="summary-card">
            <div class="number critical">{len(critical_secrets)}</div>
            <div>Critical Secrets</div>
        </div>
        <div class="summary-card">
            <div class="number high">{len(high_vulns)}</div>
            <div>High-Risk Vulnerabilities</div>
        </div>
        <div class="summary-card">
            <div class="number">{summary['total_js_files']}</div>
            <div>JS Files Analyzed</div>
        </div>
    </div>
    
    <div class="section">
        <h2>[*] Key Findings</h2>
        """
        
        if critical_secrets:
            html += f"""
        <div class="risk-indicator risk-critical">
            <strong>Critical Secret Exposure:</strong> Found {len(critical_secrets)} critical secrets that could provide unauthorized access to systems or data.
        </div>
        """
        
        if high_vulns:
            html += f"""
        <div class="risk-indicator risk-high">
            <strong>High-Risk Vulnerabilities:</strong> Identified {len(high_vulns)} high-severity security issues requiring immediate attention.
        </div>
        """
        
        if summary['total_endpoints_discovered'] > 0:
            html += f"""
        <div class="risk-indicator risk-medium">
            <strong>API Surface Exposure:</strong> Discovered {summary['total_endpoints_discovered']} API endpoints that expand the attack surface.
        </div>
        """
        
        html += """
    </div>
    
    <div class="section">
        <h2>[*] Recommendations</h2>
        <ol>
        """
        
        if critical_secrets:
            html += "<li><strong>Immediate Action Required:</strong> Rotate all exposed credentials and implement proper secret management.</li>"
        
        if high_vulns:
            html += "<li><strong>Security Remediation:</strong> Address high-severity vulnerabilities to reduce attack surface.</li>"
        
        html += """
            <li><strong>Code Review:</strong> Implement regular security code reviews for JavaScript files.</li>
            <li><strong>Secret Scanning:</strong> Integrate automated secret scanning into CI/CD pipeline.</li>
            <li><strong>API Security:</strong> Review and secure all discovered API endpoints.</li>
        </ol>
    </div>
    
    <div class="section">
        <p><em>This executive summary provides a high-level overview. Refer to the detailed report for complete findings and remediation guidance. (Modified by H3RM!T)</em></p>
    </div>
</body>
</html>
        """
        
        return html