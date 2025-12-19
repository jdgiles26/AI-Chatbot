"""
Security Reporter for Mac Mini M2
Generates comprehensive security reports in multiple formats.
"""

import json
from datetime import datetime
from typing import Dict
from pathlib import Path


class SecurityReporter:
    """Generates detailed security reports from analysis results."""
    
    def __init__(self):
        pass
    
    def generate_report(self, scan_results: Dict, analysis_results: Dict, 
                       output_file: str, format: str = 'json'):
        """
        Generate a comprehensive security report.
        
        Args:
            scan_results: Results from file system scan
            analysis_results: Results from security analysis
            output_file: Path to output file
            format: Report format (json, html, pdf)
        """
        if format == 'json':
            self._generate_json_report(scan_results, analysis_results, output_file)
        elif format == 'html':
            self._generate_html_report(scan_results, analysis_results, output_file)
        elif format == 'pdf':
            # PDF generation would require additional libraries
            # For now, generate HTML and suggest conversion
            html_file = output_file.replace('.pdf', '.html')
            self._generate_html_report(scan_results, analysis_results, html_file)
            print(f"[*] HTML report generated: {html_file}")
            print("[*] Convert to PDF using: wkhtmltopdf or browser print function")
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json_report(self, scan_results: Dict, analysis_results: Dict, output_file: str):
        """Generate JSON format report."""
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'format': 'json',
                'version': '1.0'
            },
            'scan_summary': {
                'scan_time': scan_results.get('scan_time'),
                'start_path': scan_results.get('start_path'),
                'platform': scan_results.get('platform'),
                'is_mac_m2': scan_results.get('is_mac_m2'),
                'total_files': scan_results.get('total_files', 0),
                'total_directories': scan_results.get('total_dirs', 0),
                'total_size': scan_results.get('total_size', 0),
                'scan_duration': scan_results.get('scan_duration', 0)
            },
            'security_summary': {
                'total_issues': analysis_results.get('total_issues', 0),
                'critical': analysis_results.get('critical', 0),
                'high': analysis_results.get('high', 0),
                'medium': analysis_results.get('medium', 0),
                'low': analysis_results.get('low', 0)
            },
            'findings': analysis_results.get('findings', []),
            'recommendations': analysis_results.get('recommendations', []),
            'detailed_scan_results': {
                'suspicious_files': scan_results.get('suspicious_files', []),
                'symlinks': scan_results.get('symlinks', [])
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    def _generate_html_report(self, scan_results: Dict, analysis_results: Dict, output_file: str):
        """Generate HTML format report."""
        html = self._generate_html_template(scan_results, analysis_results)
        
        with open(output_file, 'w') as f:
            f.write(html)
    
    def _generate_html_template(self, scan_results: Dict, analysis_results: Dict) -> str:
        """Generate HTML template for the report."""
        # Get summary data
        total_issues = analysis_results.get('total_issues', 0)
        critical = analysis_results.get('critical', 0)
        high = analysis_results.get('high', 0)
        medium = analysis_results.get('medium', 0)
        low = analysis_results.get('low', 0)
        
        findings = analysis_results.get('findings', [])
        recommendations = analysis_results.get('recommendations', [])
        
        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - Mac Mini M2</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        header {{
            border-bottom: 3px solid #007aff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        
        h1 {{
            color: #1d1d1f;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            color: #666;
            font-size: 1.1em;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #007aff;
        }}
        
        .summary-card h3 {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #1d1d1f;
        }}
        
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 30px 0;
        }}
        
        .severity-card {{
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .severity-card.critical {{
            background: #ff3b30;
            color: white;
        }}
        
        .severity-card.high {{
            background: #ff9500;
            color: white;
        }}
        
        .severity-card.medium {{
            background: #ffcc00;
            color: #333;
        }}
        
        .severity-card.low {{
            background: #34c759;
            color: white;
        }}
        
        .severity-card .count {{
            font-size: 2em;
            font-weight: bold;
        }}
        
        .severity-card .label {{
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        section {{
            margin: 40px 0;
        }}
        
        h2 {{
            color: #1d1d1f;
            font-size: 1.8em;
            margin-bottom: 20px;
            border-bottom: 2px solid #e5e5e5;
            padding-bottom: 10px;
        }}
        
        .finding {{
            background: #f8f9fa;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #007aff;
        }}
        
        .finding.critical {{
            border-left-color: #ff3b30;
        }}
        
        .finding.high {{
            border-left-color: #ff9500;
        }}
        
        .finding.medium {{
            border-left-color: #ffcc00;
        }}
        
        .finding.low {{
            border-left-color: #34c759;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .finding-title {{
            font-weight: bold;
            font-size: 1.1em;
            color: #1d1d1f;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{
            background: #ff3b30;
            color: white;
        }}
        
        .severity-badge.high {{
            background: #ff9500;
            color: white;
        }}
        
        .severity-badge.medium {{
            background: #ffcc00;
            color: #333;
        }}
        
        .severity-badge.low {{
            background: #34c759;
            color: white;
        }}
        
        .finding-path {{
            font-family: 'Courier New', monospace;
            background: #e5e5e5;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            overflow-x: auto;
            font-size: 0.9em;
        }}
        
        .finding-description {{
            margin: 10px 0;
            color: #333;
        }}
        
        .mitigation {{
            background: #e3f2fd;
            padding: 15px;
            border-radius: 4px;
            margin-top: 10px;
        }}
        
        .mitigation-title {{
            font-weight: bold;
            color: #1976d2;
            margin-bottom: 5px;
        }}
        
        .mitigation code {{
            background: #fff;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        
        .recommendation {{
            background: #e8f5e9;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #4caf50;
        }}
        
        .recommendation.critical {{
            background: #ffebee;
            border-left-color: #f44336;
        }}
        
        .recommendation.high {{
            background: #fff3e0;
            border-left-color: #ff9800;
        }}
        
        .recommendation-title {{
            font-weight: bold;
            font-size: 1.2em;
            color: #1d1d1f;
            margin-bottom: 10px;
        }}
        
        .recommendation ul {{
            margin-left: 20px;
            margin-top: 10px;
        }}
        
        .recommendation li {{
            margin: 5px 0;
        }}
        
        footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #e5e5e5;
            text-align: center;
            color: #666;
        }}
        
        .references {{
            margin-top: 10px;
            font-size: 0.9em;
        }}
        
        .references a {{
            color: #007aff;
            text-decoration: none;
        }}
        
        .references a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Assessment Report</h1>
            <p class="subtitle">Mac Mini M2 Security Analysis</p>
            <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <section>
            <h2>Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Files Scanned</h3>
                    <div class="value">{scan_results.get('total_files', 0):,}</div>
                </div>
                <div class="summary-card">
                    <h3>Directories</h3>
                    <div class="value">{scan_results.get('total_dirs', 0):,}</div>
                </div>
                <div class="summary-card">
                    <h3>Total Size</h3>
                    <div class="value">{self._format_size(scan_results.get('total_size', 0))}</div>
                </div>
                <div class="summary-card">
                    <h3>Scan Duration</h3>
                    <div class="value">{scan_results.get('scan_duration', 0):.1f}s</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>Security Issues</h2>
            <div class="severity-grid">
                <div class="severity-card critical">
                    <div class="count">{critical}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="severity-card high">
                    <div class="count">{high}</div>
                    <div class="label">High</div>
                </div>
                <div class="severity-card medium">
                    <div class="count">{medium}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="severity-card low">
                    <div class="count">{low}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>Detailed Findings</h2>
            {self._generate_findings_html(findings)}
        </section>
        
        <section>
            <h2>Recommendations</h2>
            {self._generate_recommendations_html(recommendations)}
        </section>
        
        <footer>
            <p>This report was generated by Mac Mini M2 Security Assistant</p>
            <p>For questions or support, please consult the documentation</p>
        </footer>
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_findings_html(self, findings: list) -> str:
        """Generate HTML for findings section."""
        if not findings:
            return '<p>No security issues detected.</p>'
        
        html = ''
        for finding in findings:
            severity = finding.get('severity', 'low')
            path = finding.get('path', 'Unknown')
            description = finding.get('description', '')
            mitigation = finding.get('mitigation', '')
            references = finding.get('references', [])
            
            html += f'''
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{finding.get('type', 'Unknown Issue')}</div>
                    <span class="severity-badge {severity}">{severity}</span>
                </div>
                <div class="finding-path">{path}</div>
                <div class="finding-description">{description}</div>
                {f'<div class="mitigation"><div class="mitigation-title">Mitigation:</div>{mitigation}</div>' if mitigation else ''}
                {self._format_references(references) if references else ''}
            </div>
            '''
        
        return html
    
    def _generate_recommendations_html(self, recommendations: list) -> str:
        """Generate HTML for recommendations section."""
        if not recommendations:
            return '<p>No recommendations available.</p>'
        
        html = ''
        for rec in recommendations:
            priority = rec.get('priority', 'general')
            title = rec.get('title', '')
            description = rec.get('description', '')
            actions = rec.get('actions', [])
            
            html += f'''
            <div class="recommendation {priority}">
                <div class="recommendation-title">{title}</div>
                <p>{description}</p>
                {f"<ul>{''.join([f'<li>{action}</li>' for action in actions])}</ul>" if actions else ''}
            </div>
            '''
        
        return html
    
    def _format_references(self, references: list) -> str:
        """Format references as HTML."""
        if not references:
            return ''
        
        html = '<div class="references"><strong>References:</strong><br>'
        for ref in references:
            html += f'<a href="{ref}" target="_blank">{ref}</a><br>'
        html += '</div>'
        return html
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}PB"
