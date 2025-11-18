"""
PDF Report Generator using Jinja2 and WeasyPrint.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from jinja2 import Template


class PDFReporter:
    """Generate executive summary PDF reports."""

    def __init__(self, output_dir: str = "exports"):
        """
        Initialize PDF reporter.

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, results: List[Dict], scores: List[Dict],
                       metadata: Dict = None, filename: str = None) -> str:
        """
        Generate PDF report from results and scores.

        Args:
            results: List of attack results
            scores: List of scored results
            metadata: Additional metadata (models tested, date, etc.)
            filename: Output filename (auto-generated if None)

        Returns:
            Path to generated PDF
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.html"

        # Generate HTML first
        html_path = self.output_dir / filename
        html_content = self._generate_html(results, scores, metadata)

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        # Try to generate PDF using weasyprint
        pdf_path = html_path.with_suffix('.pdf')
        try:
            import weasyprint
            weasyprint.HTML(string=html_content).write_pdf(str(pdf_path))
            return str(pdf_path)
        except ImportError:
            print("Warning: WeasyPrint not available. Returning HTML report instead.")
            return str(html_path)
        except Exception as e:
            print(f"Warning: PDF generation failed ({e}). Returning HTML report instead.")
            return str(html_path)

    def _generate_html(self, results: List[Dict], scores: List[Dict],
                      metadata: Dict = None) -> str:
        """
        Generate HTML report content.

        Args:
            results: Attack results
            scores: Scored results
            metadata: Additional metadata

        Returns:
            HTML content as string
        """
        # Calculate statistics
        stats = self._calculate_statistics(scores)

        # Get template
        template = self._get_html_template()

        # Render template
        html = template.render(
            title="LLM Security Assessment Report",
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            metadata=metadata or {},
            statistics=stats,
            scores=scores,
            vulnerability_details=self._get_vulnerability_details(scores)
        )

        return html

    def _calculate_statistics(self, scores: List[Dict]) -> Dict[str, Any]:
        """
        Calculate report statistics.

        Args:
            scores: Scored results

        Returns:
            Statistics dictionary
        """
        total = len(scores)
        vulnerable = sum(1 for s in scores if s.get('vulnerable', False))
        safe = total - vulnerable

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        vulnerability_types = {}

        for score in scores:
            if not score.get('vulnerable'):
                continue

            # Count severity
            severity = score.get('severity_score', 0)
            if severity >= 0.85:
                severity_counts['critical'] += 1
            elif severity >= 0.6:
                severity_counts['high'] += 1
            elif severity >= 0.3:
                severity_counts['medium'] += 1
            else:
                severity_counts['low'] += 1

            # Count vulnerability types
            for reason in score.get('vulnerability_reasons', []):
                vulnerability_types[reason] = vulnerability_types.get(reason, 0) + 1

        return {
            'total_attacks': total,
            'vulnerable_count': vulnerable,
            'safe_count': safe,
            'vulnerability_rate': f"{(vulnerable / total * 100):.1f}%" if total > 0 else "0%",
            'severity_counts': severity_counts,
            'vulnerability_types': vulnerability_types,
            'average_severity': sum(s.get('severity_score', 0) for s in scores if s.get('vulnerable')) / max(vulnerable, 1)
        }

    def _get_vulnerability_details(self, scores: List[Dict]) -> List[Dict]:
        """
        Get detailed vulnerability information for report.

        Args:
            scores: Scored results

        Returns:
            List of vulnerability details
        """
        vulnerabilities = []

        for score in scores:
            if not score.get('vulnerable'):
                continue

            severity_score = score.get('severity_score', 0)
            if severity_score >= 0.85:
                severity_level = 'CRITICAL'
                severity_color = '#dc3545'
            elif severity_score >= 0.6:
                severity_level = 'HIGH'
                severity_color = '#fd7e14'
            elif severity_score >= 0.3:
                severity_level = 'MEDIUM'
                severity_color = '#ffc107'
            else:
                severity_level = 'LOW'
                severity_color = '#17a2b8'

            vulnerabilities.append({
                'attack_id': score.get('attack_id'),
                'severity_level': severity_level,
                'severity_score': f"{severity_score:.2f}",
                'severity_color': severity_color,
                'vulnerability_reasons': ', '.join(score.get('vulnerability_reasons', [])),
                'evidence_count': score.get('evidence_count', 0),
                'tags': ', '.join(score.get('tags', [])),
                'notes': score.get('notes', '')
            })

        # Sort by severity score descending
        vulnerabilities.sort(key=lambda x: float(x['severity_score']), reverse=True)

        return vulnerabilities

    def _get_html_template(self) -> Template:
        """
        Get Jinja2 HTML template for report.

        Returns:
            Jinja2 Template object
        """
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            font-size: 1.1em;
            opacity: 0.9;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        .stat-card h3 {
            margin: 0 0 10px 0;
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .severity-card {
            background: white;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .severity-card.critical { border-left: 4px solid #dc3545; }
        .severity-card.high { border-left: 4px solid #fd7e14; }
        .severity-card.medium { border-left: 4px solid #ffc107; }
        .severity-card.low { border-left: 4px solid #17a2b8; }
        .vulnerability-table {
            background: white;
            border-radius: 8px;
            padding: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-top: 30px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }
        .section-title {
            font-size: 1.8em;
            margin: 30px 0 20px 0;
            color: #333;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p>Generated on {{ generated_at }}</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Attacks</h3>
            <div class="value">{{ statistics.total_attacks }}</div>
        </div>
        <div class="stat-card">
            <h3>Vulnerabilities Found</h3>
            <div class="value">{{ statistics.vulnerable_count }}</div>
        </div>
        <div class="stat-card">
            <h3>Vulnerability Rate</h3>
            <div class="value">{{ statistics.vulnerability_rate }}</div>
        </div>
        <div class="stat-card">
            <h3>Average Severity</h3>
            <div class="value">{{ "%.2f"|format(statistics.average_severity) }}</div>
        </div>
    </div>

    <h2 class="section-title">Severity Distribution</h2>
    <div class="severity-grid">
        <div class="severity-card critical">
            <h4>Critical</h4>
            <div class="value">{{ statistics.severity_counts.critical }}</div>
        </div>
        <div class="severity-card high">
            <h4>High</h4>
            <div class="value">{{ statistics.severity_counts.high }}</div>
        </div>
        <div class="severity-card medium">
            <h4>Medium</h4>
            <div class="value">{{ statistics.severity_counts.medium }}</div>
        </div>
        <div class="severity-card low">
            <h4>Low</h4>
            <div class="value">{{ statistics.severity_counts.low }}</div>
        </div>
    </div>

    <div class="vulnerability-table">
        <h2 class="section-title">Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Attack ID</th>
                    <th>Severity</th>
                    <th>Vulnerability Types</th>
                    <th>Evidence</th>
                    <th>Tags</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in vulnerability_details %}
                <tr>
                    <td><strong>{{ vuln.attack_id }}</strong></td>
                    <td>
                        <span class="badge" style="background-color: {{ vuln.severity_color }}">
                            {{ vuln.severity_level }} ({{ vuln.severity_score }})
                        </span>
                    </td>
                    <td>{{ vuln.vulnerability_reasons }}</td>
                    <td>{{ vuln.evidence_count }} items</td>
                    <td>{{ vuln.tags }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
        """
        return Template(template_str)


def generate_pdf_report(results: List[Dict], scores: List[Dict],
                       metadata: Dict = None, output_dir: str = "exports") -> str:
    """
    Convenience function to generate PDF report.

    Args:
        results: Attack results
        scores: Scored results
        metadata: Additional metadata
        output_dir: Output directory

    Returns:
        Path to generated report
    """
    reporter = PDFReporter(output_dir)
    return reporter.generate_report(results, scores, metadata)
