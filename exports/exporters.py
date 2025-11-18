"""
Exporters for different data formats.
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any


class BaseExporter:
    """Base class for all exporters."""

    def __init__(self, output_dir: str = "exports"):
        """
        Initialize exporter.

        Args:
            output_dir: Directory to save exports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, data: Any, filename: str) -> str:
        """
        Export data to file.

        Args:
            data: Data to export
            filename: Output filename

        Returns:
            Path to exported file
        """
        raise NotImplementedError()


class CSVExporter(BaseExporter):
    """Export results to CSV format."""

    def export(self, data: List[Dict], filename: str = None) -> str:
        """
        Export data to CSV.

        Args:
            data: List of dictionaries to export
            filename: Output filename (auto-generated if None)

        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"export_{timestamp}.csv"

        output_path = self.output_dir / filename

        if not data:
            # Create empty CSV
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                f.write("No data to export\n")
            return str(output_path)

        # Get all unique keys from all dictionaries
        fieldnames = set()
        for item in data:
            fieldnames.update(self._flatten_dict(item).keys())
        fieldnames = sorted(list(fieldnames))

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for item in data:
                flattened = self._flatten_dict(item)
                writer.writerow(flattened)

        return str(output_path)

    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
        """
        Flatten nested dictionary.

        Args:
            d: Dictionary to flatten
            parent_key: Parent key for recursion
            sep: Separator for nested keys

        Returns:
            Flattened dictionary
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k

            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert lists to JSON strings
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, v))

        return dict(items)


class JSONExporter(BaseExporter):
    """Export results to JSON format."""

    def export(self, data: Any, filename: str = None, pretty: bool = True) -> str:
        """
        Export data to JSON.

        Args:
            data: Data to export
            filename: Output filename (auto-generated if None)
            pretty: Whether to pretty-print JSON

        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"export_{timestamp}.json"

        output_path = self.output_dir / filename

        with open(output_path, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, ensure_ascii=False)

        return str(output_path)


class SARIFExporter(BaseExporter):
    """
    Export results to SARIF (Static Analysis Results Interchange Format).
    SARIF is a standard format for static analysis tool output.
    """

    def export(self, results: List[Dict], filename: str = None) -> str:
        """
        Export results to SARIF format.

        Args:
            results: List of attack results with scores
            filename: Output filename (auto-generated if None)

        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sarif_report_{timestamp}.sarif"

        output_path = self.output_dir / filename

        sarif_report = self._build_sarif(results)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_report, f, indent=2)

        return str(output_path)

    def _build_sarif(self, results: List[Dict]) -> Dict:
        """
        Build SARIF-compliant report structure.

        Args:
            results: List of results to convert

        Returns:
            SARIF-compliant dictionary
        """
        # SARIF 2.1.0 schema
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "RedTeam LLM Security Scanner",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/your-org/redteam",
                            "rules": self._build_rules()
                        }
                    },
                    "results": self._build_results(results),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + 'Z'
                        }
                    ]
                }
            ]
        }

        return sarif

    def _build_rules(self) -> List[Dict]:
        """Build SARIF rules definitions."""
        return [
            {
                "id": "LLM-001",
                "name": "JailbreakVulnerability",
                "shortDescription": {
                    "text": "LLM Jailbreak Vulnerability"
                },
                "fullDescription": {
                    "text": "The model responds to jailbreak attempts that bypass safety guardrails."
                },
                "defaultConfiguration": {
                    "level": "error"
                }
            },
            {
                "id": "LLM-002",
                "name": "InstructionLeakage",
                "shortDescription": {
                    "text": "System Instruction Leakage"
                },
                "fullDescription": {
                    "text": "The model exposes system instructions or internal prompts."
                },
                "defaultConfiguration": {
                    "level": "warning"
                }
            },
            {
                "id": "LLM-003",
                "name": "SecretExposure",
                "shortDescription": {
                    "text": "Secret or Credential Exposure"
                },
                "fullDescription": {
                    "text": "The model exposes secrets, API keys, or credentials."
                },
                "defaultConfiguration": {
                    "level": "error"
                }
            },
            {
                "id": "LLM-004",
                "name": "SafetyBypass",
                "shortDescription": {
                    "text": "Safety Filter Bypass"
                },
                "fullDescription": {
                    "text": "The model's safety filters were bypassed."
                },
                "defaultConfiguration": {
                    "level": "error"
                }
            },
            {
                "id": "LLM-005",
                "name": "HarmfulContent",
                "shortDescription": {
                    "text": "Harmful Content Generation"
                },
                "fullDescription": {
                    "text": "The model generated harmful or dangerous content."
                },
                "defaultConfiguration": {
                    "level": "error"
                }
            }
        ]

    def _build_results(self, results: List[Dict]) -> List[Dict]:
        """
        Convert attack results to SARIF results format.

        Args:
            results: List of attack results

        Returns:
            List of SARIF-compliant results
        """
        sarif_results = []

        for result in results:
            if not result.get('vulnerable', False):
                continue  # Only report vulnerabilities

            rule_id = self._get_rule_id(result)
            level = self._get_severity_level(result.get('severity_score', 0))

            sarif_result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": result.get('notes', 'Vulnerability detected')
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": result.get('attack_id', 'unknown'),
                                "kind": "attack"
                            }
                        ]
                    }
                ],
                "properties": {
                    "attack_id": result.get('attack_id'),
                    "vulnerability_reasons": result.get('vulnerability_reasons', []),
                    "severity_score": result.get('severity_score'),
                    "evidence_count": result.get('evidence_count'),
                    "tags": result.get('tags', []),
                    "timestamp": result.get('timestamp')
                }
            }

            sarif_results.append(sarif_result)

        return sarif_results

    def _get_rule_id(self, result: Dict) -> str:
        """
        Determine rule ID based on vulnerability reasons.

        Args:
            result: Attack result

        Returns:
            Rule ID
        """
        reasons = result.get('vulnerability_reasons', [])

        if 'secret_exposure' in reasons:
            return "LLM-003"
        elif 'instruction_leakage' in reasons:
            return "LLM-002"
        elif 'safety_bypass' in reasons:
            return "LLM-004"
        elif 'harmful_content' in reasons:
            return "LLM-005"
        else:
            return "LLM-001"

    def _get_severity_level(self, score: float) -> str:
        """
        Convert numeric severity score to SARIF level.

        Args:
            score: Severity score (0.0-1.0)

        Returns:
            SARIF level (note, warning, error)
        """
        if score >= 0.8:
            return "error"
        elif score >= 0.5:
            return "warning"
        else:
            return "note"


def export_results(results: List[Dict], format: str = 'json',
                  output_dir: str = 'exports', filename: str = None) -> str:
    """
    Convenience function to export results in specified format.

    Args:
        results: Results to export
        format: Export format ('csv', 'json', 'sarif')
        output_dir: Output directory
        filename: Output filename

    Returns:
        Path to exported file

    Raises:
        ValueError: If format is not supported
    """
    exporters = {
        'csv': CSVExporter,
        'json': JSONExporter,
        'sarif': SARIFExporter
    }

    if format.lower() not in exporters:
        raise ValueError(f"Unsupported format: {format}. Supported: {list(exporters.keys())}")

    exporter_class = exporters[format.lower()]
    exporter = exporter_class(output_dir)

    return exporter.export(results, filename)
