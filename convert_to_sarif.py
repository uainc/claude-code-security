import json
from datetime import datetime

def convert_to_sarif(claude_output: list) -> dict:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ClaudeCode",
                        "version": "1.0.0",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    run = sarif["runs"][0]

    for finding in claude_output:
        result = {
            "ruleId": finding.get("rule_id", "CLAUDE-001"),
            "level": map_severity(finding.get("severity", "warning")),
            "message": {
                "text": finding.get("message", "")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("file", "unknown")
                        },
                        "region": {
                            "startLine": finding.get("line", 1),
                            "startColumn": finding.get("column", 1)
                        }
                    }
                }
            ]
        }
        run["results"].append(result)

    return sarif

def map_severity(severity: str) -> str:
    mapping = {
        "error": "error",
        "high": "error",
        "warning": "warning",
        "medium": "warning",
        "info": "note",
        "low": "note"
    }
    return mapping.get(severity.lower(), "warning")

# Example usage
with open("/home/runner/work/claude-code-security/claude-code-security/claudecode-results.json") as f:
    claude_findings = json.load(f)

sarif_output = convert_to_sarif(claude_findings)

with open("results.sarif", "w") as f:
    json.dump(sarif_output, f, indent=2)
