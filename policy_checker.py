"""
policy_checker.py

This script loads an AWS IAM policy JSON file and checks for overly permissive statements, 
such as wildcard ("*") Actions or Resources.

Exit codes:
    0 - Policy is clean, no issues found
    1 - Issues detected
    2 - Input error (file not found, invalid JSON, etc.)
"""

from datetime import datetime, timezone
import argparse
import json
import sys

CONTROL_MAP = {
    "action_wildcard":  {"framework": "NIST 800-53", "control_id": "AC-6"},
    "service_wildcard": {"framework": "NIST 800-53", "control_id": "AC-6"},
    "resource_wildcard": {"framework": "NIST 800-53", "control_id": "AC-3"},
}

def check_policy(policy):
    """
    Check a parsed IAM policy dictionary for overly permissive statements.

    Args:
        policy: A dictionary representing a parsed IAM policy JSON.

    Returns:
        A list of finding dictionaries, each with keys:
            "severity" - "FAIL" or "WARN"
            "sid"      - The statement's Sid (or None if missing)
            "message"  - A human-readable description of the issue
            "type"     - Finding type for control mapping (e.g., "action_wildcard")
    """
    findings = []

    for statement in policy.get("Statement", []):

        # Skip "Deny" statements - they restrict access rather than grant it,
        # so wildcards in Deny statements are not a security concern.
        effect = statement.get("Effect")
        if effect == "Deny":
            continue

        sid = statement.get("Sid")

        # Check if "Action" is a wildcard ("*"), meaning all actions are allowed.
        # The value can be either a single string or a list of strings,
        # so we check for both cases using isinstance().
        action = statement.get("Action")
        if isinstance(action, str) and action == "*":
            findings.append({
                "severity": "FAIL",
                "sid": sid,
                "message": "Action is \"*\"",
                "type": "action_wildcard"
            })
        elif isinstance(action, list) and "*" in action:
            findings.append({
                "severity": "FAIL",
                "sid": sid,
                "message": "Action is \"*\"",
                "type": "action_wildcard"
            })

        # Check for service-level wildcards (e.g., "s3:*", "iam:*").
        # These grant full access to a specific AWS service, which is risky
        # but less severe than a full "*" wildcard.
        if isinstance(action, str) and action.endswith(":*"):
            findings.append({
                "severity": "WARN",
                "sid": sid,
                "message": f"Action \"{action}\" grants full access to a service",
                "type": "service_wildcard"
            })
        elif isinstance(action, list):
            for item in action:
                if isinstance(item, str) and item.endswith(":*"):
                    findings.append({
                        "severity": "WARN",
                        "sid": sid,
                        "message": f"Action \"{item}\" grants full access to a service",
                        "type": "service_wildcard"
                    })

        # Check if "Resource" is a wildcard ("*"), meaning all resources are affected.
        # Same string-or-list check as above.
        resource = statement.get("Resource")
        if isinstance(resource, str) and resource == "*":
            findings.append({
                "severity": "FAIL",
                "sid": sid,
                "message": "Resource is \"*\"",
                "type": "resource_wildcard"
            })
        elif isinstance(resource, list) and "*" in resource:
            findings.append({
                "severity": "FAIL",
                "sid": sid,
                "message": "Resource is \"*\"",
                "type": "resource_wildcard"
            })

    return findings

def enrich_findings(findings, resource):
    """
    Enrich raw findings with compliance framework metadata and timestamps.

    Args:
        findings: A list of finding dictionaries from check_policy(), each
                  containing a "type" key used to look up control mappings.
        resource: The filename or path of the policy that was checked.

    Returns:
        A list of enriched dictionaries, each with keys:
            "framework"  - Compliance framework name (e.g., "NIST 800-53")
            "control_id" - The specific control identifier (e.g., "AC-6")
            "finding"    - A human-readable description of the issue
            "severity"   - "FAIL" or "WARN"
            "resource"   - The policy file that was checked
            "timestamp"  - ISO 8601 UTC timestamp of when the check ran

    Raises:
        ValueError: If a finding's "type" is not found in CONTROL_MAP.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    enriched = []
    for finding in findings:
        if finding["type"] not in CONTROL_MAP:
            raise ValueError(f"Unknown finding type: {finding['type']}")
        control = CONTROL_MAP[finding["type"]]
        enriched.append({
            "framework": control["framework"],
            "control_id": control["control_id"],
            "finding": finding["message"],
            "severity": finding["severity"],
            "resource": resource,
            "timestamp": timestamp,
        })
    return enriched

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check an AWS IAM policy JSON file for overly permissive statements."
    )
    parser.add_argument("filename", help="Path to the JSON policy file.")
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)."
    )
    args = parser.parse_args()
    filename = args.filename

    try:
        with open(filename, "r") as file:
            policy = json.load(file)
    except FileNotFoundError:
        print(f"{filename} doesn't exist.", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError:
        print(f"{filename} contains invalid JSON.", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"{filename} can't be read.", file=sys.stderr)
        sys.exit(2)

    findings = check_policy(policy)

    if args.output == "json":
        enriched = enrich_findings(findings, resource=filename)
        json.dump(enriched, sys.stdout, indent=2)
        print()  # trailing newline
    else:
        print(f"Checking: {filename}")
        for finding in findings:
            print(f"[{finding['severity']}] Statement \"{finding['sid']}\": {finding['message']}")
        print(f"\nResults: {len(findings)} issues found.")

    sys.exit(1 if findings else 0)
