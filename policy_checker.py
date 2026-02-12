"""
policy_checker.py

This script loads an AWS IAM policy JSON file and checks for overly permissive statements, 
such as wildcard ("*") Actions or Resources.

Exit codes:
    0 - Policy is clean, no issues found
    1 - Issues detected
    2 - Input error (file not found, invalid JSON, etc.)
"""

import argparse
import json
import sys

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
                "message": "Action is \"*\""
            })
        elif isinstance(action, list) and "*" in action:
            findings.append({
                "severity": "FAIL",
                "sid": sid,
                "message": "Action is \"*\""
            })

        # Check for service-level wildcards (e.g., "s3:*", "iam:*").
        # These grant full access to a specific AWS service, which is risky
        # but less severe than a full "*" wildcard.
        if isinstance(action, str) and action.endswith(":*"):
            findings.append({
                "severity": "WARN",
                "sid": sid,
                "message": f"Action \"{action}\" grants full access to a service"
            })
        elif isinstance(action, list):
            for item in action:
                if isinstance(item, str) and item.endswith(":*"):
                    findings.append({
                        "severity": "WARN",
                        "sid": sid,
                        "message": f"Action \"{item}\" grants full access to a service"
                    })

        # Check if "Resource" is a wildcard ("*"), meaning all resources are affected.
        # Same string-or-list check as above.
        resource = statement.get("Resource")
        if isinstance(resource, str) and resource == "*":
            findings.append({
                "severity": "FAIL",
                "sid": sid,
                "message": "Resource is \"*\""
            })
        elif isinstance(resource, list) and "*" in resource:
            findings.append({
                "severity": "FAIL",
                "sid": sid,
                "message": "Resource is \"*\""
            })

    return findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check an AWS IAM policy JSON file for overly permissive statements."
    )
    parser.add_argument("filename", help="Path to the JSON policy file.")
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

    print(f"Checking: {filename}")

    findings = check_policy(policy)

    for finding in findings:
        print(f"[{finding['severity']}] Statement \"{finding['sid']}\": {finding['message']}")

    print(f"\nResults: {len(findings)} issues found.")
    sys.exit(1 if findings else 0)
