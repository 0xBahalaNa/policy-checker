"""
policy_checker.py

This script loads an AWS IAM policy JSON file and checks for overly permissive statements,
such as wildcard ("*") Actions or Resources. It also performs CJIS v6.0 specific checks
for policies accessing Criminal Justice Information (CJI) resources.

Exit codes:
    0 - Policy is clean, no issues found
    1 - Issues detected
    2 - Input error (file not found, invalid JSON, etc.)
"""

from datetime import datetime, timezone
import argparse
import json
import sys

# Maps each finding type to its compliance framework and control ID.
# This lets the tool output audit-ready references that GRC teams can trace
# directly back to the relevant control requirements:
#   AC-6 (Least Privilege)            — wildcard actions grant more permissions than needed
#   AC-3 (Access Enforcement)         — wildcard resources bypass resource-level boundaries
#   IA-2 (Identification & Auth)      — CJI access without MFA violates identity assurance
#   AC-2 (Account Management)         — cross-account CJI access needs org-level guardrails
CONTROL_MAP = {
    "action_wildcard":  {"framework": "NIST 800-53", "control_id": "AC-6"},
    "service_wildcard": {"framework": "NIST 800-53", "control_id": "AC-6"},
    "resource_wildcard": {"framework": "NIST 800-53", "control_id": "AC-3"},
    "cji_missing_mfa":  {"framework": "CJIS v6.0", "control_id": "IA-2"},
    "cji_cross_account": {"framework": "CJIS v6.0", "control_id": "AC-2"},
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

def check_cjis_policy(policy):
    """
    Check a parsed IAM policy for CJIS v6.0 specific requirements.

    Checks for:
        - Policies accessing CJI resources without MFA conditions (IA-2)
        - Policies allowing cross-account access to CJI resources (AC-2)

    Args:
        policy: A dictionary representing a parsed IAM policy JSON.

    Returns:
        A list of finding dictionaries with the same structure as check_policy().
    """
    findings = []

    for statement in policy.get("Statement", []):
        if statement.get("Effect") == "Deny":
            continue

        sid = statement.get("Sid")
        resource = statement.get("Resource")
        condition = statement.get("Condition", {})

        # Normalize resource to a list for consistent checking.
        if isinstance(resource, str):
            resources = [resource]
        elif isinstance(resource, list):
            resources = resource
        else:
            continue

        # Check if any resource references CJI data (by naming pattern or tag).
        has_cji_resource = any(
            "cji" in r.lower() or "criminal-justice" in r.lower()
            for r in resources
        )
        if not has_cji_resource:
            continue

        # CJIS IA-2: CJI resources should require MFA.
        mfa_required = (
            condition.get("Bool", {}).get("aws:MultiFactorAuthPresent") == "true"
        )
        if not mfa_required:
            findings.append({
                "severity": "FAIL",
                "sid": sid,
                "message": "CJI resource access without MFA condition"
                          " (aws:MultiFactorAuthPresent)",
                "type": "cji_missing_mfa"
            })

        # CJIS AC-2: CJI resources should not allow cross-account access
        # without explicit principal restrictions.
        #
        # IAM policies represent the Principal field in three ways:
        #   - A string:  "arn:aws:iam::123456789012:root"
        #   - A dict:    {"AWS": "arn:aws:iam::123456789012:root"}
        #   - A dict with a list: {"AWS": ["arn:...:root", "arn:...:root"]}
        # The code below normalizes all three forms into a flat list so we
        # can check each principal consistently.
        principal = statement.get("Principal")
        if principal and principal != "*":
            principals = [principal] if isinstance(principal, str) else []
            if isinstance(principal, dict):
                principals = principal.get("AWS", [])
                if isinstance(principals, str):
                    principals = [principals]
            for p in principals:
                if ":root" in p and "arn:aws:iam::" in p:
                    account_condition = condition.get("StringEquals", {}).get("aws:PrincipalOrgID")
                    if not account_condition:
                        findings.append({
                            "severity": "WARN",
                            "sid": sid,
                            "message": "Cross-account access to CJI resource"
                                      " without org restriction",
                            "type": "cji_cross_account"
                        })
                        break

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

# This guard ensures the code below only runs when the script is executed
# directly (e.g., `python policy_checker.py test-policy.json`), not when it
# is imported as a module by other code or tests.
if __name__ == "__main__":

    # --- 1. Parse command-line arguments ---
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

    # --- 2. Load and parse the policy JSON file ---
    try:
        with open(filename, "r", encoding="utf-8") as file:
            parsed_policy = json.load(file)
    except FileNotFoundError:
        print(f"{filename} doesn't exist.", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError:
        print(f"{filename} contains invalid JSON.", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"{filename} can't be read.", file=sys.stderr)
        sys.exit(2)

    # --- 3. Run checks and output results ---
    results = check_policy(parsed_policy)
    results.extend(check_cjis_policy(parsed_policy))

    if args.output == "json":
        enriched_results = enrich_findings(results, resource=filename)
        json.dump(enriched_results, sys.stdout, indent=2)
        print()  # trailing newline
    else:
        print(f"Checking: {filename}")
        for result in results:
            print(f"[{result['severity']}] Statement \"{result['sid']}\": {result['message']}")
        print(f"\nResults: {len(results)} issues found.")

    sys.exit(1 if results else 0)
