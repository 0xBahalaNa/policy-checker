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

# Create a parser variable with a description of the tool.
parser = argparse.ArgumentParser(description="Check an AWS IAM policy JSON file for overly permissive statements.")

# Add a positional argument for the file name.
parser.add_argument("filename", help="Path to the JSON policy file.")

# Parse the command-line arguments.
args = parser.parse_args()

filename = args.filename

# Attempt to open and parse the JSON policy file.
# Each `except` block handles a different type of error that could occur.
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

# Counter to track how many issues are found.
issues = 0

# Iterate through each statement in the policy.
# .get() returns a default (here, an empty list) if the key is missing,
# which avoids a KeyError.
for statement in policy.get("Statement", []):
    
    # Skip "Deny" statements — they restrict access rather than grant it,
    # so wildcards in Deny statements are not a security concern.
    effect = statement.get("Effect")
    if effect == "Deny":
        continue

    # Check if "Action" is a wildcard ("*"), meaning all actions are allowed.
    # The value can be either a single string or a list of strings,
    # so we check for both cases using isinstance().
    action = statement.get("Action")
    if isinstance(action, str) and action == "*":
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Action is \"*\"")
        issues += 1
    elif isinstance(action, list) and "*" in action:
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Action is \"*\"")
        issues += 1

    # Check if "Resource" is a wildcard ("*"), meaning all resources are affected.
    # Same string-or-list check as above.
    resource = statement.get("Resource")
    if isinstance(resource, str) and resource == "*":
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Resource is \"*\"")
        issues += 1
    elif isinstance(resource, list) and "*" in resource:
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Resource is \"*\"")
        issues += 1

# Print the final results.
print(f"\nResults: {issues} issues found.")

sys.exit(1 if issues > 0 else 0)
