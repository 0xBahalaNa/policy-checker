"""
policy_checker.py

This script loads an AWS policy file and checks if it is overly permissive.
"""

import json

# Variable containing name of policy file to validate.
# Change when necessary.
filename = "test-policy.json"

# Load JSON policy file.
with open(filename, "r") as file:
    policy = json.load(file)

print(f"Checking: {filename}")

# Counter for the number of issues found.
issues = 0

# Loop to iterate through all the policy statements.
for statement in policy.get("Statement", []):

    # Check if "Action" is overly permissive.
    action = statement.get("Action")
    if isinstance(action, str) and action == "*":
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Action is \"*\"")
        issues += 1
    elif isinstance(action, list) and "*" in action:
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Action is \"*\"")
        issues += 1

    # Check if "Resource" is overly permissive 
    resource = statement.get("Resource")
    if isinstance(resource, str) and resource == "*":
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Resource is \"*\"")
        issues += 1
    elif isinstance(resource, list) and "*" in resource:
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Resource is \"*\"")
        issues += 1   

# Print final results. 
print(f"\nResults: {issues} issues found.")