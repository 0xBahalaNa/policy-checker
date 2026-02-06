"""
policy_checker.py

This script loads an AWS policy file and checks if it is overly permisssive.
"""

import json

# Variable containing name of policy file to validate.
# Change when necessary.
filename = "test_policy.json"

# Load JSON policy file.
with open(filename, "r") as file:
    policy = json.load(file)

print(f"Checking: {filename}")

# Counter for the number of issues found.
issues = 0

# Loop to iterate through all the policy statements.
for statement in policy.get("Statement", []):

    # Check if "Action" is overly permissive.
    if statement.get("Action") == "*":
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Action is \"*\"")
        issues += 1

    # Check if "Resource" is overly permissive 
    if statement.get("Resource") == "*":
        print(f"[FAIL] Statement \"{statement.get('Sid')}\": Resource is \"*\"")
        issues += 1

# Print final results. 
print(f"\nResults: {issues} issues found.")