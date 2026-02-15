# policy_checker.py

This script loads an AWS IAM policy file and checks if it is overly permissive.

## Usage
```
python policy_checker.py <filename> [--output text|json]
```

### Examples
```
python policy_checker.py policy.json
python policy_checker.py policy.json --output json
python policy_checker.py policy.json --output json > results.json
```

## What It Does
- Loads a JSON policy file.
- Iterates over the `Statement` entries.
- Checks for excessive permissions such as:
    - `Action` is `*`
    - `Resource` is `*`
    - Service-level wildcards (e.g., `s3:*`, `iam:*`)
- Maps findings to NIST 800-53 compliance controls.
- Prints a summary of the results.

## Compliance Mapping

Each check maps to controls across NIST 800-53 Rev 5, FedRAMP, and CJIS v6.0:

| Check | NIST 800-53 | FedRAMP | CJIS Security Policy |
|-------|-------------|---------|----------------------|
| Action is `*` | AC-6 (Least Privilege) | AC-6 | 5.5.2.1 (Least Privilege) |
| Resource is `*` | AC-3 (Access Enforcement) | AC-3 | 5.5.2 (Access Control Enforcement) |
| Service-level wildcard (e.g., `s3:*`) | AC-6 (Least Privilege) | AC-6 | 5.5.2.1 (Least Privilege) |
| Overly permissive IAM policy | AC-2 (Account Management) | AC-2 | 5.5.1 (Account Management) |

### How This Supports Audits

The JSON output (`--output json`) provides machine-readable evidence for compliance assessments. Auditors can use this output to verify CM-6 (Configuration Settings), CM-7 (Least Functionality), and SA-11 (Developer Testing) controls. Each finding includes the compliance framework, control ID, severity, and a UTC timestamp for audit trail purposes.

## Output Formats

### Text (default)
Human-readable output for terminal use.
```
Checking: test-policy.json
[FAIL] Statement "DangerousAdmin01": Action is "*"
[FAIL] Statement "DangerousAdmin01": Resource is "*"

Results: 2 issues found.
```

### JSON (`--output json`)
Structured output for automation and compliance pipelines. Each finding includes `framework`, `control_id`, `finding`, `severity`, `resource`, and `timestamp`.
```json
[
  {
    "framework": "NIST 800-53",
    "control_id": "AC-6",
    "finding": "Action is \"*\"",
    "severity": "FAIL",
    "resource": "test-policy.json",
    "timestamp": "2026-02-14T12:00:00+00:00"
  }
]
```

## Testing
```
python -m pytest tests/ -v
```

## Requirements
- Python 3.x

## License
- MIT License