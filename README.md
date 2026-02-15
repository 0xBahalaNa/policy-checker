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