from policy_checker import check_policy

def test_clean_policy():
    """No wildcards — findings should be empty."""
    policy = {
        "Statement": [
            {
                "Sid": "AllowSpecific",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 0


def test_action_wildcard_string():
    """Action is "*" as a string — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "WildAction",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "FAIL"
    assert findings[0]["sid"] == "WildAction"


def test_action_wildcard_in_list():
    """Action "*" inside a list — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "WildActionList",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "*"],
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "FAIL"


def test_resource_wildcard_string():
    """Resource is "*" as a string — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "WildResource",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "FAIL"


def test_resource_wildcard_in_list():
    """Resource "*" inside a list — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "WildResourceList",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": ["arn:aws:s3:::my-bucket/*", "*"]
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "FAIL"


def test_deny_statement_skipped():
    """Deny statements with wildcards should be skipped entirely."""
    policy = {
        "Statement": [
            {
                "Sid": "DenyAll",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 0


def test_service_wildcard_string():
    """Service-level wildcard as a string (e.g., "s3:*") — should be WARN."""
    policy = {
        "Statement": [
            {
                "Sid": "ServiceWild",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "WARN"


def test_service_wildcard_in_list():
    """Service-level wildcard in a list (e.g., "iam:*") — should be WARN."""
    policy = {
        "Statement": [
            {
                "Sid": "ServiceWildList",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "iam:*"],
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "WARN"
