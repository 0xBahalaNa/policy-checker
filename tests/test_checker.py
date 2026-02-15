from policy_checker import check_policy, check_cjis_policy, enrich_findings
from datetime import datetime

def test_enrich_findings_timestamp_format():
    """Timestamp should be valid ISO 8601."""
    raw = [{"severity": "FAIL", "sid": "Test", "message": "Test", "type": "action_wildcard"}]
    enriched = enrich_findings(raw, resource="test.json")
    timestamp = enriched[0]["timestamp"]
    parsed = datetime.fromisoformat(timestamp)
    assert parsed is not None

def test_enrich_findings_structure():
    """Enriched findings should have framework, control_id, resource, and timestamp."""
    raw = [{"severity": "FAIL", "sid": "Test", "message": "Action is \"*\"", "type": "action_wildcard"}]
    enriched = enrich_findings(raw, resource="test-policy.json")
    assert len(enriched) == 1
    result = enriched[0]
    assert result["framework"] == "NIST 800-53"
    assert result["control_id"] == "AC-6"
    assert result["severity"] == "FAIL"
    assert result["resource"] == "test-policy.json"
    assert "timestamp" in result

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

def test_findings_include_type_key():
    """Findings should include a 'type' key for control mapping."""
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
    assert findings[0]["type"] == "action_wildcard"


def test_cjis_missing_mfa():
    """CJI resource access without MFA condition — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "CJINoMFA",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "FAIL"
    assert findings[0]["type"] == "cji_missing_mfa"


def test_cjis_with_mfa_clean():
    """CJI resource access with MFA condition — should pass."""
    policy = {
        "Statement": [
            {
                "Sid": "CJIWithMFA",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*",
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                }
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) == 0


def test_cjis_cross_account_no_org_restriction():
    """Cross-account access to CJI resource without org restriction — should be WARN."""
    policy = {
        "Statement": [
            {
                "Sid": "CJICrossAcct",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-evidence-store/*",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:root"
                }
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) >= 1
    types = [f["type"] for f in findings]
    assert "cji_cross_account" in types


def test_cjis_non_cji_resource_skipped():
    """Non-CJI resources should not trigger CJIS checks."""
    policy = {
        "Statement": [
            {
                "Sid": "RegularAccess",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::regular-bucket/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) == 0


def test_cjis_deny_skipped():
    """Deny statements should be skipped by CJIS checks."""
    policy = {
        "Statement": [
            {
                "Sid": "DenyCJI",
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) == 0
