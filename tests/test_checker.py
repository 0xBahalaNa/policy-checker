"""
Unit tests for policy_checker.py.

Covers four areas:
    1. Basic wildcard detection   — Action "*", Resource "*", service-level wildcards (e.g., "s3:*")
    2. Effect field validation    — missing, misspelled, or invalid Effect values (CM-6)
    3. CJIS v6.0 compliance       — MFA requirement (IA-2), cross-account access (AC-2)
    4. Finding enrichment         — timestamp format, framework/control_id metadata

Run the full suite with:
    pytest
"""

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


def test_not_action_flagged():
    """NotAction in an Allow statement — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "DangerousNotAction",
                "Effect": "Allow",
                "NotAction": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    findings = check_policy(policy)
    assert any(f["type"] == "not_action" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "not_action")


def test_not_resource_flagged():
    """NotResource in an Allow statement — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "DangerousNotResource",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::public-bucket/*"
            }
        ]
    }
    findings = check_policy(policy)
    assert any(f["type"] == "not_resource" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "not_resource")


def test_not_principal_flagged():
    """NotPrincipal in an Allow statement — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "DangerousNotPrincipal",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
                "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:root"}
            }
        ]
    }
    findings = check_policy(policy)
    assert any(f["type"] == "not_principal" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "not_principal")


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


def test_cjis_with_mfa_bool_if_exists():
    """CJI resource access with BoolIfExists MFA condition — should pass."""
    policy = {
        "Statement": [
            {
                "Sid": "CJIWithMFABoolIfExists",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*",
                "Condition": {
                    "BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}
                }
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) == 0


def test_cjis_with_mfa_null_condition():
    """CJI resource access with Null MFA condition — should pass."""
    policy = {
        "Statement": [
            {
                "Sid": "CJIWithMFANull",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*",
                "Condition": {
                    "Null": {"aws:MultiFactorAuthPresent": "false"}
                }
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) == 0


def test_cjis_public_access_flagged():
    """Principal "*" on a CJI resource — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "CJIPublicAccess",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*",
                "Principal": "*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "cji_public_access" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "cji_public_access")


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


def test_cjis_not_action_flagged():
    """NotAction on a CJI resource — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "CJINotAction",
                "Effect": "Allow",
                "NotAction": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "not_action" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "not_action")


def test_cjis_not_principal_flagged():
    """NotPrincipal on a CJI resource — should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "CJINotPrincipal",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*",
                "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:root"}
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "not_principal" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "not_principal")


# --- Effect validation tests (check_policy) ---

def test_missing_effect_flagged():
    """Missing Effect key — should produce WARN with invalid_effect type."""
    policy = {
        "Statement": [
            {
                "Sid": "NoEffect",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "WARN"
    assert findings[0]["type"] == "invalid_effect"
    assert "None" in findings[0]["message"]


def test_misspelled_effect_flagged():
    """Misspelled Effect (e.g., "Alow") — should produce WARN."""
    policy = {
        "Statement": [
            {
                "Sid": "Typo",
                "Effect": "Alow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "WARN"
    assert findings[0]["type"] == "invalid_effect"
    assert "Alow" in findings[0]["message"]


def test_invalid_effect_skips_further_checks():
    """Invalid Effect should NOT produce action/resource wildcard findings."""
    policy = {
        "Statement": [
            {
                "Sid": "BadEffect",
                "Effect": "Allow!",
                "Action": "*",
                "Resource": "*",
                "NotAction": "s3:GetObject"
            }
        ]
    }
    findings = check_policy(policy)
    # Only the invalid_effect finding — no action_wildcard, resource_wildcard,
    # or not_action findings because the continue skips further analysis.
    assert len(findings) == 1
    assert findings[0]["type"] == "invalid_effect"


# --- Effect validation tests (check_cjis_policy) ---

def test_cjis_missing_effect_flagged():
    """Missing Effect on a CJI resource statement — should produce WARN."""
    policy = {
        "Statement": [
            {
                "Sid": "CJINoEffect",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "WARN"
    assert findings[0]["type"] == "invalid_effect"


def test_cjis_misspelled_effect_flagged():
    """Misspelled Effect on a CJI resource — should produce WARN."""
    policy = {
        "Statement": [
            {
                "Sid": "CJITypo",
                "Effect": "Alow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "WARN"
    assert findings[0]["type"] == "invalid_effect"
    assert "Alow" in findings[0]["message"]


def test_cjis_invalid_effect_skips_cjis_checks():
    """Invalid Effect should NOT produce MFA or cross-account findings."""
    policy = {
        "Statement": [
            {
                "Sid": "CJIBadEffect",
                "Effect": "Allw",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*",
                "Principal": "*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    # Only invalid_effect — no cji_missing_mfa or cji_public_access.
    assert len(findings) == 1
    assert findings[0]["type"] == "invalid_effect"


# --- Case-insensitive Effect tests ---

def test_deny_case_insensitive_lowercase():
    """Lowercase "deny" should be skipped like "Deny"."""
    policy = {
        "Statement": [
            {
                "Sid": "LowerDeny",
                "Effect": "deny",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 0


def test_deny_case_insensitive_uppercase():
    """Uppercase "DENY" should be skipped like "Deny"."""
    policy = {
        "Statement": [
            {
                "Sid": "UpperDeny",
                "Effect": "DENY",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    findings = check_policy(policy)
    assert len(findings) == 0


def test_allow_case_insensitive():
    """Lowercase "allow" should be treated as valid Allow."""
    policy = {
        "Statement": [
            {
                "Sid": "LowerAllow",
                "Effect": "allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    findings = check_policy(policy)
    # Should produce action_wildcard and resource_wildcard, NOT invalid_effect
    types = [f["type"] for f in findings]
    assert "invalid_effect" not in types
    assert "action_wildcard" in types


def test_cjis_deny_case_insensitive():
    """Lowercase "deny" should be skipped by CJIS checks."""
    policy = {
        "Statement": [
            {
                "Sid": "CJILowerDeny",
                "Effect": "deny",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert len(findings) == 0


def test_cjis_allow_case_insensitive():
    """Uppercase "ALLOW" on CJI resource should trigger CJIS checks."""
    policy = {
        "Statement": [
            {
                "Sid": "CJIUpperAllow",
                "Effect": "ALLOW",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    # Should trigger cji_missing_mfa, NOT invalid_effect
    types = [f["type"] for f in findings]
    assert "invalid_effect" not in types
    assert "cji_missing_mfa" in types
