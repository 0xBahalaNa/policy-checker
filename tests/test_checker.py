"""
Unit tests for policy_checker.py.

Covers five areas:
    1. Basic wildcard detection   — Action "*", Resource "*", service-level wildcards (e.g., "s3:*")
    2. Effect field validation    — missing, misspelled, or invalid Effect values (CM-6)
    3. CJIS v6.1 compliance       — MFA requirement (IA-2), cross-account access (AC-2)
    4. Finding enrichment         — timestamp format, framework/control_id metadata
    5. CLI input errors           — --cji-patterns file failures exit 2

Run the full suite with:
    pytest
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from policy_checker import check_policy, check_cjis_policy, enrich_findings

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


def test_single_object_statement():
    """A single-object Statement still reports the wildcard findings."""
    policy = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    }
    findings = check_policy(policy)
    types = [f["type"] for f in findings]
    assert "action_wildcard" in types
    assert "resource_wildcard" in types
    assert all(
        f["severity"] == "FAIL"
        for f in findings
        if f["type"] in ("action_wildcard", "resource_wildcard")
    )
    assert check_cjis_policy(policy) == []


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


def test_cjis_non_string_aws_principal_keeps_findings():
    """Non-string Principal AWS items must not raise or drop earlier findings."""
    policy = {
        "Statement": [
            {
                "Sid": "EarlierGap",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*",
            },
            {
                "Sid": "MalformedPrincipal",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*",
                "Principal": {
                    "AWS": [123, None, "arn:aws:iam::123456789012:root"]
                },
            },
        ]
    }
    findings = check_cjis_policy(policy)
    earlier = [f for f in findings if f["sid"] == "EarlierGap"]
    malformed = [f for f in findings if f["sid"] == "MalformedPrincipal"]
    assert any(f["type"] == "cji_missing_mfa" for f in earlier)
    assert any(f["type"] == "cji_missing_mfa" for f in malformed)
    assert any(f["type"] == "cji_cross_account" for f in malformed)


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


def test_cjis_not_resource_cji_arn_requires_mfa():
    """NotResource naming a CJI ARN still grants other CJI resources."""
    policy = {
        "Statement": [
            {
                "Sid": "NotResourceCJI",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": [
                    "arn:aws:s3:::cji-data-bucket/*",
                    "arn:aws:s3:::cji-evidence-store/*"
                ]
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "cji_missing_mfa" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "cji_missing_mfa")


def test_cjis_not_resource_exclusion_grants_cji():
    """NotResource on a non-CJI ARN grants every CJI bucket by exclusion."""
    policy = {
        "Statement": [
            {
                "Sid": "NotResourceBackups",
                "Effect": "Allow",
                "Action": "s3:*",
                "NotResource": "arn:aws:s3:::backups/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "cji_missing_mfa" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "cji_missing_mfa")


def test_cjis_not_resource_with_mfa_clean():
    """NotResource grant with MFA should not raise the IA-2 finding."""
    policy = {
        "Statement": [
            {
                "Sid": "NotResourceBackupsMFA",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::backups/*",
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                }
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert findings == []


def test_cjis_not_resource_not_action():
    """NotAction on a NotResource grant should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "NotResourceNotAction",
                "Effect": "Allow",
                "NotAction": "s3:GetObject",
                "NotResource": "arn:aws:s3:::cji-data-bucket/*",
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                }
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "not_action" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "not_action")


def test_cjis_not_resource_not_principal():
    """NotPrincipal on a NotResource grant should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "NotResourceNotPrincipal",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::cji-data-bucket/*",
                "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                }
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "not_principal" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "not_principal")


def test_cjis_not_resource_cross_account():
    """Cross-account principal on a NotResource grant should be WARN."""
    policy = {
        "Statement": [
            {
                "Sid": "NotResourceCrossAccount",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::criminal-justice-records/*",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                }
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "cji_cross_account" for f in findings)
    assert any(f["severity"] == "WARN" for f in findings if f["type"] == "cji_cross_account")


def test_cjis_not_resource_public_access():
    """Principal * on a NotResource grant should be FAIL."""
    policy = {
        "Statement": [
            {
                "Sid": "NotResourcePublic",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::backups/*",
                "Principal": "*",
                "Condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                }
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "cji_public_access" for f in findings)
    assert any(f["severity"] == "FAIL" for f in findings if f["type"] == "cji_public_access")


def test_cjis_not_resource_star_grants_nothing():
    """NotResource * matches no resource, so CJIS controls do not apply."""
    policy = {
        "Statement": [
            {
                "Sid": "NotResourceStar",
                "Effect": "Allow",
                "Action": "s3:*",
                "NotResource": "*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert findings == []


def test_cjis_not_resource_partial_name_exclusion_still_grants_cji():
    """Excluding only the cji token still grants the other CJI names."""
    policy = {
        "Statement": [
            {
                "Sid": "ExcludeOnlyCjiToken",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "*cji*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "cji_missing_mfa" for f in findings)


def test_cjis_not_resource_star_in_list_grants_nothing():
    """A NotResource list that includes "*" still excludes every resource."""
    policy = {
        "Statement": [
            {
                "Sid": "NotResourceStarInList",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": ["*", "arn:aws:s3:::backups/*"]
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert findings == []


def test_cjis_deny_not_resource_skipped():
    """Deny with NotResource should stay outside the CJIS grant checks."""
    policy = {
        "Statement": [
            {
                "Sid": "DenyNotResource",
                "Effect": "Deny",
                "Action": "s3:*",
                "NotResource": "arn:aws:s3:::backups/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert findings == []


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


# --- CJI pattern matching tests ---

def test_cjis_criminal_underscore_matched():
    """criminal_justice naming convention should trigger CJIS checks."""
    policy = {
        "Statement": [
            {
                "Sid": "Underscore",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::criminal_justice_records/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "cji_missing_mfa" for f in findings)


def test_cjis_cj_data_matched():
    """cj-data naming convention should trigger CJIS checks."""
    policy = {
        "Statement": [
            {
                "Sid": "CJData",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cj-data-bucket/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "cji_missing_mfa" for f in findings)


def test_cjis_cj_info_matched():
    """cj-info naming convention should trigger CJIS checks."""
    policy = {
        "Statement": [
            {
                "Sid": "CJInfo",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cj-info-store/*"
            }
        ]
    }
    findings = check_cjis_policy(policy)
    assert any(f["type"] == "cji_missing_mfa" for f in findings)


def test_cjis_custom_patterns_override_defaults():
    """Custom patterns should replace defaults, not extend them."""
    policy = {
        "Statement": [
            {
                "Sid": "CustomMatch",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::secret-records/*"
            }
        ]
    }
    # "cji" default would NOT match "secret-records", but custom pattern does
    findings = check_cjis_policy(policy, cji_patterns=["secret-records"])
    assert any(f["type"] == "cji_missing_mfa" for f in findings)


def test_cjis_custom_patterns_skip_default_match():
    """When custom patterns are set, default patterns should not match."""
    policy = {
        "Statement": [
            {
                "Sid": "DefaultNoMatch",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*"
            }
        ]
    }
    # Custom pattern does not include "cji", so this should NOT trigger
    findings = check_cjis_policy(policy, cji_patterns=["secret-records"])
    assert len(findings) == 0


def test_cjis_regex_pattern_supported():
    """Regex patterns should work for flexible matching."""
    policy = {
        "Statement": [
            {
                "Sid": "RegexMatch",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::law-enforcement-2024/*"
            }
        ]
    }
    findings = check_cjis_policy(policy, cji_patterns=["law-enforcement-\\d+"])
    assert any(f["type"] == "cji_missing_mfa" for f in findings)


def _cji_only_policy(tmp_path):
    policy = {
        "Statement": [
            {
                "Sid": "CJIAccessNoMFA",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::cji-data-bucket/*",
            }
        ]
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return policy_path


def _run_checker(policy_path, *extra):
    script = Path(__file__).resolve().parents[1] / "policy_checker.py"
    return subprocess.run(
        [sys.executable, str(script), str(policy_path), *extra],
        capture_output=True,
        text=True,
    )


def test_cli_rejects_empty_cji_patterns_list(tmp_path):
    policy_path = _cji_only_policy(tmp_path)
    patterns_path = tmp_path / "patterns.json"
    patterns_path.write_text("[]\n", encoding="utf-8")

    bare = _run_checker(policy_path)
    assert bare.returncode == 1
    assert "CJI resource access without MFA" in bare.stdout

    empty = _run_checker(policy_path, "--cji-patterns", str(patterns_path))
    assert empty.returncode == 2
    assert empty.stderr.strip() == (
        "CJI patterns file must contain at least one pattern."
    )
    assert "0 issues found" not in empty.stdout


def test_cli_cji_patterns_list_still_runs_checks(tmp_path):
    policy_path = _cji_only_policy(tmp_path)
    patterns_path = tmp_path / "patterns.json"
    patterns_path.write_text(json.dumps(["cji"]), encoding="utf-8")

    result = _run_checker(policy_path, "--cji-patterns", str(patterns_path))
    assert result.returncode == 1
    assert "CJI resource access without MFA" in result.stdout
    assert result.stderr == ""


def _run_cji_patterns(tmp_path, patterns_json):
    patterns = tmp_path / "patterns.json"
    patterns.write_text(patterns_json, encoding="utf-8")
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"Version":"2012-10-17","Statement":[]}',
        encoding="utf-8",
    )
    checker = Path(__file__).resolve().parents[1] / "policy_checker.py"
    return subprocess.run(
        [
            sys.executable,
            str(checker),
            str(policy),
            "--cji-patterns",
            str(patterns),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cji_patterns_rejects_non_string_element(tmp_path):
    result = _run_cji_patterns(tmp_path, "[123]")
    assert result.returncode == 2
    assert result.stderr.strip() == (
        "CJI pattern at index 0 must be a string (got int)."
    )
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr


def test_cji_patterns_rejects_non_string_at_later_index(tmp_path):
    result = _run_cji_patterns(tmp_path, '["cji", null]')
    assert result.returncode == 2
    assert result.stderr.strip() == (
        "CJI pattern at index 1 must be a string (got NoneType)."
    )


def test_cji_patterns_rejects_empty_string(tmp_path):
    """An empty pattern string exits 2 instead of matching every ARN."""
    result = _run_cji_patterns(tmp_path, '[""]')
    assert result.returncode == 2
    assert result.stderr.strip() == (
        "CJI pattern at index 0 must be a non-empty string."
    )
    assert "Traceback" not in result.stderr


def test_invalid_cji_pattern_exits_2(tmp_path):
    """A bad --cji-patterns regex is an input error and names that pattern."""
    result = _run_cji_patterns(tmp_path, '["cji", "[invalid("]')
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert "index 1" in result.stderr
    assert "[invalid(" in result.stderr


def _assert_patterns_file_error(result, path):
    assert result.returncode == 2
    assert str(path) in result.stderr
    assert "Traceback" not in result.stderr


def test_cji_patterns_unreadable_file(tmp_path):
    """An unreadable --cji-patterns file exits 2 with a stderr message."""
    policy_path = _cji_only_policy(tmp_path)
    patterns_path = tmp_path / "patterns.json"
    patterns_path.write_text('["cji"]', encoding="utf-8")
    patterns_path.chmod(0)
    try:
        with open(patterns_path, encoding="utf-8"):
            pytest.skip("this process can read a mode-000 file")
    except PermissionError:
        pass
    result = _run_checker(policy_path, "--cji-patterns", str(patterns_path))
    _assert_patterns_file_error(result, patterns_path)


def test_cji_patterns_directory(tmp_path):
    """A directory passed to --cji-patterns exits 2 with a stderr message."""
    policy_path = _cji_only_policy(tmp_path)
    result = _run_checker(policy_path, "--cji-patterns", str(tmp_path))
    _assert_patterns_file_error(result, tmp_path)


def test_cji_patterns_undecodable_file(tmp_path):
    """A non-UTF-8 --cji-patterns file exits 2 with a stderr message."""
    policy_path = _cji_only_policy(tmp_path)
    patterns_path = tmp_path / "patterns.json"
    patterns_path.write_bytes(b"\xff\xfe")
    result = _run_checker(policy_path, "--cji-patterns", str(patterns_path))
    _assert_patterns_file_error(result, patterns_path)
