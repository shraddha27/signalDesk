from app.scoring import parse_employee_count, score_account


def test_score_explains_observed_security_evidence():
    score, tier, signals = score_account(
        {
            "news": "The company disclosed a ransomware incident last quarter.",
            "certifications": "SOC 2 and HIPAA",
        },
        industry="Healthcare",
        employee_count=250,
    )

    assert score == 63
    assert tier == "high"
    assert [signal["category"] for signal in signals] == [
        "incident",
        "compliance",
        "industry_fit",
        "company_size",
    ]
    assert "ransomware" in signals[0]["evidence"].lower()


def test_score_does_not_infer_urgency_without_evidence():
    score, tier, signals = score_account({"company_name": "Northwind"}, "Retail", 12)

    assert score == 0
    assert tier == "low"
    assert signals == []


def test_score_is_capped_and_employee_ranges_parse():
    score, tier, _ = score_account(
        {
            "incident": "Data breach",
            "vulnerability": "Critical vulnerability, unpatched",
            "jobs": "Hiring a security engineer",
            "compliance": "GDPR",
        },
        industry="Financial services",
        employee_count=500,
    )

    assert score == 100
    assert tier == "high"
    assert parse_employee_count("1,001-5,000 employees") == 1001
    assert parse_employee_count("not available") is None


def test_shodan_records_get_explainable_exposure_and_vulnerability_signals():
    score, tier, signals = score_account(
        {
            "_shodan": {"module": "https"},
            "hostnames": ["web.example.org"],
            "port": 443,
            "transport": "tcp",
            "vulns": {"CVE-2026-1234": {}, "CVE-2026-5678": {}},
            "data": "The response body mentions a ransomware incident.",
        }
    )

    assert score == 27
    assert tier == "low"
    assert [signal["category"] for signal in signals] == [
        "shodan_vulnerability",
        "shodan_exposure",
    ]
    assert "CVE-2026-1234" in signals[0]["evidence"]
    assert "port 443" in signals[1]["evidence"]


def test_shodan_score_uses_severity_exploitation_and_product_lifecycle_evidence():
    score, tier, signals = score_account(
        {
            "_shodan": {"module": "https"},
            "ip_str": "203.0.113.8",
            "port": 3389,
            "tags": ["eol-product"],
            "product": "Example Server",
            "version": "1.0",
            "vulns": {
                "CVE-2026-1000": {
                    "cvss": 9.8,
                    "kev": True,
                    "ransomware_campaign": "Known",
                    "verified": True,
                }
            },
        }
    )

    assert score == 100
    assert tier == "high"
    assert [signal["category"] for signal in signals] == [
        "shodan_vulnerability",
        "shodan_kev",
        "shodan_eol",
        "shodan_exposure",
        "shodan_ransomware",
        "shodan_verified",
    ]
    assert "highest CVSS 9.8" in signals[0]["evidence"]
    assert "does not mean the company was attacked" in signals[4]["evidence"]


def test_shodan_downweights_cloud_attribution_and_excludes_honeypots():
    cloud_score, _, cloud_signals = score_account(
        {
            "_shodan": {"module": "https"},
            "port": 443,
            "tags": ["cloud"],
            "vulns": {"CVE-2026-1000": {"cvss": 9.8}},
        }
    )
    honeypot_score, _, honeypot_signals = score_account(
        {
            "_shodan": {"module": "https"},
            "port": 3389,
            "tags": ["honeypot"],
            "vulns": {"CVE-2026-1000": {"cvss": 9.8, "kev": True}},
        }
    )

    assert cloud_score == 22
    assert cloud_signals[0]["category"] == "shodan_vulnerability"
    assert any(signal["category"] == "data_quality" for signal in cloud_signals)
    assert honeypot_score == 0
    assert [signal["category"] for signal in honeypot_signals] == ["data_quality"]


def test_shodan_identifies_public_database_and_expired_certificate():
    score, _, signals = score_account(
        {
            "_shodan": {"module": "mongodb"},
            "port": 27017,
            "ssl": {"cert": {"expired": True}},
        }
    )

    assert score == 30
    assert [signal["category"] for signal in signals] == [
        "shodan_database_exposure",
        "shodan_tls",
    ]
    assert "MongoDB" in signals[0]["evidence"]


def test_shodan_scores_enabled_legacy_tls_but_ignores_disabled_versions():
    score, _, signals = score_account(
        {
            "_shodan": {"module": "https"},
            "port": 443,
            "timestamp": "2026-11-10T04:32:20.000000",
            "ssl": {"versions": ["-SSLv3", "-TLSv1.2", "TLSv1.1"]},
        }
    )
    disabled_score, _, disabled_signals = score_account(
        {
            "_shodan": {"module": "https"},
            "port": 443,
            "ssl": {"versions": ["-TLSv1.0", "TLSv1.2"]},
        }
    )

    assert score == 17
    assert signals[0]["category"] == "shodan_tls"
    assert "TLSv1.1" in signals[0]["evidence"]
    assert "2026-11-10T04:32:20" in signals[0]["evidence"]
    assert disabled_score == 2
    assert [signal["category"] for signal in disabled_signals] == [
        "shodan_exposure"
    ]
