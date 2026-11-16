"""Deterministic account ranking with evidence attached to every signal."""

import re
from collections.abc import Mapping
from typing import Any

INCIDENT_TERMS = (
    "ransomware",
    "data breach",
    "security breach",
    "data leak",
    "cyber attack",
    "security incident",
    "compromised",
)
EXPOSURE_TERMS = (
    "unpatched",
    "end of life",
    "end-of-life",
    "known vulnerability",
    "exposed database",
    "cve-",
    "critical vulnerability",
)
HIRING_TERMS = (
    "security engineer",
    "cybersecurity analyst",
    "information security",
    "security operations",
    "chief information security",
)
COMPLIANCE_TERMS = ("hipaa", "pci dss", "gdpr", "iso 27001", "soc 2", "fedramp")
TARGET_INDUSTRY_TERMS = (
    "finance",
    "financial",
    "bank",
    "insurance",
    "health",
    "medical",
    "software",
    "technology",
)
DATABASE_PORTS = {
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    9042: "Cassandra",
    9160: "Cassandra",
    9200: "Elasticsearch/OpenSearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
    28017: "MongoDB",
}
CONTROL_PLANE_PORTS = {
    2375: "Docker API",
    2379: "etcd",
    2380: "etcd",
    6443: "Kubernetes API",
    10250: "Kubelet",
    10255: "Kubelet",
    10257: "Kubernetes controller manager",
    10259: "Kubernetes scheduler",
}


def _text(value: Any) -> str:
    """Flatten simple nested values so signals can be found in flexible schemas."""
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return " ".join(f"{key} {_text(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_text(item) for item in value)
    return str(value)


def _snippet(value: str, term: str) -> str:
    """Return a short, readable evidence excerpt rather than the whole source cell."""
    position = value.casefold().find(term.casefold())
    if position < 0:
        return value[:180]
    start = max(0, position - 55)
    return value[start : start + 180].strip()


def _shodan_vulnerabilities(
    value: Any,
) -> list[tuple[str, Mapping[str, Any]]]:
    if isinstance(value, Mapping):
        return [
            (str(identifier), details if isinstance(details, Mapping) else {})
            for identifier, details in value.items()
        ]
    if isinstance(value, (list, tuple, set)):
        identifiers = sorted(value, key=str) if isinstance(value, set) else value
        return [(str(identifier), {}) for identifier in identifiers]
    return []


def _numeric_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _cve_list(identifiers: list[str]) -> str:
    shown = ", ".join(identifiers[:3])
    remaining = len(identifiers) - 3
    if remaining > 0:
        shown += f", and {remaining} more"
    return shown


def score_account(
    attributes: Mapping[str, Any],
    industry: str | None = None,
    employee_count: int | None = None,
) -> tuple[int, str, list[dict[str, Any]]]:
    """Return an explainable priority score, tier, and the supporting signals.

    This is a prioritization heuristic, not a probability that an account will buy.
    """
    signals: list[dict[str, Any]] = []
    is_shodan_record = bool({"ip_str", "_shodan", "hostnames"} & attributes.keys())
    searchable_fields = (
        []
        if is_shodan_record
        else [
            (str(key), _text(value))
            for key, value in attributes.items()
            if value is not None and _text(value).strip()
        ]
    )

    # Incident and exposure signals carry the most weight because they indicate urgency.
    categories = (
        ("incident", "Recent security incident", INCIDENT_TERMS, 35),
        ("exposure", "Potential security exposure", EXPOSURE_TERMS, 25),
        ("security_hiring", "Security team hiring", HIRING_TERMS, 20),
        ("compliance", "Regulatory or compliance exposure", COMPLIANCE_TERMS, 10),
    )
    for category, title, terms, points in (
        categories if not is_shodan_record else ()
    ):
        for field, value in searchable_fields:
            match = next((term for term in terms if term in value.casefold()), None)
            if match:
                signals.append(
                    {
                        "category": category,
                        "title": title,
                        "points": points,
                        "evidence": f"{field}: {_snippet(value, match)}",
                    }
                )
                break

    if is_shodan_record:
        raw_tags = attributes.get("tags")
        if isinstance(raw_tags, str):
            tags = {raw_tags.casefold()}
        elif isinstance(raw_tags, (list, tuple, set)):
            tags = {str(tag).casefold() for tag in raw_tags}
        else:
            tags = set()

        if "honeypot" in tags:
            signals.append(
                {
                    "category": "data_quality",
                    "title": "Possible honeypot or decoy",
                    "points": 0,
                    "evidence": (
                        "Shodan tagged this endpoint as a honeypot. Its service and "
                        "vulnerability findings are excluded from prospect scoring."
                    ),
                }
            )
        else:
            technical_signals: list[dict[str, Any]] = []
            vulnerabilities = _shodan_vulnerabilities(attributes.get("vulns"))
            vulnerability_ids = [identifier for identifier, _ in vulnerabilities]
            if vulnerabilities:
                cvss_scores: list[float] = []
                for _, details in vulnerabilities:
                    try:
                        cvss = float(details.get("cvss"))
                    except (TypeError, ValueError):
                        continue
                    if 0 <= cvss <= 10:
                        cvss_scores.append(cvss)
                highest_cvss = max(cvss_scores, default=None)
                vulnerability_points = (
                    35
                    if highest_cvss is not None and highest_cvss >= 9
                    else 30
                    if highest_cvss is not None and highest_cvss >= 7
                    else 25
                )
                cvss_evidence = (
                    f"; highest CVSS {highest_cvss:.1f}" if highest_cvss is not None else ""
                )
                technical_signals.append(
                    {
                        "category": "shodan_vulnerability",
                        "title": "Shodan-listed vulnerability findings",
                        "points": vulnerability_points,
                        "evidence": (
                            f"Shodan lists {len(vulnerabilities)} CVE(s){cvss_evidence}: "
                            f"{_cve_list(vulnerability_ids)}. Verify the affected product, "
                            "version, and current exposure before outreach."
                        ),
                    }
                )

                kev_ids = [
                    identifier
                    for identifier, details in vulnerabilities
                    if details.get("kev") is True
                ]
                if kev_ids:
                    technical_signals.append(
                        {
                            "category": "shodan_kev",
                            "title": "Known-exploited vulnerability indicator",
                            "points": 20,
                            "evidence": (
                                f"Shodan marks {len(kev_ids)} CVE(s) as known exploited: "
                                f"{_cve_list(kev_ids)}."
                            ),
                        }
                    )

                ransomware_ids = [
                    identifier
                    for identifier, details in vulnerabilities
                    if str(details.get("ransomware_campaign", "")).casefold()
                    == "known"
                ]
                if ransomware_ids:
                    technical_signals.append(
                        {
                            "category": "shodan_ransomware",
                            "title": "Vulnerability linked to ransomware campaigns",
                            "points": 15,
                            "evidence": (
                                f"Shodan marks {len(ransomware_ids)} CVE(s) as associated "
                                f"with a known ransomware campaign: "
                                f"{_cve_list(ransomware_ids)}. This does not mean the "
                                "company was attacked."
                            ),
                        }
                    )

                verified_ids = [
                    identifier
                    for identifier, details in vulnerabilities
                    if details.get("verified") is True
                ]
                if verified_ids:
                    technical_signals.append(
                        {
                            "category": "shodan_verified",
                            "title": "Shodan marks vulnerability findings verified",
                            "points": 10,
                            "evidence": (
                                f"Shodan marks {len(verified_ids)} CVE finding(s) verified: "
                                f"{_cve_list(verified_ids)}. Recheck the live asset."
                            ),
                        }
                    )

            if "eol-product" in tags:
                product = " ".join(
                    str(value)
                    for value in (attributes.get("product"), attributes.get("version"))
                    if value
                )
                evidence = "Shodan tagged the observed product as end-of-life."
                if product:
                    evidence += f" Fingerprint: {product[:100]}."
                technical_signals.append(
                    {
                        "category": "shodan_eol",
                        "title": "End-of-life product tag",
                        "points": 20,
                        "evidence": evidence,
                    }
                )

            port = _numeric_port(attributes.get("port"))
            transport = str(attributes.get("transport") or "unknown").upper()
            if port in CONTROL_PLANE_PORTS:
                technical_signals.append(
                    {
                        "category": "shodan_exposure",
                        "title": "Container or orchestration control plane exposed",
                        "points": 20,
                        "evidence": (
                            f"Shodan observed {CONTROL_PLANE_PORTS[port]} on "
                            f"{transport} port {port}; confirm it is intended to be public."
                        ),
                    }
                )
            elif port in DATABASE_PORTS:
                technical_signals.append(
                    {
                        "category": "shodan_database_exposure",
                        "title": "Database service reachable from the internet",
                        "points": 18,
                        "evidence": (
                            f"Shodan observed {DATABASE_PORTS[port]} on {transport} "
                            f"port {port}; reachability alone does not prove data access."
                        ),
                    }
                )
            elif port in {3389} or port is not None and 5800 <= port <= 5999:
                technical_signals.append(
                    {
                        "category": "shodan_exposure",
                        "title": "Remote desktop service publicly reachable",
                        "points": 20,
                        "evidence": (
                            f"Shodan observed a remote desktop service on {transport} "
                            f"port {port}; verify access controls and ownership."
                        ),
                    }
                )
            elif port == 22:
                technical_signals.append(
                    {
                        "category": "shodan_exposure",
                        "title": "SSH service publicly reachable",
                        "points": 8,
                        "evidence": (
                            "Shodan observed SSH on port 22. Internet reachability is "
                            "common and is not, by itself, evidence of weak security."
                        ),
                    }
                )
            elif port in {21, 23, 69, 512, 513, 514}:
                technical_signals.append(
                    {
                        "category": "shodan_exposure",
                        "title": "Legacy or clear-text service publicly reachable",
                        "points": 18,
                        "evidence": (
                            f"Shodan observed a legacy service on {transport} port {port}; "
                            "confirm whether it is still needed and protected."
                        ),
                    }
                )
            elif port in {161, 162}:
                technical_signals.append(
                    {
                        "category": "shodan_exposure",
                        "title": "SNMP network-management service exposed",
                        "points": 12,
                        "evidence": (
                            f"Shodan observed SNMP on {transport} port {port}; "
                            "review public reachability and community/access settings."
                        ),
                    }
                )
            elif port == 445:
                technical_signals.append(
                    {
                        "category": "shodan_exposure",
                        "title": "SMB file-sharing service publicly reachable",
                        "points": 15,
                        "evidence": (
                            "Shodan observed SMB on port 445; verify public access is "
                            "intentional and appropriately restricted."
                        ),
                    }
                )
            elif port is not None:
                is_web_port = port in {80, 443, 8080, 8443}
                web_points = 1 if tags & {"cdn", "cloud"} else 2
                technical_signals.append(
                    {
                        "category": "shodan_exposure",
                        "title": "Public web service observed"
                        if is_web_port
                        else "Public service observed",
                        "points": web_points if is_web_port else 5,
                        "evidence": (
                            (
                                f"Shodan observed a service on {transport} port {port}. "
                                "Ordinary public web access is a weak risk signal on its own."
                            )
                            if is_web_port
                            else (
                                f"Shodan observed a service on {transport} port {port}; "
                                "verify the service identity and access controls."
                            )
                        ),
                    }
                )

            if "database" in tags and (port is None or port not in DATABASE_PORTS):
                technical_signals.append(
                    {
                        "category": "shodan_database_exposure",
                        "title": "Shodan tagged the endpoint as database-related",
                        "points": 15,
                        "evidence": "Shodan tag: database. Verify the service and its access controls.",
                    }
                )
            if "vpn" in tags:
                technical_signals.append(
                    {
                        "category": "shodan_exposure",
                        "title": "VPN service fingerprint observed",
                        "points": 8,
                        "evidence": "Shodan tagged this endpoint as VPN-related; review remote-access controls.",
                    }
                )
            if "devops" in tags:
                technical_signals.append(
                    {
                        "category": "shodan_exposure",
                        "title": "DevOps-related service fingerprint observed",
                        "points": 12,
                        "evidence": "Shodan tagged this endpoint as DevOps-related; verify whether its interface should be public.",
                    }
                )
            ssl_data = attributes.get("ssl")
            certificate = (
                ssl_data.get("cert") if isinstance(ssl_data, Mapping) else None
            )
            ssl_versions = (
                ssl_data.get("versions") if isinstance(ssl_data, Mapping) else None
            )
            legacy_tls = {
                str(version)
                for version in (ssl_versions if isinstance(ssl_versions, list) else [])
                if str(version).casefold()
                in {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}
            }
            if legacy_tls:
                technical_signals.append(
                    {
                        "category": "shodan_tls",
                        "title": "Legacy TLS protocol supported",
                        "points": 15,
                        "evidence": (
                            "Shodan observed legacy protocol support: "
                            f"{', '.join(sorted(legacy_tls))}. Review current TLS configuration."
                        ),
                    }
                )
            if isinstance(certificate, Mapping) and certificate.get("expired") is True:
                technical_signals.append(
                    {
                        "category": "shodan_tls",
                        "title": "Expired TLS certificate observed",
                        "points": 12,
                        "evidence": (
                            "Shodan's certificate record marks the TLS certificate "
                            "expired; recheck current certificate status."
                        ),
                    }
                )
            if "self-signed" in tags:
                technical_signals.append(
                    {
                        "category": "shodan_tls",
                        "title": "Self-signed certificate tag",
                        "points": 3,
                        "evidence": (
                            "Shodan tagged the certificate as self-signed. This can be "
                            "intentional and needs verification."
                        ),
                    }
                )

            provider_tagged = bool(tags & {"cdn", "cloud"})
            if provider_tagged:
                for signal in technical_signals:
                    signal["points"] = max(1, (signal["points"] * 3 + 2) // 5)
                signals.append(
                    {
                        "category": "data_quality",
                        "title": "Cloud or CDN attribution needs verification",
                        "points": 0,
                        "evidence": (
                            "Shodan tagged this endpoint as cloud/CDN-hosted. Confirm "
                            "that the exposed service belongs to the prospect, not a provider."
                        ),
                    }
                )
            signals.extend(technical_signals)

    industry_text = (industry or "").casefold()
    industry_match = next(
        (term for term in TARGET_INDUSTRY_TERMS if term in industry_text), None
    )
    if industry_match:
        signals.append(
            {
                "category": "industry_fit",
                "title": "Higher-risk industry",
                "points": 10,
                "evidence": f"Industry: {industry}",
            }
        )

    if employee_count is not None and 50 <= employee_count <= 10_000:
        signals.append(
            {
                "category": "company_size",
                "title": "Target company size",
                "points": 8,
                "evidence": f"Employee count: {employee_count:,}",
            }
        )

    signals.sort(key=lambda signal: signal["points"], reverse=True)
    if is_shodan_record and signals and attributes.get("timestamp"):
        signals[0]["evidence"] += (
            f" Shodan observation timestamp: {str(attributes['timestamp'])[:40]}."
        )

    # Cap the additive score while preserving the ordered, human-readable evidence.
    score = min(100, sum(signal["points"] for signal in signals))
    tier = "high" if score >= 60 else "medium" if score >= 35 else "low"
    return score, tier, signals


def parse_employee_count(value: Any) -> int | None:
    """Extract a representative lower-bound count from common employee ranges."""
    match = re.search(r"\d[\d,]*", str(value or ""))
    if not match:
        return None
    try:
        return int(match.group().replace(",", ""))
    except ValueError:
        return None
