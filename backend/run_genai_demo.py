"""
run_genai_demo.py
-----------------
Standalone demo: executes both GenAI modules against live Gemini API
using sample Indian banking incident test cases and prints formatted output.

Run from backend/ directory:
    python -X utf8 run_genai_demo.py
"""

import sys, os, io, json, logging, textwrap

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s - %(message)s")

SEP  = "=" * 68
SEP2 = "-" * 68

def banner(t):  print(f"\n{SEP}\n  {t}\n{SEP}")
def section(t): print(f"\n  {SEP2}\n  {t}\n  {SEP2}")

def show(label, text, width=100):
    print(f"\n  [{label}]")
    for line in text.splitlines():
        wrapped = textwrap.fill(line, width=width, subsequent_indent="    ")
        print(f"    {wrapped}" if wrapped else "")

# ══════════════════════════════════════════════════════════════════════════════
# TEST DATA — Indian Banking Incident Scenarios
# ══════════════════════════════════════════════════════════════════════════════

BANKING_CVES = [
    {
        "cveId":       "CVE-2026-1043",
        "description": "Remote Code Execution in Web Application Gateway allows unauthenticated attackers to execute arbitrary OS commands via crafted HTTP multipart requests.",
        "cvssScore":   9.8,
        "severity":    "CRITICAL",
        "epssScore":   0.9452,
        "isKEV":       True,
    },
    {
        "cveId":       "CVE-2026-2090",
        "description": "SQL Injection in Core Banking Authentication Module allows remote authenticated attackers to bypass multi-factor verification and gain privileged access.",
        "cvssScore":   8.1,
        "severity":    "HIGH",
        "epssScore":   0.7812,
        "isKEV":       False,
    },
]

BANKING_ASSETS = {
    "CVE-2026-1043": ["Web Application Gateway", "Edge Firewall Router"],
    "CVE-2026-2090": ["Authentication Service", "Core Database Cluster"],
}

BANKING_TECHNIQUES = [
    {
        "techniqueId": "T1190",
        "name":        "Exploit Public-Facing Application",
        "tactic":      "Initial Access",
        "capecId":     "CAPEC-242",
        "capecName":   "Connection Reset",
    },
    {
        "techniqueId": "T1110",
        "name":        "Brute Force / Authentication Bypass",
        "tactic":      "Credential Access",
        "capecId":     "CAPEC-109",
        "capecName":   "SQL Injection",
    },
]

BANKING_INCIDENTS = [
    {
        "incidentId":     "INC-20260520-001",
        "attackType":     "APT Lateral Movement — Core Banking Breach Attempt",
        "affectedAssets": ["Web Application Gateway", "Authentication Service", "Core Database Cluster"],
        "attackVector":   "T1190 - Exploit Public-Facing Application → T1021 - Remote Services",
        "timestamp":      "2026-05-20T14:32:00+05:30",
        "detectionTime":  "2026-05-20T14:47:00+05:30  (15 min dwell time)",
    },
    {
        "incidentId":     "INC-20260520-002",
        "attackType":     "SQL Injection → Credential Dump → Privilege Escalation",
        "affectedAssets": ["Authentication Service", "Core Database Cluster"],
        "attackVector":   "T1110 - Brute Force / SQL Injection against /api/v1/auth",
        "timestamp":      "2026-05-20T22:05:00+05:30",
        "detectionTime":  "2026-05-20T22:09:00+05:30  (4 min dwell time)",
    },
]

BANKING_ALERTS = [
    {
        "id":          "alert_01",
        "severity":    "CRITICAL",
        "asset_id":    "Asset_1",
        "message":     "External port sweep targeting web gateway — 450 SYN packets from 185.220.101.42",
        "cve_id":      "CVE-2026-1043",
        "technique_id":"T1190",
        "timestamp":   "2026-05-20T14:32:00+05:30",
    },
    {
        "id":          "alert_02",
        "severity":    "HIGH",
        "asset_id":    "Asset_2",
        "message":     "Abnormal auth failure rate: 847 failed MFA attempts in 2 minutes on /api/v1/auth",
        "cve_id":      "CVE-2026-2090",
        "technique_id":"T1110",
        "timestamp":   "2026-05-20T22:05:00+05:30",
    },
]


def main():
    from genai.playbook_gen import PlaybookGenerator
    from genai.rca_gen import RCAGenerator
    from config import settings

    playbook_engine = PlaybookGenerator()
    rca_engine      = RCAGenerator()

    gemini_on = playbook_engine.enabled
    mode_tag  = "[LIVE Gemini API]" if gemini_on else "[FALLBACK MODE — no API key]"

    banner(f"Sarathi Cyberdefense — GenAI Module Demo  {mode_tag}")
    print(f"\n  GEMINI_API_KEY present : {gemini_on}")
    print(f"  Model                  : {playbook_engine.model_name}")
    print(f"  Temperature / top_p    : 0.2 / 0.8")

    # ══════════════════════════════════════════════════════════════════════════
    # PART 1 — PlaybookGenerator
    # ══════════════════════════════════════════════════════════════════════════
    banner("PART 1 — PlaybookGenerator")

    for cve in BANKING_CVES:
        assets = BANKING_ASSETS[cve["cveId"]]
        section(f"1a. generate_remediation_playbook() — {cve['cveId']} ({cve['severity']})")
        print(f"\n  Assets: {', '.join(assets)}")
        print(f"  CVSS: {cve['cvssScore']}  |  EPSS: {cve['epssScore']}  |  KEV: {cve['isKEV']}")
        print(f"  Calling Gemini … (may take 5-15 seconds)")

        result = playbook_engine.generate_remediation_playbook(
            cve_data=cve,
            affected_assets=assets,
        )

        print(f"\n  Generated at : {result['generatedAt']}")
        print(f"  Raw length   : {len(result['rawResponse'])} chars\n")

        for field in ("executiveSummary", "immediateActions", "shortTermRemediation",
                      "longTermHardening", "verificationSteps", "rollbackPlan", "complianceNotes"):
            val = result.get(field, "")
            if val:
                preview = val[:300] + ("…" if len(val) > 300 else "")
                show(field, preview)

        print()

    # Security policy
    section("1b. generate_security_policy() — T1190: Exploit Public-Facing Application")
    tech = BANKING_TECHNIQUES[0]
    print(f"\n  Calling Gemini …")
    policy = playbook_engine.generate_security_policy(tech)
    show("securityPolicy", policy[:600] + ("…" if len(policy) > 600 else ""))

    # ══════════════════════════════════════════════════════════════════════════
    # PART 2 — RCAGenerator
    # ══════════════════════════════════════════════════════════════════════════
    banner("PART 2 — RCAGenerator")

    for incident in BANKING_INCIDENTS:
        section(f"2a. generate_rca_report() — {incident['incidentId']}")
        print(f"\n  Attack Type   : {incident['attackType']}")
        print(f"  Assets        : {', '.join(incident['affectedAssets'])}")
        print(f"  Detection Gap : {incident['timestamp']}  →  {incident['detectionTime']}")
        print(f"\n  Calling Gemini …")

        result = rca_engine.generate_rca_report(incident)

        print(f"\n  Incident ID  : {result['incidentId']}")
        print(f"  Raw length   : {len(result['rawResponse'])} chars\n")

        for field in ("executiveSummary", "timeline", "rootCause",
                      "contributingFactors", "immediateImpact",
                      "lessonLearned", "preventionMeasures"):
            val = result.get(field, "")
            if val:
                preview = val[:280] + ("…" if len(val) > 280 else "")
                show(field, preview)
        print()

    # SOC IR Drafts
    section("2b. generate_incident_response_draft() — real-time alert drafts")
    for alert in BANKING_ALERTS:
        print(f"\n  Alert: {alert['id']}  |  {alert['severity']}  |  {alert['asset_id']}")
        print(f"  Calling Gemini …")
        draft = rca_engine.generate_incident_response_draft(alert)
        show("irDraft", draft[:500] + ("…" if len(draft) > 500 else ""))

    # ══════════════════════════════════════════════════════════════════════════
    # PART 3 — Sample API response shapes
    # ══════════════════════════════════════════════════════════════════════════
    banner("PART 3 — Sample API Response Shapes")

    section("POST /api/playbooks/remediation  →  first CVE playbook (fields only)")
    result = playbook_engine.generate_remediation_playbook(
        cve_data=BANKING_CVES[0],
        affected_assets=BANKING_ASSETS[BANKING_CVES[0]["cveId"]],
    )
    sample = {k: v[:120] + "…" if isinstance(v, str) and len(v) > 120 else v
              for k, v in result.items() if k != "rawResponse"}
    print(json.dumps(sample, indent=4))

    section("POST /api/playbooks/rca  →  first incident (fields only)")
    rca = rca_engine.generate_rca_report(BANKING_INCIDENTS[0])
    rca_sample = {k: v[:120] + "…" if isinstance(v, str) and len(v) > 120 else v
                  for k, v in rca.items() if k != "rawResponse"}
    print(json.dumps(rca_sample, indent=4))

    print(f"\n{SEP}")
    print("  Demo complete.")
    print(SEP + "\n")


if __name__ == "__main__":
    main()
