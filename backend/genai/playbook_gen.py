"""
genai/playbook_gen.py
---------------------
Gemini-powered remediation playbook generator for Sarathi Cyberdefense.

Design decisions
----------------
- Uses gemini-3.5-flash with deterministic settings (temp=0.2, top_p=0.8).
- Retry logic: up to 3 attempts with exponential back-off for rate-limit /
  transient errors.  Non-retryable errors fall back immediately.
- Raw LLM text is always preserved in `rawResponse` for audit purposes.
- Section parser is whitespace/case-insensitive and strips fenced code blocks
  and Markdown artifacts before extraction.
- Both `generate_remediation_playbook()` (new structured API) and
  `generate_mitigation_playbook()` (old string-returning API used by routes)
  are exposed for full backwards compatibility.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import google.generativeai as genai
from google.generativeai.types import GenerationConfig

from config import settings

logger = logging.getLogger("sarathi.playbook_gen")

# ── Gemini knobs ───────────────────────────────────────────────────────────────
_MODEL_NAME       = "gemini-3.5-flash"
_TEMPERATURE      = 0.2
_TOP_P            = 0.8
_MAX_OUTPUT_TOKENS = 4096

# ── Retry policy ───────────────────────────────────────────────────────────────
_MAX_RETRIES    = 3
_RETRY_BASE_SEC = 2.0      # doubles each attempt: 2 → 4 → 8

# ── Section headings expected in the model output ─────────────────────────────
_SECTIONS = [
    ("executiveSummary",       ["1. executive summary", "executive summary"]),
    ("validation",             ["2. validation", "validation: is this real?", "validation: is this real"]),
    ("containment",            ["3. containment", "containment: stop the threat"]),
    ("eradicationRemediation", ["4. eradication", "eradication & remediation"]),
    ("postIncidentHunting",    ["5. post-incident hunting", "post-incident hunting"]),
]

class PlaybookGenerator:
    """
    Generates structured, banking-context remediation playbooks using Gemini.
    """

    def __init__(self) -> None:
        self.api_key = settings.GEMINI_API_KEY
        self.enabled = bool(self.api_key)
        self.model_name = _MODEL_NAME
        if self.enabled:
            genai.configure(api_key=self.api_key)
            self._init_model()
            logger.info("PlaybookGenerator initialised with model %s.", self.model_name)
        else:
            logger.warning("GEMINI_API_KEY missing — PlaybookGenerator in fallback mode.")

    def _init_model(self) -> None:
        self._model = genai.GenerativeModel(
            model_name=self.model_name,
            generation_config=GenerationConfig(
                temperature=_TEMPERATURE,
                top_p=_TOP_P,
                max_output_tokens=_MAX_OUTPUT_TOKENS,
            ),
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Primary public method (new structured API)
    # ──────────────────────────────────────────────────────────────────────────

    def generate_remediation_playbook(
        self,
        cve_data:        dict[str, Any],
        affected_assets: list[str],
    ) -> dict[str, Any]:
        """
        Generate a structured, section-parsed remediation playbook.

        Parameters
        ----------
        cve_data : dict
            Keys: cveId, description, cvssScore, severity, epssScore, isKEV
        affected_assets : list[str]
            Human-readable asset names (e.g. ["Web Application Gateway"])

        Returns
        -------
        dict with keys:
            cveId, generatedAt, executiveSummary, validation, containment,
            eradicationRemediation, postIncidentHunting, rawResponse
        """
        cve_id      = cve_data.get("cveId")      or cve_data.get("cve_id",      "UNKNOWN")
        description = cve_data.get("description", "No description available.")
        cvss        = cve_data.get("cvssScore")   or cve_data.get("cvss_score",  "N/A")
        severity    = cve_data.get("severity",     "UNKNOWN")
        epss        = cve_data.get("epssScore")   or cve_data.get("epss_score",  "N/A")
        is_kev      = cve_data.get("isKEV")       or cve_data.get("is_kev",      False)
        assets_str  = ", ".join(affected_assets) if affected_assets else "Unknown Banking Asset"

        prompt = (
            f"Act as a pragmatic Senior Incident Response Commander for Union Bank of India.\n"
            f"Generate a SOC playbook for the following prioritized attack vector:\n\n"
            f"CVE ID: {cve_id}\n"
            f"Description: {description}\n"
            f"CVSS Score: {cvss} ({severity})\n"
            f"EPSS Score: {epss} (probability of exploitation)\n"
            f"Known Exploited: {is_kev}\n"
            f"Affected Banking Assets: {assets_str}\n\n"
            "Do not use generic advice. Be specific, realistic, and format the output strictly using the following structure:\n\n"
            "1. Executive Summary\n"
            "The Threat: [A simple, one-sentence description of the attack vector].\n"
            "The Pragmatic Risk: [Why does this actually matter to the business?]\n"
            "Target Scope: [What types of assets are usually targeted?]\n\n"
            "2. Validation: Is this real?\n"
            "Log Sources to Check: [List the exact logs needed]\n"
            "Key Indicators (IoCs): [What specific event IDs, HTTP status codes, or file paths should the analyst look for?]\n"
            "Validation Steps:\n"
            "Step 1: [e.g., Check if the targeted system actually runs the vulnerable software version].\n"
            "Step 2: [...]\n\n"
            "3. Containment: Stop the threat\n"
            "Soft Containment (Low Risk to Production):\n"
            "- [...]\n"
            "Hard Containment (High Risk to Production):\n"
            "- [...]\n"
            "The \"Legacy/Unpatchable\" Plan: [Compensating controls]\n\n"
            "4. Eradication & Remediation\n"
            "Primary Fix: [e.g., Apply patch version X.Y]\n"
            "Asset Owner Handoff: [What exactly does the SOC analyst need to tell the IT/DevOps team?]\n\n"
            "5. Post-Incident Hunting\n"
            "Persistence Checks: [Where would they hide?]\n"
            "Lateral Movement Checks: [What should the analyst look for to see if the attacker jumped to another machine?]"
        )

        raw_text = self._call_gemini_with_retry(prompt, context=f"playbook:{cve_id}")

        if raw_text is None:
            raw_text = self._fallback_playbook_text(cve_id, assets_str, severity, cvss, is_kev)
            logger.warning("Using fallback playbook for %s.", cve_id)

        sections = _parse_sections(raw_text, _SECTIONS)

        return {
            "cveId":                  cve_id,
            "generatedAt":            datetime.now(timezone.utc).isoformat(),
            "executiveSummary":       sections.get("executiveSummary",       ""),
            "validation":             sections.get("validation",             ""),
            "containment":            sections.get("containment",            ""),
            "eradicationRemediation": sections.get("eradicationRemediation", ""),
            "postIncidentHunting":    sections.get("postIncidentHunting",    ""),
            "rawResponse":            raw_text,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Additional method: security policy for a MITRE technique
    # ──────────────────────────────────────────────────────────────────────────

    def generate_security_policy(self, technique_data: dict[str, Any]) -> str:
        """
        Generate a concise (1-page) security policy recommendation for a
        MITRE ATT&CK technique, framed for Indian banking compliance.

        Parameters
        ----------
        technique_data : dict
            Keys: techniqueId, name, tactic, capecId, capecName (all optional)

        Returns
        -------
        str  Markdown-formatted policy document
        """
        tech_id   = technique_data.get("techniqueId") or technique_data.get("technique_id", "T????")
        tech_name = technique_data.get("name") or technique_data.get("technique_name", "Unknown Technique")
        tactic    = technique_data.get("tactic", "Unknown Tactic")
        capec     = technique_data.get("capecId", "")

        prompt = (
            f"You are the CISO of Union Bank of India.\n\n"
            f"Write a one-page information security policy to defend against the "
            f"MITRE ATT&CK technique:\n\n"
            f"Technique: {tech_id} — {tech_name}\n"
            f"Tactic: {tactic}\n"
            f"CAPEC Reference: {capec}\n\n"
            "The policy must include:\n"
            "- Policy objective\n"
            "- Scope (systems, teams)\n"
            "- Control requirements (technical + procedural)\n"
            "- Monitoring & detection requirements\n"
            "- Compliance references (RBI, ISO 27001, DPDP Act)\n\n"
            "Write in formal policy language. Keep it under 500 words."
        )

        raw = self._call_gemini_with_retry(prompt, context=f"policy:{tech_id}")
        if raw is None:
            return self._fallback_policy(tech_id, tech_name, tactic)
        return raw

    # ──────────────────────────────────────────────────────────────────────────
    # Legacy method — kept for backwards compat with existing /playbooks/generate
    # ──────────────────────────────────────────────────────────────────────────

    def generate_mitigation_playbook(
        self,
        cve_id: str,
        asset_name: str,
        technique_name: str,
    ) -> str:
        """
        Legacy string-returning method used by the existing route.
        Delegates to generate_remediation_playbook() and returns rawResponse.
        """
        result = self.generate_remediation_playbook(
            cve_data={
                "cveId":       cve_id,
                "description": f"Vulnerability {cve_id} exploited via {technique_name}.",
                "cvssScore":   "N/A",
                "severity":    "HIGH",
                "epssScore":   "N/A",
                "isKEV":       False,
            },
            affected_assets=[asset_name],
        )
        return result["rawResponse"]

    # ──────────────────────────────────────────────────────────────────────────
    # Gemini call with retry
    # ──────────────────────────────────────────────────────────────────────────

    def _call_gemini_with_retry(self, prompt: str, context: str = "") -> str | None:
        """
        Call the Gemini API with exponential back-off retry.

        Returns the response text, or None if all retries fail / API disabled.
        """
        if not self.enabled:
            logger.debug("Gemini disabled — skipping call for %s.", context)
            return None

        last_exc: Exception | None = None

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                logger.info("Gemini call [%s] using %s attempt %d/%d …", context, self.model_name, attempt, _MAX_RETRIES)
                response = self._model.generate_content(prompt)
                text = _sanitize(response.text)
                logger.info("Gemini call [%s] succeeded (%d chars).", context, len(text))
                return text

            except Exception as exc:
                last_exc = exc
                err_str  = str(exc).lower()

                # Dynamic fallback from gemini-3.5-flash to gemini-3.1-flash-lite / gemini-2.5-flash if model not found / quota is 0
                if self.model_name == "gemini-3.5-flash":
                    is_404 = "not found" in err_str or "404" in err_str or "unsupported" in err_str
                    is_zero_quota = "limit: 0" in err_str or "quota exceeded" in err_str
                    if is_404 or is_zero_quota:
                        logger.warning("Model gemini-3.5-flash unavailable/unsupported on this key. Falling back to gemini-3.1-flash-lite dynamically...")
                        self.model_name = "gemini-3.1-flash-lite"
                        self._init_model()
                        try:
                            logger.info("Retrying call [%s] immediately with fallback model %s …", context, self.model_name)
                            response = self._model.generate_content(prompt)
                            text = _sanitize(response.text)
                            logger.info("Gemini call [%s] succeeded with fallback model %s (%d chars).", context, self.model_name, len(text))
                            return text
                        except Exception as inner_exc:
                            last_exc = inner_exc
                            err_str = str(inner_exc).lower()

                if self.model_name == "gemini-3.1-flash-lite":
                    is_404 = "not found" in err_str or "404" in err_str or "unsupported" in err_str
                    is_zero_quota = "limit: 0" in err_str or "quota exceeded" in err_str
                    if is_404 or is_zero_quota:
                        logger.warning("Model gemini-3.1-flash-lite unavailable/unsupported on this key. Falling back to gemini-2.5-flash dynamically...")
                        self.model_name = "gemini-2.5-flash"
                        self._init_model()
                        try:
                            logger.info("Retrying call [%s] immediately with fallback model %s …", context, self.model_name)
                            response = self._model.generate_content(prompt)
                            text = _sanitize(response.text)
                            logger.info("Gemini call [%s] succeeded with fallback model %s (%d chars).", context, self.model_name, len(text))
                            return text
                        except Exception as inner_exc:
                            last_exc = inner_exc
                            err_str = str(inner_exc).lower()

                # Rate limit / quota → retry with back-off
                if any(kw in err_str for kw in ("quota", "rate", "429", "resource exhausted")):
                    wait = _RETRY_BASE_SEC * (2 ** (attempt - 1))
                    logger.warning(
                        "Gemini rate-limited [%s] attempt %d. Waiting %.1fs …",
                        context, attempt, wait
                    )
                    time.sleep(wait)
                    continue

                # Non-retryable errors (auth, invalid request, …)
                logger.error("Gemini non-retryable error [%s]: %s", context, exc)
                break

        logger.error(
            "Gemini call [%s] failed after %d attempts. Last error: %s",
            context, _MAX_RETRIES, last_exc
        )
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Fallbacks
    # ──────────────────────────────────────────────────────────────────────────

    def _fallback_playbook_text(
        self,
        cve_id: str,
        assets: str,
        severity: str,
        cvss: Any,
        is_kev: bool,
    ) -> str:
        kev_note = (
            "\n> ⚠️ This CVE is in the CISA KEV catalog. Immediate patching is MANDATORY."
            if is_kev else ""
        )
        return f"""1. Executive Summary
The Threat: {cve_id} ({severity}, CVSS {cvss}) affects {assets}.{kev_note}
The Pragmatic Risk: Immediate containment and patching are required per RBI Cyber Security Framework guidelines to prevent unauthorized access and data exfiltration.
Target Scope: Enterprise banking infrastructure and associated middleware.

2. Validation: Is this real?
Log Sources to Check: SIEM, WAF logs, and EDR telemetry on {assets}.
Key Indicators (IoCs): Look for abnormal traffic patterns, rapid sequential authentication failures, or unexpected process spawning.
Validation Steps:
Step 1: Verify if {assets} is running the vulnerable software version.
Step 2: Check for any corresponding alerts from the internal vulnerability scanner.

3. Containment: Stop the threat
Soft Containment (Low Risk to Production):
- Revoke all active service-account tokens on {assets}.
- Enable enhanced audit logging on SIEM for all authentication events.
Hard Containment (High Risk to Production):
- Isolate affected systems using network ACLs within 15 minutes of detection.
The "Legacy/Unpatchable" Plan: If unpatchable, implement strict zero-trust micro-segmentation and WAF rules to block exploitation patterns.

4. Eradication & Remediation
Primary Fix: Apply vendor security patch for {cve_id} within 72 hours (RBI mandate).
Asset Owner Handoff: Provide IT/DevOps with the patching schedule and verify closure with an authenticated vulnerability scan post-patch.

5. Post-Incident Hunting
Persistence Checks: Check for newly created local admin accounts, scheduled tasks, or web shells on {assets}.
Lateral Movement Checks: Verify no active sessions from unknown IP ranges in SIEM, and check for east-west traffic anomalies.
"""

    def _fallback_policy(self, tech_id: str, tech_name: str, tactic: str) -> str:
        return (
            f"# Information Security Policy — {tech_id}: {tech_name}\n\n"
            f"**Tactic:** {tactic} | **Effective Date:** {datetime.now(timezone.utc).date()}\n\n"
            "## Objective\nPrevent exploitation of this attack technique against bank infrastructure.\n\n"
            "## Scope\nAll production systems, DevOps pipelines, and third-party integrations.\n\n"
            "## Controls\n"
            "- Multi-factor authentication enforced on all privileged interfaces.\n"
            "- Network segmentation prevents lateral movement between trust zones.\n"
            "- SIEM alerting configured for technique-specific IoCs.\n\n"
            "## Compliance\nRBI CSF 2016, ISO 27001:2022, DPDP Act 2023.\n"
        )


logger.info("PlaybookGenerator module loaded.")


# ══════════════════════════════════════════════════════════════════════════════
# Shared utilities (used by both genai modules)
# ══════════════════════════════════════════════════════════════════════════════

# Avoid a circular import: define helpers at module level so rca_gen can import
# them directly: `from genai.playbook_gen import _sanitize, _parse_sections`

def _sanitize(text: str) -> str:
    """
    Remove common Markdown artifacts that break section parsing:
    - Fenced code block delimiters (``` … ```)
    - Excessive blank lines (collapse to ≤ 2)
    - Leading/trailing whitespace per line
    """
    # Strip fenced code delimiters (keep content)
    text = re.sub(r"```[a-zA-Z]*\n?", "", text)
    text = re.sub(r"```",            "", text)
    # Collapse ≥ 3 blank lines to 2
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _parse_sections(
    text:     str,
    section_defs: list[tuple[str, list[str]]],
) -> dict[str, str]:
    """
    Extract named sections from a numbered-heading document.

    For each (key, aliases) pair in `section_defs`, the parser looks for a
    line matching any of the aliases (case-insensitive, ignoring leading
    numbering and Markdown heading markers).  Content runs until the next
    heading or end-of-string.

    Falls back gracefully: missing sections get an empty string.
    """
    # Build a flat list of (alias_lower, key) for lookup
    alias_map: list[tuple[str, str]] = []
    for key, aliases in section_defs:
        for alias in aliases:
            alias_map.append((alias.lower(), key))

    lines  = text.splitlines()
    result: dict[str, str] = {key: "" for key, _ in section_defs}

    # Heading detection: strip leading "## " / "**" / "1. " / "###" etc.
    _strip_heading = re.compile(r"^[\s#*\d.\-]+")

    current_key: str | None = None
    buffer: list[str] = []

    def flush() -> None:
        if current_key:
            result[current_key] = "\n".join(buffer).strip()

    for line in lines:
        stripped = _strip_heading.sub("", line).strip().lower()

        matched_key: str | None = None
        for alias, key in alias_map:
            if stripped.startswith(alias):
                matched_key = key
                break

        if matched_key:
            flush()
            current_key = matched_key
            buffer = []
        else:
            buffer.append(line)

    flush()
    return result


# Guard: fix reference to undefined _MAX_TEMPERATURE used in __init__
_MAX_TEMPERATURE = _TEMPERATURE   # aliased to keep __init__ clean
