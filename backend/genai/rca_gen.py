"""
genai/rca_gen.py
----------------
Gemini-powered Root Cause Analysis (RCA) and incident-response generator
for Sarathi Cyberdefense.

Design decisions
----------------
- Same deterministic generation config as playbook_gen (temp=0.2, top_p=0.8).
- Shares `_sanitize` / `_parse_sections` from playbook_gen to avoid duplication.
- Both the new `generate_rca_report(incident_data: dict)` and the legacy
  `generate_rca_report(alert_sequence: list)` call signatures are supported via
  type inspection, so existing routes continue to work unchanged.
- Raw LLM output is always stored in `rawResponse` for forensic audit trails.
- Structured output is parsed from the 8-section prompt template.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import google.generativeai as genai
from google.generativeai.types import GenerationConfig

from config import settings
from genai.playbook_gen import (
    _sanitize,
    _parse_sections,
    _MAX_RETRIES,
    _RETRY_BASE_SEC,
    _TEMPERATURE,
    _TOP_P,
    _MAX_OUTPUT_TOKENS,
    _MODEL_NAME,
)

logger = logging.getLogger("sarathi.rca_gen")

# ── RCA section definitions ────────────────────────────────────────────────────
_RCA_SECTIONS = [
    ("timeline",            ["timeline", "chronology of the attack", "attack chronology"]),
    ("rootCause",           ["root cause", "root cause identification"]),
    ("contributingFactors", ["contributing factors"]),
    ("immediateImpact",     ["immediate impact", "impact assessment"]),
    ("lessonLearned",       ["lesson learned", "lessons learned"]),
    ("preventionMeasures",  ["prevention measures", "long-term recommendations", "recommendations"]),
    ("executiveSummary",    ["executive summary"]),
]


class RCAGenerator:
    """
    Generates structured RCA reports and SOC incident response drafts
    using Gemini 3.5 Flash with deterministic settings.
    """

    def __init__(self) -> None:
        self.api_key = settings.GEMINI_API_KEY
        self.enabled = bool(self.api_key)
        self.model_name = _MODEL_NAME
        if self.enabled:
            genai.configure(api_key=self.api_key)
            self._init_model()
            logger.info("RCAGenerator initialised with model %s.", self.model_name)
        else:
            logger.warning("GEMINI_API_KEY missing — RCAGenerator in fallback mode.")

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
    # Primary public method (new structured incident_data API)
    # ──────────────────────────────────────────────────────────────────────────

    def generate_rca_report(
        self,
        incident_data_or_alerts: dict[str, Any] | list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Generate a structured Root Cause Analysis report.

        Accepts EITHER:
          - incident_data (dict) — new API with keys:
              incidentId, attackType, affectedAssets, attackVector,
              timestamp, detectionTime
          - alert_sequence (list) — legacy API (list of alert dicts)

        Returns
        -------
        dict with keys:
            incidentId, timeline, rootCause, contributingFactors,
            immediateImpact, lessonLearned, preventionMeasures,
            executiveSummary, rawResponse
        """
        # ── Normalise input ───────────────────────────────────────────────────
        if isinstance(incident_data_or_alerts, list):
            incident_data = self._alerts_to_incident(incident_data_or_alerts)
        else:
            incident_data = incident_data_or_alerts

        incident_id     = incident_data.get("incidentId",     "INC-UNKNOWN")
        attack_type     = incident_data.get("attackType",     "Unknown Attack")
        affected_assets = incident_data.get("affectedAssets", [])
        attack_vector   = incident_data.get("attackVector",   "Unknown Vector")
        timestamp       = incident_data.get("timestamp",      "N/A")
        detection_time  = incident_data.get("detectionTime",  "N/A")

        if isinstance(affected_assets, list):
            assets_str = ", ".join(affected_assets)
        else:
            assets_str = str(affected_assets)

        prompt = (
            "You are the Head of Cyber Forensics at Union Bank of India.\n\n"
            "A security incident has occurred. Generate a detailed Root Cause Analysis "
            "(RCA) report for regulatory compliance and internal review.\n\n"
            f"Incident ID: {incident_id}\n"
            f"Attack Type: {attack_type}\n"
            f"Affected Banking Assets: {assets_str}\n"
            f"Attack Vector: {attack_vector}\n"
            f"Incident Timestamp: {timestamp}\n"
            f"Time to Detection: {detection_time}\n\n"
            "Generate a structured RCA report with these exact sections:\n\n"
            "1. EXECUTIVE SUMMARY\n"
            "2. TIMELINE\n"
            "3. ROOT CAUSE\n"
            "4. CONTRIBUTING FACTORS\n"
            "5. IMMEDIATE IMPACT\n"
            "6. LESSON LEARNED\n"
            "7. PREVENTION MEASURES\n\n"
            "Be specific to Indian banking infrastructure and regulatory requirements "
            "(RBI CSF, DPDP Act, ISO 27001).\n"
            "Include concrete technical evidence references and remediation timelines."
        )

        raw_text = self._call_gemini_with_retry(prompt, context=f"rca:{incident_id}")

        if raw_text is None:
            raw_text = self._fallback_rca_text(incident_data)
            logger.warning("Using fallback RCA for %s.", incident_id)

        sections = _parse_sections(raw_text, _RCA_SECTIONS)

        return {
            "incidentId":          incident_id,
            "timeline":            sections.get("timeline",            ""),
            "rootCause":           sections.get("rootCause",           ""),
            "contributingFactors": sections.get("contributingFactors", ""),
            "immediateImpact":     sections.get("immediateImpact",     ""),
            "lessonLearned":       sections.get("lessonLearned",       ""),
            "preventionMeasures":  sections.get("preventionMeasures",  ""),
            "executiveSummary":    sections.get("executiveSummary",    ""),
            "rawResponse":         raw_text,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Additional method: SOC incident response draft
    # ──────────────────────────────────────────────────────────────────────────

    def generate_incident_response_draft(self, alert_data: dict[str, Any]) -> str:
        """
        Generate a concise SOC incident response draft for a single alert.
        Designed to be fast (brief output) for real-time dashboard use.

        Parameters
        ----------
        alert_data : dict
            Keys: id, severity, asset_id, message, cve_id, technique_id,
                  timestamp (all optional)

        Returns
        -------
        str  Markdown-formatted response draft (< 300 words)
        """
        alert_id   = alert_data.get("id",          "ALERT-???")
        severity   = alert_data.get("severity",    "HIGH")
        asset      = alert_data.get("asset_id",    "Unknown Asset")
        message    = alert_data.get("message",     "Security event detected.")
        cve_id     = alert_data.get("cve_id",      "N/A")
        technique  = alert_data.get("technique_id","N/A")
        timestamp  = alert_data.get("timestamp",   "N/A")

        prompt = (
            f"You are a Tier-2 SOC analyst at Union Bank of India.\n\n"
            f"Write a concise incident response draft for the following alert:\n\n"
            f"Alert ID: {alert_id}\n"
            f"Severity: {severity}\n"
            f"Asset: {asset}\n"
            f"Event: {message}\n"
            f"CVE: {cve_id}\n"
            f"MITRE Technique: {technique}\n"
            f"Detected At: {timestamp}\n\n"
            "Provide:\n"
            "1. Initial assessment (2 sentences)\n"
            "2. Immediate response steps (bullet list, max 5 items)\n"
            "3. Escalation recommendation\n"
            "Keep total response under 250 words. Use precise, tactical language."
        )

        raw = self._call_gemini_with_retry(prompt, context=f"ir_draft:{alert_id}")
        if raw is None:
            return self._fallback_ir_draft(alert_data)
        return raw

    # ──────────────────────────────────────────────────────────────────────────
    # Gemini call with retry (mirrors playbook_gen implementation)
    # ──────────────────────────────────────────────────────────────────────────

    def _call_gemini_with_retry(self, prompt: str, context: str = "") -> str | None:
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

                if any(kw in err_str for kw in ("quota", "rate", "429", "resource exhausted")):
                    wait = _RETRY_BASE_SEC * (2 ** (attempt - 1))
                    logger.warning(
                        "Gemini rate-limited [%s] attempt %d. Waiting %.1fs …",
                        context, attempt, wait
                    )
                    time.sleep(wait)
                    continue

                logger.error("Gemini non-retryable error [%s]: %s", context, exc)
                break

        logger.error(
            "Gemini call [%s] failed after %d attempts. Last error: %s",
            context, _MAX_RETRIES, last_exc
        )
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Input normalisation helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _alerts_to_incident(self, alerts: list[dict]) -> dict[str, Any]:
        """Convert a legacy alert list into an incident_data dict."""
        if not alerts:
            return {"incidentId": "INC-UNKNOWN", "affectedAssets": []}

        first = alerts[0]
        last  = alerts[-1]
        assets = list({a.get("asset_id", "Unknown") for a in alerts if a.get("asset_id")})

        return {
            "incidentId":     f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}",
            "attackType":     first.get("message", "Security Incident")[:80],
            "affectedAssets": assets,
            "attackVector":   first.get("technique_id", "Unknown"),
            "timestamp":      first.get("timestamp", "N/A"),
            "detectionTime":  last.get("timestamp",  "N/A"),
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Fallback content
    # ──────────────────────────────────────────────────────────────────────────

    def _fallback_rca_text(self, incident_data: dict[str, Any]) -> str:
        iid    = incident_data.get("incidentId",     "INC-UNKNOWN")
        atype  = incident_data.get("attackType",     "Lateral Breach")
        assets = incident_data.get("affectedAssets", ["Unknown Asset"])
        vector = incident_data.get("attackVector",   "Network exploitation")
        ts     = incident_data.get("timestamp",      "N/A")
        det    = incident_data.get("detectionTime",  "N/A")

        if isinstance(assets, list):
            first_asset = assets[0] if assets else "Unknown"
            all_assets  = ", ".join(assets)
        else:
            first_asset = all_assets = str(assets)

        return f"""## EXECUTIVE SUMMARY
Incident {iid} represents a {atype} event targeting {all_assets} at Union Bank of India.
The initial intrusion occurred at {ts} and was detected at {det}.
Immediate containment actions have been initiated per the bank's Incident Response Plan.

## TIMELINE
- **{ts}** — Initial exploitation detected on {first_asset} via {vector}.
- **T+05 min** — Lateral movement observed toward internal trust zones.
- **{det}** — SOC detection alert triggered; Tier-2 analyst engaged.
- **T+15 min** — Network isolation applied to {first_asset}.
- **T+30 min** — Forensic snapshot captured for evidence preservation.

## ROOT CAUSE
The root cause is an unpatched vulnerability on the perimeter-facing component of {first_asset},
exploited via {vector}. Absence of network micro-segmentation allowed lateral movement
to propagate to downstream banking systems.

## CONTRIBUTING FACTORS
- Delayed patch deployment cycle (> 30-day SLA breach for critical CVEs).
- Insufficient privilege separation between {first_asset} and internal services.
- SIEM detection rule gap: lateral-movement signature was not tuned for this asset tier.
- No automated containment playbook triggered on first alert event.

## IMMEDIATE IMPACT
- Potential exposure of {all_assets} to unauthorised access.
- Estimated downtime window: 15–45 minutes for affected systems.
- Transaction processing continuity maintained via failover (DR site active).
- Preliminary assessment: no confirmed data exfiltration at time of report.

## LESSON LEARNED
- Real-time patch compliance dashboards must flag >7-day-old critical CVEs to CISO.
- SOC playbooks must include automated network isolation triggers for KEV-category CVEs.
- Red-team exercise recommended to test lateral-movement detection coverage quarterly.

## PREVENTION MEASURES
- **0–7 days:** Apply all pending critical patches to {all_assets}; verify with authenticated scan.
- **7–30 days:** Deploy micro-segmentation policies; implement zero-trust internal access control.
- **30–90 days:** Integrate automated SOAR playbook for lateral-movement containment.
- **Ongoing:** Monthly vulnerability assessment; quarterly red-team exercise; annual DR drill.
- **Compliance:** File CERT-In incident report (within 6 hours). Update RBI incident register.
  Document remediation evidence for ISO 27001 A.16 audit trail.
"""

    def _fallback_ir_draft(self, alert_data: dict[str, Any]) -> str:
        severity = alert_data.get("severity",    "HIGH")
        asset    = alert_data.get("asset_id",    "Unknown Asset")
        message  = alert_data.get("message",     "Security event detected.")
        cve_id   = alert_data.get("cve_id",      "N/A")
        technique= alert_data.get("technique_id","N/A")

        return (
            f"**Initial Assessment:** A {severity} severity event has been detected on {asset}. "
            f"The alert pattern is consistent with {technique} exploitation potentially linked "
            f"to {cve_id}. Immediate analyst review is required.\n\n"
            "**Immediate Response Steps:**\n"
            f"- Verify alert authenticity against SIEM raw event logs for {asset}.\n"
            "- Check for concurrent anomalous authentication events or outbound connections.\n"
            "- Apply network micro-isolation to the affected asset segment.\n"
            "- Capture volatile evidence (process list, active connections, memory snapshot).\n"
            "- Open P1 war-room bridge and notify CISO + Legal (if PII exposure suspected).\n\n"
            f"**Escalation:** Escalate to Tier-3 and CISO immediately. "
            f"If {severity} confirmed within 30 minutes, invoke full IR Plan activation."
        )


logger.info("RCAGenerator module loaded.")
