import json
import logging
import re

import requests

from api_app.connectors_manager.classes import Connector
from api_app.connectors_manager.exceptions import (
    ConnectorConfigurationException,
    ConnectorRunException,
)
from api_app.models import Tag

logger = logging.getLogger(__name__)


class LLMSummarizer(Connector):
    """
    Local LLM-based connector using Ollama for job report summarization, threat classification,  # noqa: E501
    risk scoring, IOC extraction, pivot suggestions, and auto-tagging.
    Privacy-first: no external AI provider calls.
    """

    def update(self):
        """Required abstract method from base class, not used in this connector."""  # noqa: E501
        pass

    def check(self):
        """
        Validate required configuration parameters before execution.
        Called automatically by IntelOwl before run() in some flows.
        """
        job = getattr(self, "job", None) or getattr(self, "_job", None)
        if job is None:
            logger.debug(
                "[LLM_Summarizer] No job context in check() - skipping validation"  # noqa: E501
            )
            return
        runtime_config = getattr(job, "runtime_configuration", None) if job else None  # noqa: E501

        self.config(runtime_configuration=runtime_config)
        params = getattr(self, "parameters", {}) or {}

        required = ["ollama_url", "model"]
        missing = [p for p in required if p not in params]
        if missing:
            raise ConnectorConfigurationException(
                f"Missing required parameters in connector config: {', '.join(missing)}. "  # noqa: E501
                "Please configure them in the admin panel or API payload."
            )

    def run(self):
        try:
            job = self._get_job()
            runtime_config = getattr(job, "runtime_configuration", None) if job else None  # noqa: E501

            self.config(runtime_configuration=runtime_config)
            params = getattr(self, "parameters", {}) or {}
            logger.info(f"[LLM_Summarizer] Config parameters: {params}")

            analyzers = self._prepare_analyzers(job)
            logger.info(f"[LLM_Summarizer] Found {len(analyzers)} analyzers")

            observable = self._resolve_observable(job, analyzers)
            logger.info(f"[LLM_Summarizer] Observable resolved: {observable}")

            report = self._build_report(job, observable, analyzers)
            report_text = self._truncate_report_text(report)

            system_prompt = self._get_system_prompt()
            full_prompt = f"{system_prompt}\n\nReport:\n{report_text}"

            llm_response = self._call_ollama_api(full_prompt, params)

            if not llm_response or llm_response.isspace():
                logger.warning("Empty LLM response — using fallback")
                return self._get_fallback_response()

            parsed_output = self._parse_and_clean_response(llm_response, report_text, analyzers, report)  # noqa: E501
            self._apply_auto_tags(parsed_output, job)
            logger.info("LLM summarization complete")
            return parsed_output

        except requests.RequestException as e:
            logger.error(f"Ollama API request failed: {str(e)}")
            raise ConnectorRunException(f"Ollama connection/API error: {str(e)}")  # noqa: E501
        except Exception as e:
            logger.exception("Unexpected error in LLM_Summarizer")
            raise ConnectorRunException(f"Unexpected error: {str(e)}")

    def _get_job(self):
        job = getattr(self, "job", None) or getattr(self, "_job", None)
        if job is None:
            job = getattr(self, "analyzable", None)
        if job is None:
            raise ConnectorRunException(
                "Job/Analyzable instance not available in connector context"  # noqa: E501
            )
        return job

    def _resolve_observable(self, job, analyzers):
        observable = getattr(job, "observable_name", None) or getattr(job, "file_name", None)  # noqa: E501

        if not observable and hasattr(job, "data_model") and job.data_model:  # noqa: E501
            observable = getattr(job.data_model, "observable_name", None)

        if not observable or observable == "unknown":
            full_report_text = json.dumps({a["name"]: a["report_summary"] for a in analyzers})  # noqa: E501
            observable = self._extract_observable_from_text(full_report_text)

        if not observable:
            observable = "unknown"
            logger.warning("Could not detect observable from any source")

        return observable

    def _extract_observable_from_text(self, full_report_text):
        patterns = [
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            r"\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}",
        ]
        for pattern in patterns:
            match = re.search(pattern, full_report_text)
            if match:
                return match.group(0)
        return None

    def _build_report(self, job, observable, analyzers):
        return {
            "id": getattr(job, "id", "unknown"),
            "observable": observable,
            "observable_type": getattr(job, "observable_classification", "unknown"),  # noqa: E501
            "status": getattr(job, "status", "unknown"),
            "analyzers": analyzers,
            "tags": (list(job.tags.values_list("label", flat=True)) if hasattr(job, "tags") else []),  # noqa: E501
        }

    def _truncate_report_text(self, report):
        report_text = json.dumps(report, indent=2)
        max_length = 12000
        if len(report_text) > max_length:
            report_text = report_text[:max_length] + (
                "\n\n[TRUNCATED REPORT - ONLY PARTIAL DATA AVAILABLE. "
                "Focus on what is visible. Do not assume missing content. "
                "Still try to produce a meaningful summary of visible analyzers.]\n"  # noqa: E501
            )
            logger.warning(
                f"[LLM_Summarizer] Report truncated to {len(report_text)} chars"  # noqa: E501
            )
        return report_text

    def _get_system_prompt(self):
        return """
You are a precise, evidence-based threat intelligence analyst. Analyze ONLY the IntelOwl job report provided below. Stay factual and grounded in the data — but you ARE allowed and expected to interpret patterns, group similar findings, and draw reasonable conclusions that a skilled analyst would make (e.g. TOR exit nodes, open resolvers, historical abuse patterns).

Output rules (strict):
- Respond with ONLY valid JSON — no explanations, no markdown, no fences, no extra text before or after the object.
- Use double quotes for strings. No trailing commas. No comments.
- The report JSON has a top-level key called "observable" — this is ALWAYS the correct and ONLY observable value to use. It is the authoritative source of truth. You MUST use EXACTLY this value in the summary (e.g. if "observable": "185.220.101.5", write "IP address 185.220.101.5"). Never use any other IP, domain, or value from analyzer reports instead.
- NEVER override or replace the top-level "observable" value with anything from analyzer fields (e.g. bgproute, rdata, rrname, ip_details, asdesc, or any subnet/network address like x.x.x.0). Subnet values ending in .0 are NOT the observable — ignore them completely for the observable field.
- When starting the summary, ALWAYS copy the "observable" value VERBATIM from the JSON and prefix it with the correct type (IP address, domain, hash, URL). Do NOT infer, correct, or change it based on analyzer content.
- If the observable is an IP and analyzers mention a subnet (e.g. x.x.x.0/24), explicitly note it as "subnet information" but NEVER use it as the observable itself.
- Summary: 1–3 detailed paragraphs. Start with observable + type. Then cover ALL analyzers (group similar items when lists are long). Highlight important patterns (TOR, proxy, NTP/open resolver, abuse feeds). End with clear overall verdict.
- Always end the summary with a complete 'Overall...' sentence summarizing the verdict (e.g. "Overall, this is a benign, legitimate Google public DNS server with no abuse indicators.").
- Threat categories: include only when there is reasonable evidence in the report (e.g. TOR exit node → ["tor","proxy"], many abuse connections → ["abuse","scanning"], etc.). Empty [] if truly clean.
- Risk score: 0–100 scale. Use common TI ranges:
  0–20  = known benign (Google/Cloudflare DNS, corporate infra)
  21–50 = suspicious / medium (TOR exit, open resolver, historical abuse but no active C2)
  51–80 = high risk (recent abuse, malware family hits, scanning behavior)
  81–100 = confirmed malicious (blacklists, active C2, exploit kit)
- Confidence: low/medium/high based on number of analyzers, agreement, data completeness.
- Extracted IOCs: only verbatim items from the report that are clearly IOCs (IPs, domains, hashes, URLs).
- Suggested pivots: 2–4 concrete next steps.
- If any analyzer has status "ERROR" or an error message, include a brief note in the summary (e.g. "Threatminer: failed due to API error (500)").

Few-shot examples (use these patterns — note correct observable usage):

Example 1 – Clean public DNS
Report: {"observable": "8.8.8.8", ... "Google public recursive name server" ...}
Output: {"summary": "The observable is IP address 8.8.8.8. Abusix: abuse contacts for Google. DShield: Google's public DNS with no attacks. IPApi: AS15169 Google LLC. IPQuery: low risk. Overall, legitimate Google public DNS server with no indicators of abuse.", "threat_categories": [], "risk_score": 5, "confidence": "high", "extracted_iocs": [], "suggested_pivots": ["Monitor for unusual traffic","Query related ASNs"]}

Example 2 – Confirmed malicious
Report: {"observable": "evil.com", ... "malicious": 42 ...}
Output: {"summary": "The observable is domain evil.com. VirusTotal: 42 malicious detections and blacklist hits. URLhaus: classified as phishing threat. Overall, strong malicious indicators including high VT score and known stealer family. Confirmed malicious infrastructure.", "threat_categories": ["malware","stealer","phishing"], "risk_score": 92, "confidence": "high", "extracted_iocs": ["evil.com"], "suggested_pivots": ["Scan associated IPs","Check phishing logs","Block in firewall"]}

Example 3 – TOR exit node
Report: {"observable": "185.220.101.5", ... "rrname": "berlin01.tor-exit.artikel10.org", count: 5056 ... "bgproute": "185.220.101.0/24" ...}
Output: {"summary": "The observable is IP address 185.220.101.5. Mnemonic_PassiveDNS shows dominant association with tor-exit.artikel10.org (over 5000 resolutions) indicating this is a long-running TOR exit node. Historical NTP pool resolutions (mostly 2020) are present but secondary. Robtex confirms ASN and routing (subnet 185.220.101.0/24). This is typical TOR exit behavior — frequently abused for anonymity but not inherently malicious. Medium risk due to proxy/TOR usage and potential for abuse.", "threat_categories": ["tor","proxy","abuse"], "risk_score": 55, "confidence": "medium", "extracted_iocs": ["berlin01.tor-exit.artikel10.org"], "suggested_pivots": ["Check current TOR exit list status", "Review abuse reports for this IP/ASN", "Monitor for outbound scanning or C2 traffic"]}

JSON STRUCTURE ONLY:
{
  "summary": "...",
  "threat_categories": [],
  "risk_score": 55,
  "confidence": "medium",
  "extracted_iocs": [],
  "suggested_pivots": []
}
"""  # noqa: E501

    def _call_ollama_api(self, full_prompt, params):
        ollama_url = params.get("ollama_url", "http://host.docker.internal:11434")  # noqa: E501
        model = params.get("model", "llama3")

        if not ollama_url.startswith(("http://", "https://")):
            raise ConnectorConfigurationException(f"Invalid ollama_url: {ollama_url}")  # noqa: E501

        logger.info(
            f"[LLM_Summarizer] Calling Ollama → {ollama_url} / model: {model}"  # noqa: E501
        )

        api_endpoint = f"{ollama_url}/api/generate"
        payload = {
            "model": model,
            "prompt": full_prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.0,
                "num_predict": -1,
                "top_p": 0.7,
                "top_k": 20,
                "repeat_penalty": 1.2,
            },
        }

        response = requests.post(api_endpoint, json=payload, timeout=180)
        response.raise_for_status()

        llm_response = response.json().get("response", "").strip()
        logger.info(
            f"[LLM_Summarizer] Raw LLM response length: {len(llm_response)}"  # noqa: E501
        )
        logger.info(
            f"[LLM_Summarizer] Raw LLM response preview: {llm_response[:300]}..."  # noqa: E501
        )

        logger.debug(
            f"[LLM_SUMMARIZER_DEBUG] Full raw response:\n{llm_response[:2000]}"  # noqa: E501
        )
        if len(llm_response) > 2000:
            logger.debug("... [response truncated in log]")
        return llm_response

    def _get_fallback_response(self):
        return {
            "summary": "Report analysis unavailable (empty LLM response).",  # noqa: E501
            "threat_categories": [],
            "risk_score": 0,
            "confidence": "low",
            "extracted_iocs": [],
            "suggested_pivots": ["Review analyzer reports manually"],
        }

    def _parse_and_clean_response(self, llm_response, report_text, analyzers, report):  # noqa: E501
        try:
            text = self._clean_llm_text(llm_response)
            parsed_output = json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse still failed after strong cleanup: {str(e)}")  # noqa: E501
            logger.debug(f"Cleaned text that failed:\n{text[:600]}...")
            parsed_output = self._handle_parse_error(llm_response, text)

        parsed_output = self._validate_and_enrich_output(parsed_output, report_text, analyzers, report)  # noqa: E501
        return parsed_output

    def _clean_llm_text(self, llm_response):
        text = llm_response.strip()

        # Remove common markdown / code block garbage
        text = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text, flags=re.IGNORECASE)
        text = re.sub(r"^```$", "", text, flags=re.MULTILINE)

        # Remove any text before first { and after last }
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 < end:
            text = text[start:end]
        else:
            text = "{}"

        # Replace single quotes with double quotes (very common mistake)
        # But only in places that look like keys/values (naive but effective)
        text = re.sub(r"(\w+)'s\b", r"\1's", text)  # protect possessives
        text = text.replace("'", '"')

        # Remove trailing commas more aggressively (repeat 2–3×)
        for _ in range(3):
            text = re.sub(r",\s*([}\]])", r"\1", text)

        # Remove // and # style comments (sometimes models still do it)
        text = re.sub(r"\s*(//|#).*?(?=\n|$)", "", text, flags=re.MULTILINE)

        return text

    def _handle_parse_error(self, llm_response, text):
        partial = {}
        try:
            # Try to find key pieces even if structure is broken
            if m := re.search(r'"summary"\s*:\s*"([^"]*?)"', text, re.DOTALL):
                partial["summary"] = m.group(1).strip()
            if m := re.search(r'"risk_score"\s*:\s*(\d+)', text):
                partial["risk_score"] = int(m.group(1))
            if m := re.search(r'"confidence"\s*:\s*"([^"]*)"', text):
                partial["confidence"] = m.group(1).strip()
        except (AttributeError, IndexError, ValueError, re.error):
            pass

        # Fill defaults for missing parts
        parsed_output = {
            "summary": partial.get("summary") or "Could not parse LLM summary — see raw analyzer reports.",  # noqa: E501
            "threat_categories": [],
            "risk_score": partial.get("risk_score", 10),
            "confidence": partial.get("confidence", "low"),
            "extracted_iocs": [],
            "suggested_pivots": ["Manual review recommended"],
        }
        logger.warning("Used partial / default output after unrecoverable JSON error")  # noqa: E501
        return parsed_output

    def _validate_and_enrich_output(self, parsed_output, report_text, analyzers, report):  # noqa: E501
        # Validate IOCs
        extracted_iocs = parsed_output.get("extracted_iocs", [])
        valid_iocs = [ioc for ioc in extracted_iocs if ioc in report_text]
        if len(valid_iocs) < len(extracted_iocs):
            logger.warning(f"Filtered hallucinated IOCs: {set(extracted_iocs) - set(valid_iocs)}")  # noqa: E501
        parsed_output["extracted_iocs"] = valid_iocs

        # Fallback summary if empty
        summary = parsed_output.get("summary", "").strip()
        if not summary:
            self._set_fallback_summary(parsed_output, analyzers, report)

        # Ensure required keys
        required_keys = [
            "summary",
            "threat_categories",
            "risk_score",
            "confidence",
            "extracted_iocs",
            "suggested_pivots",
        ]
        missing_keys = [k for k in required_keys if k not in parsed_output]
        if missing_keys:
            logger.warning(f"Missing keys in LLM output: {missing_keys} — using defaults")  # noqa: E501
            self._ensure_required_keys(parsed_output, missing_keys)

        # Type conversions
        parsed_output["risk_score"] = int(parsed_output.get("risk_score", 0))
        parsed_output["threat_categories"] = list(parsed_output.get("threat_categories", []))  # noqa: E501
        parsed_output["extracted_iocs"] = list(parsed_output.get("extracted_iocs", []))  # noqa: E501
        parsed_output["suggested_pivots"] = list(parsed_output.get("suggested_pivots", []))  # noqa: E501

        return parsed_output

    def _set_fallback_summary(self, parsed_output, analyzers, report):
        analyzer_count = len(analyzers)
        obs_type = report.get("observable_type", "unknown")
        obs_name = report.get("observable", "unknown")

        if analyzer_count == 0:
            auto_summary = (
                f"Analysis failed or no analyzers produced usable output for observable "  # noqa: E501
                f"'{obs_name}' ({obs_type}). Manual review of raw reports recommended."  # noqa: E501
            )
        else:
            auto_summary = (
                f"The observable '{obs_name}' ({obs_type}) was processed by {analyzer_count} "  # noqa: E501
                f"analyzer(s), but LLM summarization failed. Key analyzers present: "  # noqa: E501
                f"{', '.join(a.get('name', '?') for a in analyzers)}. "
                f"Please check raw reports for details."
            )

        parsed_output["summary"] = auto_summary
        logger.warning("LLM summary empty — using improved auto-generated fallback summary")  # noqa: E501

    def _ensure_required_keys(self, parsed_output, missing_keys):
        for k in missing_keys:
            parsed_output[k] = (
                [] if "iocs" in k or "pivots" in k or "categories" in k else 0 if "risk" in k else "low"  # noqa: E501
            )

    def _apply_auto_tags(self, parsed_output, job):
        for category in parsed_output["threat_categories"]:
            tag_label = f"ai:{category.lower().replace(' ', '-')}"
            tag, created = Tag.objects.get_or_create(label=tag_label)
            if created:
                logger.info(f"Created new tag: {tag_label}")
            job.tags.add(tag)

    def _prepare_analyzers(self, job):
        if not hasattr(job, "analyzerreports"):
            return []

        analyzers = self._build_analyzer_list(job.analyzerreports.all())
        analyzers = self._sort_analyzers_by_size(analyzers)
        self._presummarize_specific_analyzers(analyzers)
        return analyzers

    def _build_analyzer_list(self, analyzer_reports):
        return [
            {
                "name": ar.config.name,
                "status": ar.status,
                "report_summary": (
                    (
                        {k: self.smart_truncate(v, k) for k, v in ar.report.items()}  # noqa: E501
                        if isinstance(ar.report, dict)
                        else {
                            "report_list": (
                                str(ar.report)[:2500] + "..." if len(str(ar.report)) > 2500 else ar.report  # noqa: E501
                            )
                        }
                    )
                    if ar.report
                    else {}
                ),
                "errors": ar.errors[:3] if ar.errors else [],
            }
            for ar in analyzer_reports
        ]

    def _sort_analyzers_by_size(self, analyzers):
        analyzers.sort(
            key=lambda a: len(json.dumps(a["report_summary"])),
            reverse=False,
        )
        return analyzers

    def _presummarize_specific_analyzers(self, analyzers):
        for analyzer in analyzers:
            name = analyzer["name"]
            report = analyzer["report_summary"]

            if name == "Mnemonic_PassiveDNS" and isinstance(report, list):
                analyzer["report_summary"] = self._summarize_mnemonic_passivedns(report)  # noqa: E501

            elif name == "DShield":
                analyzer["report_summary"] = self._summarize_dshield(report)

    def _summarize_mnemonic_passivedns(self, report):
        domains = set()
        ntp_count = 0
        tor_count = 0
        google_count = 0
        suspicious_count = 0
        for entry in report:
            rrname = entry.get("rrname", "").lower()
            if "tor-exit" in rrname:
                tor_count += 1
            elif any(p in rrname for p in ["ntp.org", "pool.ntp.org", ".pool."]):  # noqa: E501
                ntp_count += 1
            elif "google" in rrname or "dns.google" in rrname:
                google_count += 1
            elif re.match(r"[0-9a-f]{8,}", rrname) or re.match(r"\d+\.\d+\.[a-z0-9]+\.[a-z]+", rrname):  # noqa: E501
                suspicious_count += 1
            else:
                domains.add(rrname)
        summary_str = f"{len(report)} resolutions. "
        if google_count:
            summary_str += f"{google_count} Google-related. "
        if tor_count:
            summary_str += f"{tor_count} TOR exit related. "
        if ntp_count:
            summary_str += f"{ntp_count} NTP pool resolutions (mostly historical). "  # noqa: E501
        if suspicious_count:
            summary_str += f"{suspicious_count} suspicious/random patterns. "
        if domains:
            summary_str += f"Other domains: {', '.join(list(domains)[:5])} ..."
        return {"pre_summary": summary_str}

    def _summarize_dshield(self, report):
        if "ip_details" not in report:
            return report
        count = len(report.get("ip_details", []))
        threat_feeds = ", ".join(report.get("ip_info", {}).get("threatfeeds", {}).keys())  # noqa: E501
        asn_info = report.get("ip_info", {}).get("comment", "no comment")
        summary_str = f"{count} port 53 connections observed. Comment: {asn_info}. Threat feeds: {threat_feeds or 'none'}."  # noqa: E501
        return {"pre_summary": summary_str}

    @staticmethod
    def smart_truncate(v, key):
        """
        Smart truncation for report fields, giving more space to important keys.  # noqa: E501
        """
        if isinstance(v, (list, dict)) and key in [
            "report",
            "rdata",
            "rrname",
            "passive_dns",
            "resolutions",
            "history",
        ]:
            return str(v)[:3000] + "..." if len(str(v)) > 3000 else v
        return str(v)[:800] + "..." if len(str(v)) > 800 else v
