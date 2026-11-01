"""
report_parser.py — Parse androAiV2 verdict JSONs and extract YARA rules.

Reads *_verdict.json files from a report directory, extracts the verdict,
summary, IOCs, YARA rules, and analysis metadata for each sample.
"""

import glob
import json
import logging
import os

logger = logging.getLogger("vt_pipeline.report_parser")


def parse_verdicts(report_dir: str) -> list:
    """
    Parse all ``*_verdict.json`` files in *report_dir*.

    Parameters
    ----------
    report_dir : str
        Path to the report directory produced by androAiV2.

    Returns
    -------
    list[dict]
        One dict per sample with keys:
        - sha256, status, is_malicious, risk_score, summary, iocs,
        - yara_rule (str or None), yara_rule_path (str or None),
        - yara_valid (bool), category, family,
        - analysis_time_sec, verdict_file, log_file
    """
    pattern = os.path.join(report_dir, "*_verdict.json")
    verdict_files = glob.glob(pattern)

    if not verdict_files:
        logger.warning("No verdict files found in %s", report_dir)
        return []

    results = []
    for vf in verdict_files:
        try:
            with open(vf, "r") as fh:
                data = json.load(fh)
        except Exception as exc:
            logger.error("Failed to parse %s: %s", vf, exc)
            continue

        sha256 = data.get("sha256", "")
        verdict = data.get("verdict", {})
        gen_rules = verdict.get("generated_rules", {}) or {}

        # Corresponding analysis log
        log_file = vf.replace("_verdict.json", "_llm_analysis.log")
        if not os.path.exists(log_file):
            log_file = None

        entry = {
            "sha256": sha256,
            "status": data.get("status", "unknown"),
            "is_malicious": verdict.get("Malicious", 0) == 1,
            "risk_score": verdict.get("Risk-Score", 0),
            "summary": verdict.get("Summary", ""),
            "iocs": verdict.get("IOCs", []),
            "yara_rule": gen_rules.get("yara_rule"),
            "yara_rule_path": gen_rules.get("yara_rule_path"),
            "yara_valid": (
                gen_rules.get("yara_validation", {}) or {}
            ).get("valid", False),
            "snort_rules": gen_rules.get("snort_rules"),
            "snort_rules_path": gen_rules.get("snort_rules_path"),
            "cif_entries": gen_rules.get("cif_entries", []) or [],
            "cif_path": gen_rules.get("cif_path"),
            "category": (gen_rules.get("ioc_summary", {}) or {}).get("category", ""),
            "family": (gen_rules.get("ioc_summary", {}) or {}).get("family", ""),
            "analysis_time_sec": data.get("analysis_time_sec", 0),
            "llm_call_count": data.get("llm_call_count", 0),
            "llm_total_tokens": data.get("llm_total_tokens", 0),
            "verdict_file": vf,
            "log_file": log_file,
        }
        results.append(entry)
        logger.debug(
            "Parsed %s: malicious=%s risk=%d yara=%s",
            sha256[:16], entry["is_malicious"], entry["risk_score"],
            "yes" if entry["yara_rule"] else "no",
        )

    logger.info(
        "Parsed %d verdict(s): %d malicious, %d YARA, %d Snort, %d CIF",
        len(results),
        sum(1 for r in results if r["is_malicious"]),
        sum(1 for r in results if r["yara_rule"]),
        sum(1 for r in results if r["snort_rules"]),
        sum(1 for r in results if r["cif_entries"]),
    )
    return results


def collect_analysis_logs(report_dir: str) -> list:
    """
    Return paths to all ``*_llm_analysis.log`` files in the report dir.

    Parameters
    ----------
    report_dir : str
        Path to the report directory.

    Returns
    -------
    list[str]
        Absolute paths to log files.
    """
    pattern = os.path.join(report_dir, "*_llm_analysis.log")
    logs = glob.glob(pattern)
    logger.debug("Found %d analysis log files", len(logs))
    return logs
