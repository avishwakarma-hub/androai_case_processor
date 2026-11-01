"""
artifact_builder.py — Build a ZIP artifact for Zintel case attachment.

Creates a ZIP file containing:
  reports/      — verdict JSONs and LLM analysis logs
  yara_rules/   — individual YARA rule files + combined_rules.yara
  pipeline_summary.json — run metadata
"""

import json
import logging
import os
import zipfile
from datetime import datetime, timezone

logger = logging.getLogger("vt_pipeline.artifact_builder")


def build_artifact_zip(
    family: str,
    parsed_verdicts: list,
    report_dir: str,
    output_dir: str,
    run_metadata: dict = None,
) -> str:
    """
    Build a ZIP artifact containing reports and YARA rules.

    Parameters
    ----------
    family : str
        Malware family name (used in the ZIP filename).
    parsed_verdicts : list[dict]
        List of parsed verdict dicts from :func:`report_parser.parse_verdicts`.
    report_dir : str
        Path to the androAiV2 report directory.
    output_dir : str
        Directory to save the ZIP file into.
    run_metadata : dict, optional
        Additional metadata to include in pipeline_summary.json.

    Returns
    -------
    str
        Absolute path to the created ZIP file.
    """
    os.makedirs(output_dir, exist_ok=True)

    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    zip_name = f"{family}_{date_str}.zip"
    zip_path = os.path.join(output_dir, zip_name)

    # Collect YARA rules from verdicts
    yara_rules = {}
    combined_yara = []
    snort_rules = {}
    combined_snort = []
    all_cif_entries = []
    for v in parsed_verdicts:
        sha_prefix = v["sha256"][:16]
        if v.get("yara_rule"):
            rule_filename = f"{family}_{sha_prefix}.yara"
            yara_rules[rule_filename] = v["yara_rule"]
            combined_yara.append(v["yara_rule"])
        if v.get("snort_rules"):
            snort_filename = f"{family}_{sha_prefix}.rules"
            snort_rules[snort_filename] = v["snort_rules"]
            combined_snort.append(v["snort_rules"])
        if v.get("cif_entries"):
            all_cif_entries.extend(v["cif_entries"])

    # Build the summary
    summary = {
        "family": family,
        "run_date": datetime.now(timezone.utc).isoformat(),
        "samples_analysed": len(parsed_verdicts),
        "malicious_count": sum(1 for v in parsed_verdicts if v.get("is_malicious")),
        "yara_rules_generated": len(yara_rules),
        "snort_rules_generated": len(snort_rules),
        "cif_entries_count": len(all_cif_entries),
        "samples": [],
    }
    for v in parsed_verdicts:
        summary["samples"].append({
            "sha256": v["sha256"],
            "is_malicious": v.get("is_malicious", False),
            "risk_score": v.get("risk_score", 0),
            "category": v.get("category", ""),
            "summary": v.get("summary", "")[:300],
            "has_yara": v.get("yara_rule") is not None,
            "has_snort": v.get("snort_rules") is not None,
            "has_cif": bool(v.get("cif_entries")),
            "analysis_time_sec": v.get("analysis_time_sec", 0),
        })
    if run_metadata:
        summary["run_metadata"] = run_metadata

    # Create ZIP
    logger.info("Building artifact ZIP: %s", zip_path)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1) Verdict JSONs
        for v in parsed_verdicts:
            verdict_file = v.get("verdict_file")
            if verdict_file and os.path.isfile(verdict_file):
                arcname = f"reports/{os.path.basename(verdict_file)}"
                zf.write(verdict_file, arcname)

        # 2) Analysis logs
        for v in parsed_verdicts:
            log_file = v.get("log_file")
            if log_file and os.path.isfile(log_file):
                arcname = f"reports/{os.path.basename(log_file)}"
                zf.write(log_file, arcname)

        # 3) Individual YARA rules
        for rule_filename, rule_text in yara_rules.items():
            zf.writestr(f"yara_rules/{rule_filename}", rule_text)

        # 4) Combined YARA rules file
        if combined_yara:
            combined_text = "\n\n".join(combined_yara)
            zf.writestr("yara_rules/combined_rules.yara", combined_text)

        # 5) Individual Snort rules
        for rule_filename, rule_text in snort_rules.items():
            zf.writestr(f"snort_rules/{rule_filename}", rule_text)

        # 6) Combined Snort rules file
        if combined_snort:
            combined_text = "\n\n".join(combined_snort)
            zf.writestr("snort_rules/combined_rules.rules", combined_text)

        # 7) CIF entries
        if all_cif_entries:
            zf.writestr(
                "cif/cif_entries.json",
                json.dumps(all_cif_entries, indent=2, ensure_ascii=False),
            )

        # 8) Pipeline summary
        zf.writestr(
            "pipeline_summary.json",
            json.dumps(summary, indent=2, ensure_ascii=False),
        )

    zip_size = os.path.getsize(zip_path)
    logger.info(
        "Artifact ZIP created: %s (%d bytes, %d reports, %d YARA, %d Snort, %d CIF)",
        zip_path, zip_size, len(parsed_verdicts),
        len(yara_rules), len(snort_rules), len(all_cif_entries),
    )
    return zip_path
