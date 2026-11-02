"""
case_processor.py — Per-case processing logic for the androAI pipeline.
"""

import logging
import os
import shutil
from datetime import datetime, timezone

from modules.androai_runner import run_analysis
from modules.report_parser import parse_verdicts
from modules.artifact_builder import build_artifact_zip

logger = logging.getLogger("androai_processor")


def build_case_comment(verdicts, scan_summary, case_name):
    """Build a structured comment string for the Zintel case."""
    run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    mal = sum(1 for v in verdicts if v.get("is_malicious"))
    yc = sum(1 for v in verdicts if v.get("yara_rule"))
    sc = sum(1 for v in verdicts if v.get("snort_rules"))

    lines = [
        "[AndroAI Case Processor - %s]" % run_date,
        "",
        "Source case: %s" % case_name,
        "Samples analysed: %d" % len(verdicts),
        "Malicious: %d | YARA rules: %d | Snort rules: %d" % (mal, yc, sc),
    ]
    if scan_summary:
        lines += [
            "",
            "--- Pre-scan Summary ---",
            "  Downloaded: %s" % scan_summary.get("downloaded", "N/A"),
            "  YARA-detected (skipped): %s" % scan_summary.get("yara_detected", 0),
            "  Undetected (analysed): %s" % scan_summary.get("undetected", 0),
        ]
    lines += ["", "--- Sample Verdicts ---"]
    for v in verdicts[:50]:
        status = "MALICIOUS" if v.get("is_malicious") else "CLEAN"
        risk = v.get("risk_score", 0)
        yt = " [YARA]" if v.get("yara_rule") else ""
        st = " [Snort]" if v.get("snort_rules") else ""
        sha = v.get("sha256", "")[:16]
        snippet = (v.get("summary", "") or "")[:120]
        lines.append("  %s... - %s Risk:%s%s%s" % (sha, status, risk, yt, st))
        if snippet:
            lines.append("    %s" % snippet)
    if len(verdicts) > 50:
        lines.append("  ... +%d more" % (len(verdicts) - 50))
    lines += ["", "Artifact ZIP attached with full reports, YARA and Snort rules."]
    return "\n".join(lines)


def process_case(case_info, cfg, zintel, compiled_yara, dry_run=False):
    """Process a single Zintel case end-to-end.

    Returns a result dict suitable for state_manager.mark_processed().
    """
    paths = cfg["paths"]
    pcfg = cfg["pipeline"]
    androai_cfg = cfg["androai"]
    case_id = str(case_info.get("id", ""))
    case_name = case_info.get("name", "")
    logger.info("=" * 60)
    logger.info("PROCESSING CASE: %s (%s)", case_name, case_id)

    entry = {
        "case_name": case_name, "samples_downloaded": 0, "yara_detected": 0,
        "samples_analysed": 0, "malicious_count": 0, "yara_rules_generated": 0,
        "artifact_attached": False, "comment_added": False, "errors": [],
    }

    # 1 — Fetch sample MD5 list
    md5s = zintel.get_case_samples(case_id)
    if not md5s:
        logger.warning("No samples in case %s", case_id)
        entry["errors"].append("no samples in case")
        return entry

    # 2 — Download samples
    case_sample_dir = os.path.join(paths["sample_download_dir"], case_id)
    sample_paths = zintel.download_samples(md5s, case_sample_dir)
    entry["samples_downloaded"] = len(sample_paths)
    if not sample_paths:
        entry["errors"].append("download failed")
        return entry

    # 3 — YARA pre-scan
    scan_summary = {"downloaded": len(sample_paths), "yara_detected": 0, "undetected": 0}
    if compiled_yara:
        from modules.yara_scanner import scan_samples
        scan = scan_samples(compiled_yara, sample_paths)
        detected = scan["detected"]
        entry["yara_detected"] = len(detected)
        scan_summary["yara_detected"] = len(detected)
        for d in detected:
            try:
                os.remove(d["path"])
            except OSError:
                pass
        sample_paths = [u["path"] for u in scan["undetected"]]
    scan_summary["undetected"] = len(sample_paths)

    if not sample_paths:
        logger.info("All samples in case %s already detected by YARA", case_id)
        return entry

    max_batch = pcfg.get("max_samples_per_batch", 50)
    if len(sample_paths) > max_batch:
        logger.info("Trimming %d samples to %d", len(sample_paths), max_batch)
        for extra in sample_paths[max_batch:]:
            try:
                os.remove(extra)
            except OSError:
                pass
        sample_paths = sample_paths[:max_batch]
    entry["samples_analysed"] = len(sample_paths)

    if dry_run:
        logger.info("[DRY RUN] Skipping analysis for case %s", case_id)
        return entry

    # 4 — Run androAiV2
    report_dir = os.path.join(paths["report_dir"], case_id)
    analysis = run_analysis(
        androai_root=androai_cfg["root"],
        androai_script=androai_cfg["script"],
        venv_python=androai_cfg["venv_python"],
        sample_dir=case_sample_dir,
        report_dir=report_dir,
        lease_hours=androai_cfg.get("lease_hours", 0.25),
        generate_rules=androai_cfg.get("generate_rules", True),
        vt_enrich=androai_cfg.get("vt_enrich", True),
        timeout=androai_cfg.get("timeout", 7200),
    )
    if not analysis["success"]:
        entry["errors"].append("androAI failed: exit=%s" % analysis["exit_code"])
        return entry

    # 5 — Parse verdicts
    verdicts = parse_verdicts(report_dir)
    entry["malicious_count"] = sum(1 for v in verdicts if v.get("is_malicious"))
    entry["yara_rules_generated"] = sum(1 for v in verdicts if v.get("yara_rule"))
    if not verdicts:
        entry["errors"].append("no verdicts produced")
        return entry

    # 6 — Build artifact ZIP
    artifact_zip = build_artifact_zip(
        family=case_name, parsed_verdicts=verdicts, report_dir=report_dir,
        output_dir=paths["artifact_dir"],
        run_metadata={"case_id": case_id, "scan_summary": scan_summary},
    )

    # 7 — Upload artifact + add comment
    entry["artifact_zip_path"] = artifact_zip
    entry["artifact_attached"] = zintel.attach_artifact_to_case(case_id, artifact_zip)
    comment = build_case_comment(verdicts, scan_summary, case_name)
    zintel.add_comment_to_case(case_id, comment)
    entry["comment_added"] = True

    # 8 — Cleanup
    if pcfg.get("cleanup_samples_after_run", True):
        try:
            shutil.rmtree(case_sample_dir, ignore_errors=True)
            logger.info("Cleaned up sample dir: %s", case_sample_dir)
        except Exception as exc:
            logger.warning("Cleanup failed for %s: %s", case_sample_dir, exc)

    return entry
