"""
llm_pipeline.py — Main orchestrator for the AndroAI case processor.

Designed to run via cron (e.g. weekly).  For each enabled researcher and
case-name prefix the pipeline discovers assigned Zintel cases, downloads
samples, runs androAiV2, and uploads artifacts back to the case.

Usage
-----
    python3 llm_pipeline.py
    python3 llm_pipeline.py --dry-run
    python3 llm_pipeline.py --config config/config.yaml
"""

import argparse
import logging
import os
import sys
from datetime import datetime

from modules.config_loader import load_config, load_env_file
from modules.zintel_client import ZintelClient
from modules.state_manager import (
    load_state, save_state, mark_processed, is_processed,
)
from modules.case_processor import process_case


def setup_logging(log_dir, level="INFO"):
    """Configure logging to console and a timestamped log file."""
    os.makedirs(log_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, "pipeline_run_%s.log" % ts)

    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.addHandler(fh)
    root.addHandler(ch)
    return log_file


def load_yara_rules(cfg):
    """Load YARA rules if enabled in config."""
    yara_cfg = cfg.get("yara", {})
    if not yara_cfg.get("enabled", False):
        return []
    from modules.yara_scanner import load_rules
    return load_rules(
        yara_cfg.get("scan_file", ""),
        yara_cfg.get("llm_generated_dir"),
    )


def _retry_failed_uploads(state, state_path, zintel, cfg, logger):
    """Retry artifact uploads for cases where processing succeeded but upload failed.

    Scans the state file for entries with ``artifact_attached: false`` and a
    valid ``artifact_zip_path`` on disk, then retries the upload.
    """
    processed = state.get("processed", {})
    artifact_dir = cfg["paths"]["artifact_dir"]
    candidates = []

    for case_id, entry in processed.items():
        if entry.get("artifact_attached"):
            continue
        # Skip entries that errored before reaching the artifact stage
        if not entry.get("artifact_zip_path") and not entry.get("case_name"):
            continue
        candidates.append((case_id, entry))

    if not candidates:
        logger.info("No failed uploads found in state — nothing to retry")
        return 0

    logger.info("Found %d case(s) with failed artifact uploads", len(candidates))
    success_count = 0
    fail_count = 0

    for case_id, entry in candidates:
        case_name = entry.get("case_name", "")
        logger.info("Retrying upload for case %s (%s)", case_id, case_name)

        # Try the recorded path first
        zip_path = entry.get("artifact_zip_path", "")
        if not zip_path or not os.path.isfile(zip_path):
            # Scan the artifact directory for a matching ZIP
            zip_path = _find_artifact_zip(artifact_dir, case_name)

        if not zip_path:
            logger.warning("No artifact ZIP found for case %s (%s) — skipping", case_id, case_name)
            fail_count += 1
            continue

        ok = zintel.attach_artifact_to_case(case_id, zip_path)
        if ok:
            entry["artifact_attached"] = True
            entry["artifact_zip_path"] = zip_path
            logger.info("Upload succeeded for case %s", case_id)
            success_count += 1
        else:
            logger.error("Upload still failing for case %s", case_id)
            fail_count += 1

        save_state(state_path, state)

    logger.info(
        "Retry complete: %d succeeded, %d failed (of %d total)",
        success_count, fail_count, len(candidates),
    )
    return 0 if fail_count == 0 else 1


def _find_artifact_zip(artifact_dir, case_name):
    """Search *artifact_dir* for a ZIP whose name starts with *case_name*."""
    if not case_name or not os.path.isdir(artifact_dir):
        return None
    for fname in sorted(os.listdir(artifact_dir), reverse=True):
        if fname.startswith(case_name) and fname.endswith(".zip"):
            return os.path.join(artifact_dir, fname)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="AndroAI case processor - cron-based LLM analysis pipeline",
    )
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--retry-uploads",
        action="store_true",
        help="Retry artifact uploads for previously processed cases where upload failed",
    )
    args = parser.parse_args()

    load_env_file(args.env_file)
    cfg = load_config(args.config)

    pcfg = cfg["pipeline"]
    log_file = setup_logging(cfg["paths"]["log_dir"], pcfg.get("log_level", "INFO"))
    logger = logging.getLogger("androai_processor")
    logger.info("AndroAI Case Processor starting - log: %s", log_file)
    if args.dry_run:
        logger.info("DRY RUN mode enabled")

    state_path = cfg["paths"]["state_file"]
    state = load_state(state_path)
    zintel = ZintelClient(cfg["zintel"])

    # ------------------------------------------------------------------
    # --retry-uploads: re-upload artifacts for cases that were processed
    # successfully but where the artifact upload failed.
    # ------------------------------------------------------------------
    if args.retry_uploads:
        return _retry_failed_uploads(state, state_path, zintel, cfg, logger)

    compiled_yara = load_yara_rules(cfg)

    total_processed = 0
    total_skipped = 0
    total_errors = 0

    for researcher in cfg["researchers"]:
        rid = researcher["id"]
        rname = researcher.get("name", str(rid))
        if not researcher.get("enabled", True):
            logger.info("Researcher %s (ID=%s) disabled - skipping", rname, rid)
            continue

        logger.info("-" * 60)
        logger.info("Researcher: %s (ID=%s)", rname, rid)

        for prefix_cfg in researcher.get("case_prefixes", []):
            prefix = prefix_cfg.get("prefix", "")
            if not prefix or not prefix_cfg.get("enabled", True):
                continue

            logger.info("Querying prefix: %s", prefix)
            cases = zintel.get_cases_by_prefix(rid, prefix, status="assigned")

            for case_info in cases:
                case_id = str(case_info.get("id", ""))
                if not case_id:
                    continue
                if is_processed(state, case_id):
                    logger.debug("Case %s already processed", case_id)
                    total_skipped += 1
                    continue

                try:
                    result = process_case(
                        case_info, cfg, zintel, compiled_yara,
                        dry_run=args.dry_run,
                    )
                    result["researcher_id"] = rid
                    result["prefix"] = prefix
                    mark_processed(state, case_id, result)
                    total_processed += 1
                    if result.get("errors"):
                        total_errors += 1
                        for err in result["errors"]:
                            logger.warning("Case %s error: %s", case_id, err)
                except Exception as exc:
                    logger.error("Unhandled error for case %s: %s", case_id, exc, exc_info=True)
                    mark_processed(state, case_id, {
                        "researcher_id": rid, "prefix": prefix,
                        "case_name": case_info.get("name", ""),
                        "errors": [str(exc)],
                    })
                    total_errors += 1

                save_state(state_path, state)

    logger.info("=" * 60)
    logger.info(
        "Pipeline complete: processed=%d skipped=%d errors=%d",
        total_processed, total_skipped, total_errors,
    )
    return 0 if total_errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
