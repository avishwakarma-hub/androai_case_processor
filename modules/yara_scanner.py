"""
yara_scanner.py — YARA pre-scan to filter already-detected samples.

Compiles the main YARA export file (zstatic-apk-sig.yara) and any
LLM-generated YARA rules, then scans downloaded samples. Samples
that match any rule are considered "already detected" and are excluded
from further analysis.
"""

import glob
import logging
import os

try:
    import yara
except ImportError:
    yara = None  # handled at call-time with a clear error

logger = logging.getLogger("vt_pipeline.yara_scanner")


def load_rules(yara_scan_file: str, llm_yara_dir: str = None):
    """
    Compile YARA rules from the main export file and any LLM-generated
    rule files.

    Parameters
    ----------
    yara_scan_file : str
        Path to the main YARA rule file (e.g. zstatic-apk-sig.yara).
    llm_yara_dir : str, optional
        Directory containing individual ``*.yara`` rule files generated
        by the LLM pipeline.

    Returns
    -------
    list
        A list of compiled yara.Rules objects.
    """
    if yara is None:
        logger.error(
            "yara-python is not installed — cannot perform YARA pre-scan. "
            "Install with: pip install yara-python"
        )
        return []

    compiled_rules = []

    # 1) Main YARA export file
    if yara_scan_file and os.path.isfile(yara_scan_file):
        try:
            rules = yara.compile(filepath=yara_scan_file)
            compiled_rules.append(("zstatic-apk-sig", rules))
            logger.info("Compiled main YARA file: %s", yara_scan_file)
        except yara.Error as exc:
            logger.error("Failed to compile %s: %s", yara_scan_file, exc)
    else:
        logger.warning("Main YARA scan file not found: %s", yara_scan_file)

    # 2) LLM-generated YARA rules (individual .yara files)
    if llm_yara_dir and os.path.isdir(llm_yara_dir):
        yara_files = glob.glob(os.path.join(llm_yara_dir, "*.yara"))
        for yf in yara_files:
            try:
                rules = yara.compile(filepath=yf)
                compiled_rules.append((os.path.basename(yf), rules))
            except yara.Error as exc:
                logger.warning("Failed to compile LLM YARA rule %s: %s", yf, exc)
        if yara_files:
            logger.info(
                "Compiled %d LLM-generated YARA files from %s",
                len(yara_files), llm_yara_dir,
            )
    else:
        logger.debug("LLM YARA dir not found or not set: %s", llm_yara_dir)

    return compiled_rules


def scan_samples(compiled_rules: list, sample_paths: list) -> dict:
    """
    Scan samples against compiled YARA rules.

    Parameters
    ----------
    compiled_rules : list
        List of ``(name, yara.Rules)`` tuples from :func:`load_rules`.
    sample_paths : list[str]
        Absolute paths to sample files.

    Returns
    -------
    dict
        ``{"detected": [...], "undetected": [...]}`` where each item is a
        dict ``{"sha256": ..., "path": ..., "matched_rules": [...]}``.
    """
    if yara is None:
        logger.error("yara-python not installed — treating all samples as undetected")
        return {
            "detected": [],
            "undetected": [
                {"sha256": os.path.basename(p), "path": p, "matched_rules": []}
                for p in sample_paths
            ],
        }

    if not compiled_rules:
        logger.warning("No YARA rules compiled — treating all samples as undetected")
        return {
            "detected": [],
            "undetected": [
                {"sha256": os.path.basename(p), "path": p, "matched_rules": []}
                for p in sample_paths
            ],
        }

    detected = []
    undetected = []

    for sample_path in sample_paths:
        sha256 = os.path.basename(sample_path)
        matched = []

        for rule_name, rules in compiled_rules:
            try:
                matches = rules.match(filepath=sample_path)
                if matches:
                    matched.extend([f"{rule_name}:{m.rule}" for m in matches])
            except yara.Error as exc:
                logger.warning(
                    "YARA scan error on %s with %s: %s",
                    sha256, rule_name, exc,
                )

        entry = {
            "sha256": sha256,
            "path": sample_path,
            "matched_rules": matched,
        }

        if matched:
            logger.debug(
                "DETECTED %s — matched %d rule(s): %s",
                sha256, len(matched), ", ".join(matched[:5]),
            )
            detected.append(entry)
        else:
            undetected.append(entry)

    logger.info(
        "YARA scan complete: %d detected, %d undetected (of %d total)",
        len(detected), len(undetected), len(sample_paths),
    )
    return {"detected": detected, "undetected": undetected}
