"""
androai_runner.py — Invoke androAiV2 analysis as a subprocess.

Calls the multi-model analysis script on a directory of APK samples,
waits for completion, and returns the result.
"""

import logging
import os
import subprocess

logger = logging.getLogger("vt_pipeline.androai_runner")


def run_analysis(
    androai_root: str,
    androai_script: str,
    venv_python: str,
    sample_dir: str,
    report_dir: str,
    lease_hours: float = 0.25,
    generate_rules: bool = True,
    vt_enrich: bool = True,
    timeout: int = 7200,
) -> dict:
    """
    Run androAiV2 analysis on a folder of APK samples.

    Parameters
    ----------
    androai_root : str
        Root directory of the androAiV2 project.
    androai_script : str
        Relative path (from androai_root) to the analysis script.
    venv_python : str
        Absolute path to the Python interpreter in the androAiV2 venv.
    sample_dir : str
        Directory containing APK samples to analyse.
    report_dir : str
        Directory where reports will be written.
    lease_hours : float
        --lease-hours value (controls how long workers run).
    generate_rules : bool
        Whether to pass --generate-rules flag.
    vt_enrich : bool
        Whether to pass --vt-enrich flag.
    timeout : int
        Maximum seconds to wait for analysis to complete (default: 2h).

    Returns
    -------
    dict
        ``{"success": bool, "exit_code": int, "stdout": str, "stderr": str}``
    """
    script_path = os.path.join(androai_root, androai_script)
    if not os.path.isfile(script_path):
        logger.error("androAiV2 script not found: %s", script_path)
        return {"success": False, "exit_code": -1, "stdout": "", "stderr": "script not found"}

    if not os.path.isfile(venv_python):
        logger.error("androAiV2 venv python not found: %s", venv_python)
        return {"success": False, "exit_code": -1, "stdout": "", "stderr": "venv python not found"}

    os.makedirs(report_dir, exist_ok=True)

    cmd = [
        venv_python,
        script_path,
        sample_dir,
        "--report-dir", report_dir,
        "--lease-hours", str(lease_hours),
    ]
    if generate_rules:
        cmd.append("--generate-rules")
    if vt_enrich:
        cmd.append("--vt-enrich")

    logger.info("Starting androAiV2 analysis")
    logger.info("  Sample dir : %s", sample_dir)
    logger.info("  Report dir : %s", report_dir)
    logger.info("  Lease hours: %s", lease_hours)
    logger.debug("  Command    : %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=androai_root,
        )
        success = proc.returncode == 0 or proc.returncode == 20
        # exit code 20 = "all keys unavailable" (normal when lease expires)

        if success:
            logger.info(
                "androAiV2 analysis completed (exit_code=%d)", proc.returncode,
            )
        else:
            logger.error(
                "androAiV2 analysis failed (exit_code=%d)", proc.returncode,
            )
            if proc.stderr:
                logger.error("stderr: %s", proc.stderr[-2000:])

        return {
            "success": success,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }

    except subprocess.TimeoutExpired:
        logger.error("androAiV2 analysis timed out after %d seconds", timeout)
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"timeout after {timeout}s",
        }
    except Exception as exc:
        logger.error("Failed to run androAiV2: %s", exc)
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": str(exc),
        }
