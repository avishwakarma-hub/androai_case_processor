"""
state_manager.py — Persistent state for processed Zintel case IDs.

Tracks which cases have already been processed so that re-runs (e.g. via
cron) skip them.  The state is stored as a JSON file keyed by case ID.
"""

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger("androai_processor.state")


def load_state(state_path):
    """Load the processed-state dict from disk.

    Returns ``{"schema_version": 1, "processed": {}}`` if the file is
    missing or unreadable.
    """
    if not os.path.isfile(state_path):
        logger.info("No state file found at %s — starting fresh", state_path)
        return {"schema_version": 1, "processed": {}}

    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        count = len(data.get("processed", {}))
        logger.info("Loaded state with %d processed case(s) from %s", count, state_path)
        return data
    except Exception as exc:
        logger.warning("Failed to load state from %s: %s — starting fresh", state_path, exc)
        return {"schema_version": 1, "processed": {}}


def save_state(state_path, state):
    """Atomically persist the state dict to disk."""
    os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
    state["last_updated"] = datetime.now(timezone.utc).isoformat()
    tmp = state_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, state_path)
    logger.info("Saved state (%d processed cases) to %s", len(state.get("processed", {})), state_path)


def mark_processed(state, case_id, entry):
    """Record a case as processed in the in-memory state dict."""
    entry.setdefault("processed_at", datetime.now(timezone.utc).isoformat())
    state.setdefault("processed", {})[str(case_id)] = entry


def is_processed(state, case_id):
    """Check whether a case has already been processed."""
    return str(case_id) in state.get("processed", {})
