"""Hash Verifier Plugin — Re-verify evidence integrity."""

from pathlib import Path
from deaddrop.core.case import CaseManager
from deaddrop.core.config import Config
from deaddrop.core.evidence import compute_hashes


def run(case_id: str, **kwargs) -> dict:
    """Re-verify all evidence in a case."""
    config = Config.load()
    mgr = CaseManager(config.db_path)
    evidence = mgr.list_evidence(case_id)

    results = {"total": len(evidence), "verified": 0, "failed": 0, "missing": 0}

    for ev in evidence:
        path = Path(ev["path"])
        if not path.exists():
            results["missing"] += 1
            continue

        current_sha256, current_md5 = compute_hashes(path)
        if current_sha256 == ev["sha256"] and current_md5 == ev["md5"]:
            results["verified"] += 1
        else:
            results["failed"] += 1
            results[f"failed_{ev['id']}"] = {
                "original_sha256": ev["sha256"],
                "current_sha256": current_sha256,
            }

    mgr.close()
    return results