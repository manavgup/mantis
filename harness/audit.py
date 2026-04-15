"""Audit log writer with SHA-3 hash chaining — the compliance backbone."""

from __future__ import annotations

import fcntl
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def _read_last_entry(self) -> tuple[int, str]:
        """Return (last_seq, last_hash) from the log file.

        Returns (0, "genesis") if the file doesn't exist or is empty.
        """
        if not self._path.exists():
            return 0, "genesis"
        with open(self._path, "r") as f:
            last_line = ""
            for line in f:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
            if not last_line:
                return 0, "genesis"
            entry = json.loads(last_line)
            return entry["seq"], entry["this_hash"]

    def write(
        self,
        run_id: str,
        event_type: str,
        actor: str,
        payload: dict,
        job_id: str | None = None,
    ) -> str:
        """Append an audit entry. Returns this_hash.

        Synchronous with file locking — never async.
        """
        with open(self._path, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                # Re-read last entry under lock to avoid races
                f.seek(0)
                last_line = ""
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped

                if last_line:
                    last_entry = json.loads(last_line)
                    prev_seq = last_entry["seq"]
                    prev_hash = last_entry["this_hash"]
                else:
                    prev_seq = 0
                    prev_hash = "genesis"

                entry = {
                    "seq": prev_seq + 1,
                    "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "run_id": run_id,
                    "job_id": job_id,
                    "event_type": event_type,
                    "actor": actor,
                    "payload": payload,
                    "prev_hash": prev_hash,
                }

                # Hash covers the full entry including prev_hash but before this_hash is set
                this_hash = hashlib.sha3_256(
                    json.dumps(entry, sort_keys=True).encode()
                ).hexdigest()
                entry["this_hash"] = this_hash

                f.seek(0, 2)  # seek to end
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                f.flush()
                return this_hash
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)


def verify_chain(path: Path) -> tuple[bool, int | None]:
    """Verify the full hash chain. Returns (valid, broken_at_seq).

    If valid, returns (True, None). If broken, returns (False, seq_number).
    """
    if not path.exists():
        return True, None

    prev_hash = "genesis"
    with open(path, "r") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            entry = json.loads(stripped)
            seq = entry["seq"]

            if entry["prev_hash"] != prev_hash:
                return False, seq

            # Recompute hash: remove this_hash, serialize, hash
            stored_hash = entry.pop("this_hash")
            computed_hash = hashlib.sha3_256(
                json.dumps(entry, sort_keys=True).encode()
            ).hexdigest()
            entry["this_hash"] = stored_hash  # restore

            if computed_hash != stored_hash:
                return False, seq

            prev_hash = stored_hash

    return True, None
