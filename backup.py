import argparse
import hashlib
import json
import sqlite3
import time
from pathlib import Path

from server import default_data_dir


def main():
    parser = argparse.ArgumentParser(description="Create a consistent local Chronicle Inventory backup")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    source = args.data_dir.resolve() / "inventory.sqlite3"
    if not source.is_file():
        parser.error(f"No inventory database found at {source}")
    backup_dir = (args.destination or (args.data_dir / "backups")).resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = backup_dir / f"chronicle-{stamp}.sqlite3"
    with sqlite3.connect(source) as src, sqlite3.connect(target) as dst:
        src.backup(dst)
        result = dst.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise SystemExit("Backup integrity check failed")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest = target.with_suffix(".json")
    manifest.write_text(json.dumps({"created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "database": target.name, "sha256": digest}, indent=2), encoding="utf-8")
    print(f"Backup created: {target}")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()
