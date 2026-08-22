from __future__ import annotations

import argparse
import hmac
import json
import re
from pathlib import Path

import app.mission as mission_module

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def sha256_value(value: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("expected a lowercase 64-character SHA-256 digest")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a Sentinel Swarm mission manifest, artifacts, and hash-chained ledger."
    )
    parser.add_argument("mission_id", help="32-character mission identifier")
    parser.add_argument(
        "--data-dir",
        type=Path,
        help="mission data directory (defaults to SENTINEL_DATA_DIR or ./data)",
    )
    parser.add_argument(
        "--expected-manifest-sha256",
        type=sha256_value,
        help="externally retained manifest digest to compare with the local anchor",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.data_dir:
        mission_module.DATA = args.data_dir.expanduser().resolve()

    result = mission_module.verify_mission(args.mission_id)
    output = result.model_dump(mode="json")
    if args.expected_manifest_sha256 and (
        not result.manifest_sha256
        or not hmac.compare_digest(args.expected_manifest_sha256, result.manifest_sha256)
    ):
        output["valid"] = False
        output["errors"].append("Manifest does not match the externally retained SHA-256")

    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
