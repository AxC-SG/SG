"""Render common lab settings plus one explicit lifecycle mode as Terraform JSON."""
import argparse
import json
from pathlib import Path

MODES = ("running", "down", "noenroll", "stopped")


def runtime_config(mode, config_dir):
    if mode not in MODES:
        raise ValueError(f"unknown runtime mode: {mode}")
    common = json.loads((config_dir / "runtime-common.json").read_text())
    selected = json.loads((config_dir / f"runtime-{mode}.json").read_text())
    # Terraform replaces object values across var files. Merge the candidate explicitly,
    # then pass one rendered file so all modes retain the common credential references.
    return {**common, **selected, "backend_candidate": {
        **common["backend_candidate"], **selected["backend_candidate"]}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=MODES)
    args = parser.parse_args()
    print(json.dumps(runtime_config(args.mode, Path(__file__).resolve().parents[2] / "config"), indent=2))
