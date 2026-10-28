#!/usr/bin/env python3
"""Conservative PR selection; missing or empty change lists run verification."""
import json
import os
from pathlib import Path, PurePosixPath
import subprocess


def classify(files, event):
    docs_only = bool(files) and all(path == "README.md" or (path.startswith("prototype-app/docs/") and PurePosixPath(path).suffix == ".md") for path in files)
    application = event != "pull_request" or not docs_only
    performance = event != "pull_request" or (not docs_only and (not files or any(path.startswith(("prototype-app/backend/", "prototype-app/scripts/", "prototype-app/docs/", ".github/")) for path in files)))
    return dict(application=application, performance=performance)


def main():
    event = os.environ.get("GITHUB_EVENT_NAME", "local")
    files = []
    if event == "pull_request":
        payload = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        base = payload["pull_request"]["base"]["sha"]
        files = subprocess.check_output(["git", "diff", "--name-only", "-z", base, "HEAD"]).decode().strip("\0").split("\0")
        files = [path for path in files if path]
    result = classify(files, event)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        for key, value in result.items():
            stream.write(f"{key}={str(value).lower()}\n")
    print(json.dumps(dict(files=files, **result)))


if __name__ == "__main__":
    main()
