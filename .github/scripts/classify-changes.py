#!/usr/bin/env python3
"""Select CI components from changed paths.

Conservative by design: pushes, an empty or missing change list, any
`.github/` change and any path no rule recognises select every component.
A component is skipped only when every changed path is known not to affect it.
"""
import json
import os
from pathlib import Path, PurePosixPath
import subprocess

COMPONENTS = ("frontend", "backend", "infrastructure")

# Paths that no build, test or scan reads. Changing only these runs the
# always-on static and secret checks and nothing else.
NO_COMPONENT_PREFIXES = ("prototype-app/Working Knowledge/",)
# Under docs/, only Markdown is inert; any other file type is treated as unknown.
MARKDOWN_ONLY_PREFIXES = ("prototype-app/docs/",)
NO_COMPONENT_FILES = {
    "README.md",
    "prototype-app/README.md",
    ".gitignore",
    ".gitleaks.toml",
    ".gitleaksignore",
    ".pre-commit-config.yaml",
    ".mcp.json",
    ".trivyignore.yaml",
}
NO_COMPONENT_NAMES = {"CLAUDE.md", "AGENTS.md"}

# Ordered: the first matching prefix decides.
COMPONENT_PREFIXES = (
    ("prototype-app/frontend/", {"frontend"}),
    ("prototype-app/backend/", {"backend"}),
    ("prototype-app/infrastructure/", {"infrastructure"}),
    # Operator scripts, governed policy content and fixtures feed backend
    # tests and performance certification.
    ("prototype-app/scripts/", {"backend"}),
    ("prototype-app/policy-packages/", {"backend"}),
    ("prototype-app/certification/", {"backend"}),
    ("prototype-app/test-fixtures/", {"backend"}),
    ("prototype-app/sample-data/", {"backend"}),
)
COMPONENT_FILES = {
    ".nvmrc": {"frontend"},
    ".vercelignore": {"frontend"},
}


def components_for(path):
    """Return the components a single changed path selects."""
    if path.startswith(".github/"):
        return set(COMPONENTS)
    if path in NO_COMPONENT_FILES or PurePosixPath(path).name in NO_COMPONENT_NAMES:
        return set()
    if path.startswith(NO_COMPONENT_PREFIXES):
        return set()
    if path.startswith(MARKDOWN_ONLY_PREFIXES) and PurePosixPath(path).suffix == ".md":
        return set()
    if path in COMPONENT_FILES:
        return set(COMPONENT_FILES[path])
    for prefix, components in COMPONENT_PREFIXES:
        if path.startswith(prefix):
            return set(components)
    return set(COMPONENTS)


def classify(files, event):
    if event != "pull_request" or not files:
        selected = set(COMPONENTS)
    else:
        selected = set().union(*(components_for(path) for path in files))
    result = {name: name in selected for name in COMPONENTS}
    # Performance certification starts the backend, so it follows backend selection.
    result["performance"] = result["backend"]
    return result


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
