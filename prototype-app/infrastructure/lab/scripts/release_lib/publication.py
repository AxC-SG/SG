"""GitHub publication lookup, including producer and candidate verification."""
import importlib.util
import io
import json
import subprocess
import zipfile

from .checks import check_publication
from .errors import ReleaseError
from .settings import FULL_SHA, REPO, REPO_ROOT

spec = importlib.util.spec_from_file_location("publication_provenance", REPO_ROOT / ".github/scripts/publication_provenance.py")
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


class PublicationSource:
    """Requires the runner's run() process boundary."""

    def resolve_sha(self, ref):
        sha = self.run(["gh", "api", f"repos/{REPO}/commits/{ref}", "--jq", ".sha"]).strip()
        if not FULL_SHA.fullmatch(sha):
            raise ReleaseError(f"cannot resolve {ref} to a commit")
        return sha

    def github_api(self, path, params=None):
        command = ["gh", "api", "--method", "GET", path]
        for key, value in (params or {}).items():
            command += ["-f", f"{key}={value}"]
        return json.loads(self.run(command))

    def publication(self, sha, required=True):
        """The lab publication record for sha; None when there is none and it is not required."""
        name = f"aws-publication-lab-{sha}"
        artifacts = json.loads(self.run(["gh", "api", "--method", "GET", f"repos/{REPO}/actions/artifacts",
                                         "-f", f"name={name}", "-f", "per_page=100"]))["artifacts"]
        live = provenance.trusted_artifacts(self.github_api, REPO, artifacts, sha)
        if not live and not required:
            return None
        if not live:
            raise ReleaseError(f"{sha[:7]} has no lab publication record; it is published once its main checks pass")
        # Download this immutable artifact, not another artifact selected again by name.
        payload = subprocess.run(["gh", "api", f"repos/{REPO}/actions/artifacts/{live[-1]['id']}/zip"],
                                 check=True, capture_output=True).stdout
        with zipfile.ZipFile(io.BytesIO(payload)) as zipped:
            record = json.loads(zipped.read("aws-publication.json"))
        try:
            provenance.validate_candidate(self.github_api, REPO, record, sha)
            producing = self.github_api(f"repos/{REPO}/actions/runs/{live[-1]['workflow_run']['id']}")
            if producing.get("event") == "push" and str(record.get("candidate_run")) != str(producing.get("id")):
                raise ValueError("publication is not bound to its producing Quality run")
        except ValueError as error:
            raise ReleaseError(f"publication provenance rejected: {error}") from error
        check_publication(record, sha)
        return record
