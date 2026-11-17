"""Vercel frontend adapter used by the lab release runner."""
import json
import os
import time
import urllib.error
import urllib.request

from .checks import staged_reference, stamp
from .errors import ReleaseError
from .settings import APP_DOMAIN, APP_ORIGIN, REPO_ROOT, VERCEL_API, VERCEL_CLI, VERCEL_PROJECT, VERCEL_TEAM


class Frontend:
    """Requires the runner's run() and log() process boundary."""

    # ---- the frontend (Vercel) ----------------------------------------------------------
    @staticmethod
    def vercel_token(required=True):
        token = os.environ.get("VERCEL_TOKEN")
        if not token and required:
            raise ReleaseError("VERCEL_TOKEN is not set; the frontend half of a release needs it")
        return token

    def vercel(self, *args):
        """The pinned Vercel CLI from the repository root, without AWS credentials. The token is an argument
        (the CLI's documented way), so it is never echoed: failures report only the command name and stderr."""
        env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_") and key != "VERCEL_TOKEN"}
        env.update(VERCEL_ORG_ID=VERCEL_TEAM, VERCEL_PROJECT_ID=VERCEL_PROJECT, VERCEL_TELEMETRY_DISABLED="1")
        return self.run(["npx", "--yes", VERCEL_CLI, *args, "--token", self.vercel_token()], env=env, cwd=REPO_ROOT)

    def vercel_api(self, method, path, body=None):
        separator = "&" if "?" in path else "?"
        request = urllib.request.Request(
            f"{VERCEL_API}{path}{separator}teamId={VERCEL_TEAM}", method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.vercel_token()}", "Content-Type": "application/json",
                     "User-Agent": "scoutgrid-lab-release"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                text = response.read()
        except urllib.error.HTTPError as error:
            raise ReleaseError(f"Vercel {method} {path} returned {error.code}: {error.read()[:300]!r}")
        except (urllib.error.URLError, TimeoutError) as error:
            raise ReleaseError(f"Vercel {method} {path} unreachable: {error}")
        return json.loads(text) if text.strip() else {}

    def frontend_deployment(self, deployment):
        found = self.vercel_api("GET", f"/v13/deployments/{deployment}")
        return {"deployment_id": found.get("id"), "url": found.get("url"), "ready_state": found.get("readyState"),
                "target": found.get("target"), "source_sha": (found.get("meta") or {}).get("githubCommitSha")}

    def checkout(self):
        """(HEAD commit, whether tracked files are unchanged) of the checkout this script runs from."""
        head = self.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"]).strip()
        return head, not self.run(["git", "-C", str(REPO_ROOT), "status", "--porcelain", "--untracked-files=no"]).strip()

    def frontend_stage(self, sha):
        """Build this checkout for production and upload it without assigning a domain (CD plan 4.5, step 1-2)."""
        head, clean = self.checkout()
        if head != sha:
            raise ReleaseError(f"this checkout is at {head[:7]}; check out {sha[:7]} to build its frontend")
        if not clean:
            raise ReleaseError("this checkout has uncommitted changes; the frontend must be built from the commit alone")
        self.log(f"Building the frontend for {sha[:7]} with {VERCEL_CLI} (production settings).")
        try:
            self.vercel("pull", "--yes", "--environment=production")
            self.vercel("build", "--prod")
        finally:
            # The pulled environment includes a short-lived Vercel OIDC token; the build no longer needs it.
            for pulled in (REPO_ROOT / ".vercel").glob(".env*.local"):
                pulled.unlink()
        reference = staged_reference(self.vercel("deploy", "--prebuilt", "--prod", "--skip-domain", "--json"))
        deadline = time.time() + 900
        while True:
            deployment = self.frontend_deployment(reference)
            if deployment["ready_state"] == "READY":
                break
            if deployment["ready_state"] in ("ERROR", "CANCELED") or time.time() > deadline:
                raise ReleaseError(f"the staged frontend {deployment['deployment_id']} is {deployment['ready_state']}")
            time.sleep(10)
        if deployment["target"] != "production":
            raise ReleaseError(f"the staged frontend {deployment['deployment_id']} targets {deployment['target']}")
        if deployment["source_sha"] not in (None, sha):
            raise ReleaseError(f"the staged frontend {deployment['deployment_id']} names commit {deployment['source_sha']}")
        return {"deployment_id": deployment["deployment_id"], "url": deployment["url"], "source_sha": sha,
                "cli": VERCEL_CLI, "staged_at": stamp()}

    def frontend_live(self, required=True):
        """The deployment the production domain serves now; None without a token when not required."""
        if not self.vercel_token(required):
            return None
        return self.vercel_api("GET", f"/v4/aliases/{APP_DOMAIN}").get("deploymentId")

    def frontend_promote(self, deployment, timeout=300):
        self.log(f"Promoting {deployment} to {APP_DOMAIN}.")
        self.vercel_api("POST", f"/v10/projects/{VERCEL_PROJECT}/promote/{deployment}")
        deadline = time.time() + timeout
        while self.frontend_live() != deployment and time.time() < deadline:
            time.sleep(5)

    def app_status(self, path):
        request = urllib.request.Request(APP_ORIGIN + path, headers={"User-Agent": "scoutgrid-lab-release"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
        except (urllib.error.URLError, TimeoutError) as error:
            return f"unreachable: {error}"
