"""Main orchestration: fetch pool credentials and drive the scan."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import IO, List, Optional

import boto3
from botocore import UNSIGNED
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

from . import __version__
from .config import Config
from .console import console
from .credentials import AWSCredentials
from .logger import Log
from .tester import ServiceTester


class PoolDiver:
    def __init__(self, config: Config, log: Log) -> None:
        self.config = config
        self.log = log

    def get_pool_credentials(self, region: str, identity_pool: str) -> AWSCredentials:
        self.log.info(
            f"Fetching credentials for pool [bold]{identity_pool}[/] in [bold]{region}[/]"
        )
        # The unauthenticated Cognito flow is public: issue unsigned requests so
        # PoolDiver works even with no local AWS credentials configured.
        client = boto3.client(
            "cognito-identity",
            region_name=region,
            config=BotoConfig(signature_version=UNSIGNED),
        )

        with console.status("[cyan]Requesting identity id...", spinner="dots"):
            identity_id = client.get_id(IdentityPoolId=identity_pool)["IdentityId"]
        self.log.good(f"Identity obtained: [bold]{identity_id}[/]")

        with console.status("[cyan]Requesting credentials for identity...", spinner="dots"):
            creds_response = client.get_credentials_for_identity(IdentityId=identity_id)
        c = creds_response["Credentials"]

        creds = AWSCredentials(
            access_key=c["AccessKeyId"],
            secret_key=c["SecretKey"],
            session_token=c["SessionToken"],
            identity_id=identity_id,
            region=region,
            expiration=c.get("Expiration"),
            identity_pool=identity_pool,
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        cred_file = (self.config.credentials_dir /
                     f"credentials_{identity_id.replace(':', '_')}_{timestamp}.json")
        creds.save_to_file(cred_file)
        self.log.good(f"Credentials saved to {cred_file}")
        return creds

    def run(self, *, region: str, identity: str, test: bool,
            no_enumerate: bool) -> None:
        #self.log.info(f"PoolDiver v{__version__} starting...")

        creds = self.get_pool_credentials(region, identity)
        self.log.good(f"Obtained credentials for identity: [bold]{creds.identity_id}[/]")

        session = creds.boto_session()

        # Confirm what these credentials map to.
        identity_arn: Optional[str] = None
        try:
            identity_arn = session.client("sts").get_caller_identity()["Arn"]
            self.log.good(f"Authenticated as: [bold]{identity_arn}[/]")
        except (ClientError, BotoCoreError) as e:
            self.log.warn(f"Could not determine identity: {e}")

        if test:
            self.log.info("Starting AWS service permission tests...")
            # No bucket given? Guess likely names from the role ARN (MobileHub /
            # Amplify follow predictable conventions) so prefix enumeration can
            # still run without the user knowing the bucket up front.
            if "s3" in self.config.services and not self.config.s3_buckets:
                guesses = self._candidate_buckets(identity_arn)
                if guesses:
                    self.log.info("Guessing S3 bucket(s) from role: "
                                  f"[bold]{', '.join(guesses)}[/] "
                                  "(use --bucket to override)")
                    self.config.s3_buckets = guesses
                else:
                    self.log.info(
                        "Tip: pass [bold]--bucket <name>[/] or [bold]--app-config "
                        "<aws-exports.js>[/] to enumerate S3 public/protected/"
                        "private prefixes when list_buckets is denied"
                    )
            if self.config.s3_write:
                self.log.warn("S3 write test enabled (--s3-write): will upload a "
                              "throwaway object to writable prefixes")
            tester = ServiceTester(
                session, self.log, self.config.max_workers,
                identity_id=creds.identity_id,
                identity_pool=self.config.identity_pool,
                s3_buckets=self.config.s3_buckets,
                s3_list=self.config.s3_list,
                s3_write=self.config.s3_write,
            )
            tester.run(self.config.services)
            tester.save_results(self.config.output_dir)

            if no_enumerate:
                self.log.warn("enumerate-iam skipped by user request")
            elif self.config.enumerate_iam_path and self.config.enumerate_iam_path.exists():
                self.run_enumerate_iam(creds)
            else:
                self.log.warn(
                    "enumerate-iam not found; set POOLDIVER_ENUMERATE_IAM or "
                    "--enumerate-path to enable it"
                )

        self.log.good("PoolDiver execution completed")

    def run_enumerate_iam(self, creds: AWSCredentials) -> Optional[Path]:
        script = self.config.enumerate_iam_path / "enumerate-iam.py"
        if not script.exists():
            self.log.warn(f"enumerate-iam.py not found at {script}")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.config.output_dir / f"enumerate_iam_output_{timestamp}.txt"
        self.log.info("Running enumerate-iam...")

        env = os.environ.copy()
        env.update(
            AWS_ACCESS_KEY_ID=creds.access_key,
            AWS_SECRET_ACCESS_KEY=creds.secret_key,
            AWS_SESSION_TOKEN=creds.session_token,
            AWS_DEFAULT_REGION=creds.region,
        )
        cmd = [
            sys.executable, str(script),
            "--access-key", creds.access_key,
            "--secret-key", creds.secret_key,
            "--region", creds.region,
            "--session-token", creds.session_token,
        ]

        console.rule("[cyan]enumerate-iam output")
        proc: Optional[subprocess.Popen] = None
        findings: List[str] = []
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                proc = subprocess.Popen(
                    cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                if self.log.verbose:
                    self._stream_verbose(proc, f, findings)   # -v: raw stream
                else:
                    self._stream_status(proc, f, findings)    # live status bar
                proc.wait()
            console.rule("[cyan]end of enumerate-iam output")

            if proc.returncode != 0:
                self.log.error(f"enumerate-iam exited with code {proc.returncode}")
                return None
            if findings:
                self.log.good(
                    f"enumerate-iam: {len(findings)} working call(s) — "
                    + ", ".join(findings)
                )
            else:
                self.log.info("enumerate-iam: no additional working calls found")
            self.log.good(f"enumerate-iam output saved to {output_file}")
            return output_file
        except KeyboardInterrupt:
            self.log.warn("enumerate-iam interrupted by user")
            if proc and proc.poll() is None:
                proc.terminate()
            raise
        except OSError as e:
            self.log.error(f"Failed to run enumerate-iam: {e}")
            return None

    @staticmethod
    def _candidate_buckets(identity_arn: Optional[str]) -> List[str]:
        """Guess likely S3 bucket names from the assumed-role ARN.

        AWS MobileHub and Amplify name the user-files bucket predictably, so a
        denied list_buckets doesn't have to be a dead end. These are guesses —
        prefix probes against them simply fail (NoSuchBucket / AccessDenied) if
        wrong. --bucket always overrides.
        """
        if not identity_arn:
            return []
        m = re.search(r"assumed-role/([^/]+)/", identity_arn)
        if not m:
            return []
        role = m.group(1)
        candidates: List[str] = []

        # MobileHub: <project>_unauth_MOBILEHUB_<id> provisions three buckets
        # (userfiles / deployments / hosting) sharing the same id. Try all —
        # deployments/hosting often expose a manifest naming the real buckets.
        mh = re.match(r"(?P<proj>.+?)_(?:un)?auth_MOBILEHUB_(?P<id>\d+)$", role, re.I)
        if mh:
            proj = mh.group("proj").lower()
            pid = mh.group("id")
            candidates += [f"{proj}-{kind}-mobilehub-{pid}"
                           for kind in ("userfiles", "deployments", "hosting")]

        # Amplify: amplify-<app>-<env>-<id>-(un)authRole -> storage bucket varies;
        # surface the app slug as a best-effort hint.
        amp = re.match(r"amplify-(?P<app>.+?)-(?P<env>[^-]+)-\d+-(?:un)?authRole$",
                       role, re.I)
        if amp:
            candidates.append(f"{amp.group('app').lower()}-storage-{amp.group('env').lower()}")

        return candidates

    @staticmethod
    def _collect_finding(line: str, findings: List[str]) -> Optional[str]:
        """Record a 'worked!' line as a finding; return the parsed action."""
        if "worked!" not in line.lower():
            return None
        m = re.search(r"--\s*([\w.\-]+\([^)]*\))\s*worked", line)
        action = m.group(1) if m else line.strip()
        findings.append(action)
        return action

    def _stream_verbose(self, proc: subprocess.Popen, f: "IO[str]",
                        findings: List[str]) -> None:
        """Echo every enumerate-iam line (used with -v for debugging hangs)."""
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            self._echo_enum_line(line)
            self._collect_finding(line, findings)
            f.write(line + "\n")
            f.flush()

    def _stream_status(self, proc: subprocess.Popen, f: "IO[str]",
                       findings: List[str]) -> None:
        """Show a live status bar while enumerate-iam runs.

        Findings print as they appear; the spinner keeps animating during long
        stalls (rich auto-refreshes on a background thread) so it's obvious the
        run is alive and when it finishes. Raw output still goes to the file.
        """
        start = time.monotonic()
        state = {"tested": 0, "current": "starting…"}

        def render() -> Spinner:
            mm, ss = divmod(int(time.monotonic() - start), 60)
            txt = Text.assemble(
                ("enumerate-iam  ", "bold cyan"),
                (f"{state['tested']} tested ", "white"), ("· ", "dim"),
                (f"{len(findings)} found ", "green"), ("· ", "dim"),
                (f"{mm:02d}:{ss:02d} ", "yellow"), ("· ", "dim"),
                (state["current"][:48], "cyan"),
            )
            return Spinner("dots", text=txt, style="cyan")

        with Live(render(), console=console, refresh_per_second=12,
                  transient=True) as live:
            for raw in iter(proc.stdout.readline, b""):
                line = raw.decode("utf-8", errors="replace").rstrip()
                f.write(line + "\n")
                f.flush()
                state["tested"] += 1
                found = self._collect_finding(line, findings)
                if found:
                    console.print(Text(f"  ✓ {found}", style="bold green"))
                    state["current"] = found
                else:
                    m = re.search(r"Remove ([\w.\-]+) action", line)
                    if m:
                        state["current"] = m.group(1)
                live.update(render())

    @staticmethod
    def _echo_enum_line(line: str) -> None:
        low = line.lower()
        if "worked!" in low:
            style = "bold green"           # a permission that actually works
        elif "not found" in low or "param validation error" in low:
            style = "dim"                  # benign: API not in installed botocore
        elif any(k in low for k in ("error", "denied", "failed")):
            style = "red"
        elif any(k in low for k in ("success", "allowed", "completed")):
            style = "green"
        elif "warning" in low:
            style = "yellow"
        else:
            style = None
        # markup=False so '[ERROR]'/'[INFO]' in the line aren't parsed as tags.
        console.print(line, style=style, markup=False, highlight=False)
