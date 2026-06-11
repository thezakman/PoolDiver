"""Main orchestration: fetch pool credentials and drive the scan."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import boto3
from botocore import UNSIGNED
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

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
        try:
            identity_arn = session.client("sts").get_caller_identity()["Arn"]
            self.log.good(f"Authenticated as: [bold]{identity_arn}[/]")
        except (ClientError, BotoCoreError) as e:
            self.log.warn(f"Could not determine identity: {e}")

        if test:
            self.log.info("Starting AWS service permission tests...")
            if "s3" in self.config.services and not self.config.s3_buckets:
                self.log.info(
                    "Tip: pass [bold]--bucket <name>[/] to enumerate S3 "
                    "public/protected/private prefixes when list_buckets is denied"
                )
            tester = ServiceTester(
                session, self.log, self.config.max_workers,
                identity_id=creds.identity_id,
                s3_buckets=self.config.s3_buckets,
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
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                proc = subprocess.Popen(
                    cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                for raw in iter(proc.stdout.readline, b""):
                    line = raw.decode("utf-8", errors="replace").rstrip()
                    self._echo_enum_line(line)
                    f.write(line + "\n")
                    f.flush()
                proc.wait()
            console.rule("[cyan]end of enumerate-iam output")

            if proc.returncode != 0:
                self.log.error(f"enumerate-iam exited with code {proc.returncode}")
                return None
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
    def _echo_enum_line(line: str) -> None:
        low = line.lower()
        if any(k in low for k in ("error", "denied", "failed")):
            console.print(f"[red]{line}[/]")
        elif any(k in low for k in ("success", "allowed", "completed")):
            console.print(f"[green]{line}[/]")
        elif "warning" in low:
            console.print(f"[yellow]{line}[/]")
        else:
            console.print(line, markup=False, highlight=False)
