#!/usr/bin/env python3
"""
PoolDiver - AWS Cognito Identity Pool Credential Extractor & Tester
===================================================================

Fetches unauthenticated credentials from a misconfigured Cognito Identity
Pool, then probes the AWS permissions those credentials grant. Optionally
chains into `enumerate-iam` for deeper enumeration.

For authorized security testing only. Use exclusively against targets you
own or have written permission to assess.

    Author : @TheZakMan
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
)
from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

__version__ = "3.0"

console = Console()

# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #

_BANNER = r"""
                    _
          dev-v{ver} | |
 _ __   ___   ___  | |
| '_ \ / _ \ / _ \ | |
| |A| | |W| | |S| || |
| |_| | |_| | |_| || |
| .__/ \___/ \___/ |_|
| |         ~~DIVER 🤿
|_|  HOW DEEP CAN I GO?
""".format(ver=__version__)


def print_banner() -> None:
    art = Text(_BANNER, style="bold yellow")
    art.highlight_words(["A", "W", "S"], "bold cyan")
    subtitle = Text.assemble(
        ("AWS Cognito Identity Pool Tester", "bold white"),
        ("  •  ", "dim"),
        ("@TheZakMan", "bold blue"),
    )
    console.print(
        Panel(
            Group(Align.center(art), Align.center(subtitle)),
            box=box.DOUBLE,
            border_style="cyan",
            padding=(0, 4),
        )
    )


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass
class Config:
    """Runtime configuration, populated from CLI args and environment."""

    enumerate_iam_path: Optional[Path] = None
    log_file: Path = Path("pooldiver_output.log")
    output_dir: Path = Path("pool_diver_results")
    credentials_dir: Path = Path("credentials")
    max_workers: int = 5
    services: List[str] = field(
        default_factory=lambda: [
            "s3", "ec2", "lambda", "dynamodb", "iam", "ssm",
            "secretsmanager", "sqs", "sns", "rds",
        ]
    )

    def ensure_dirs(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def default_enumerate_path() -> Optional[Path]:
        """Resolve the enumerate-iam location from the environment."""
        env = os.environ.get("POOLDIVER_ENUMERATE_IAM")
        if env:
            return Path(env).expanduser()
        return None


# --------------------------------------------------------------------------- #
# Logging — file only; the console is owned by rich
# --------------------------------------------------------------------------- #


class Log:
    """Minimal logger: rich for the console, a plain file for the audit trail."""

    def __init__(self, log_file: Path, verbose: bool = False) -> None:
        self.verbose = verbose
        self._fh = open(log_file, "a", encoding="utf-8")
        self._lock = threading.Lock()
        self._write("file", f"=== PoolDiver session started {self._now()} ===")

    @staticmethod
    def _now() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _write(self, level: str, msg: str) -> None:
        with self._lock:
            self._fh.write(f"{self._now()} [{level.upper()}] {msg}\n")
            self._fh.flush()

    def info(self, msg: str) -> None:
        console.print(f"[cyan]ℹ[/] {msg}")
        self._write("info", msg)

    def good(self, msg: str) -> None:
        console.print(f"[bold green]✓[/] {msg}")
        self._write("info", msg)

    def warn(self, msg: str) -> None:
        console.print(f"[yellow]⚠[/] {msg}")
        self._write("warning", msg)

    def error(self, msg: str) -> None:
        console.print(f"[bold red]✗[/] {msg}")
        self._write("error", msg)

    def debug(self, msg: str) -> None:
        if self.verbose:
            console.print(f"[dim]· {msg}[/]")
        self._write("debug", msg)

    def close(self) -> None:
        self._write("file", f"=== PoolDiver session ended {self._now()} ===")
        self._fh.close()


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #


@dataclass
class AWSCredentials:
    access_key: str
    secret_key: str
    session_token: str
    identity_id: str
    region: str
    expiration: Optional[datetime] = None

    def is_expired(self) -> bool:
        if self.expiration is None:
            return False
        now = datetime.now(self.expiration.tzinfo or timezone.utc)
        return now >= self.expiration

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "AccessKeyId": self.access_key,
            "SecretAccessKey": self.secret_key,
            "SessionToken": self.session_token,
            "IdentityId": self.identity_id,
            "Region": self.region,
            "Expiration": self.expiration.isoformat() if self.expiration else None,
        }

    def save_to_file(self, filepath: Path) -> None:
        filepath.write_text(json.dumps(self.to_dict(), indent=4), encoding="utf-8")

    def boto_session(self) -> boto3.Session:
        return boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            aws_session_token=self.session_token,
            region_name=self.region,
        )


# --------------------------------------------------------------------------- #
# Service permission testing
# --------------------------------------------------------------------------- #


class ServiceTester:
    """Probes AWS service permissions in parallel with a live status bar."""

    # Pretty labels rendered in the status bar.
    LABELS = {
        "s3": "S3", "ec2": "EC2", "lambda": "Lambda", "dynamodb": "DynamoDB",
        "iam": "IAM", "ssm": "SSM", "secretsmanager": "Secrets Manager",
        "sqs": "SQS", "sns": "SNS", "rds": "RDS",
    }

    def __init__(self, session: boto3.Session, log: Log, max_workers: int = 5) -> None:
        self.session = session
        self.log = log
        self.max_workers = max_workers
        self.results: Dict[str, dict] = {}
        self.status: Dict[str, str] = {}          # service -> pending/running/granted/denied/error
        self.findings: Dict[str, str] = {}        # service -> short summary
        self.order: List[str] = []
        self.start_time = time.monotonic()
        self._lock = threading.Lock()

    # -- individual probes -------------------------------------------------- #

    def _probes(self) -> Dict[str, Callable[[], dict]]:
        return {
            "s3": self._s3, "ec2": self._ec2, "lambda": self._lambda,
            "dynamodb": self._dynamodb, "iam": self._iam, "ssm": self._ssm,
            "secretsmanager": self._secretsmanager, "sqs": self._sqs,
            "sns": self._sns, "rds": self._rds,
        }

    def _s3(self) -> dict:
        c = self.session.client("s3")
        return {"buckets": [
            {"name": b["Name"], "creation_date": str(b["CreationDate"])}
            for b in c.list_buckets().get("Buckets", [])
        ]}

    def _ec2(self) -> dict:
        c = self.session.client("ec2")
        return {"instances": [
            {"id": i["InstanceId"], "type": i["InstanceType"],
             "state": i["State"]["Name"], "vpc_id": i.get("VpcId", "N/A")}
            for r in c.describe_instances().get("Reservations", [])
            for i in r.get("Instances", [])
        ]}

    def _lambda(self) -> dict:
        c = self.session.client("lambda")
        return {"functions": [
            {"name": f["FunctionName"], "runtime": f.get("Runtime", "N/A"),
             "handler": f.get("Handler", "N/A")}
            for f in c.list_functions().get("Functions", [])
        ]}

    def _dynamodb(self) -> dict:
        c = self.session.client("dynamodb")
        return {"tables": c.list_tables().get("TableNames", [])}

    def _iam(self) -> dict:
        c = self.session.client("iam")
        result: Dict[str, Any] = {}
        try:
            result["user"] = c.get_user().get("User", {})
        except ClientError as e:
            result["user"] = f"denied ({e.response['Error']['Code']})"
        try:
            result["roles"] = [r["RoleName"] for r in c.list_roles().get("Roles", [])]
        except ClientError as e:
            result["roles"] = f"denied ({e.response['Error']['Code']})"
        return result

    def _ssm(self) -> dict:
        c = self.session.client("ssm")
        return {"parameters": [p["Name"] for p in c.describe_parameters().get("Parameters", [])]}

    def _secretsmanager(self) -> dict:
        c = self.session.client("secretsmanager")
        return {"secrets": [s["Name"] for s in c.list_secrets().get("SecretList", [])]}

    def _sqs(self) -> dict:
        c = self.session.client("sqs")
        return {"queues": c.list_queues().get("QueueUrls", [])}

    def _sns(self) -> dict:
        c = self.session.client("sns")
        return {"topics": [t["TopicArn"] for t in c.list_topics().get("Topics", [])]}

    def _rds(self) -> dict:
        c = self.session.client("rds")
        return {"instances": [
            {"id": i["DBInstanceIdentifier"], "engine": i["Engine"]}
            for i in c.describe_db_instances().get("DBInstances", [])
        ]}

    # -- finding summaries -------------------------------------------------- #

    @staticmethod
    def _summarize(service: str, result: dict) -> str:
        def plural(n: int, noun: str) -> str:
            return f"{n} {noun}{'' if n == 1 else 's'}"

        if service == "s3":
            return plural(len(result.get("buckets", [])), "bucket")
        if service == "ec2":
            return plural(len(result.get("instances", [])), "instance")
        if service == "lambda":
            return plural(len(result.get("functions", [])), "function")
        if service == "dynamodb":
            return plural(len(result.get("tables", [])), "table")
        if service == "ssm":
            return plural(len(result.get("parameters", [])), "parameter")
        if service == "secretsmanager":
            return plural(len(result.get("secrets", [])), "secret")
        if service == "sqs":
            return plural(len(result.get("queues", [])), "queue")
        if service == "sns":
            return plural(len(result.get("topics", [])), "topic")
        if service == "rds":
            return plural(len(result.get("instances", [])), "instance")
        if service == "iam":
            roles = result.get("roles")
            return plural(len(roles), "role") if isinstance(roles, list) else "user/roles"
        return ""

    # -- orchestration ------------------------------------------------------ #

    def run(self, services: List[str]) -> None:
        probes = self._probes()
        self.order = [s for s in services if s in probes]
        skipped = [s for s in services if s not in probes]
        for s in skipped:
            self.log.warn(f"Unknown service '{s}', skipping")

        with self._lock:
            for s in self.order:
                self.status[s] = "pending"
                self.findings[s] = ""

        stop = threading.Event()

        with Live(self._render(), console=console, refresh_per_second=12,
                  transient=False) as live:
            def refresher() -> None:
                while not stop.is_set():
                    live.update(self._render())
                    time.sleep(0.08)

            t = threading.Thread(target=refresher, daemon=True)
            t.start()
            try:
                with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                    futures = {ex.submit(self._test_one, s, probes[s]): s
                               for s in self.order}
                    for fut in as_completed(futures):
                        fut.result()  # state already recorded; surface unexpected raises
            finally:
                stop.set()
                t.join()
                live.update(self._render())

    def _test_one(self, service: str, probe: Callable[[], dict]) -> None:
        with self._lock:
            self.status[service] = "running"
        try:
            result = probe()
            with self._lock:
                self.results[service] = result
                self.status[service] = "granted"
                self.findings[service] = self._summarize(service, result)
            self.log.debug(f"{service}: granted ({self.findings[service]})")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            with self._lock:
                self.results[service] = {"error": code}
                self.status[service] = "denied"
                self.findings[service] = code
            self.log.debug(f"{service}: denied ({code})")
        except (BotoCoreError, EndpointConnectionError) as e:
            with self._lock:
                self.results[service] = {"error": str(e)}
                self.status[service] = "error"
                self.findings[service] = "connection error"
            self.log.debug(f"{service}: error ({e})")
        except Exception as e:  # noqa: BLE001 - never let one probe kill the run
            with self._lock:
                self.results[service] = {"error": str(e)}
                self.status[service] = "error"
                self.findings[service] = "unexpected error"
            self.log.debug(f"{service}: unexpected error ({e})")

    # -- rendering ---------------------------------------------------------- #

    _STATUS_CELL = {
        "pending": ("⏳ pending", "dim"),
        "granted": ("✓ granted", "bold green"),
        "denied": ("✗ denied", "red"),
        "error": ("⚠ error", "yellow"),
    }

    def _render(self) -> Panel:
        with self._lock:
            order = list(self.order)
            status = dict(self.status)
            findings = dict(self.findings)

        table = Table(box=box.SIMPLE_HEAVY, expand=True, pad_edge=False)
        table.add_column("Service", style="bold white", no_wrap=True, width=18)
        table.add_column("Status", width=16)
        table.add_column("Findings", style="cyan", overflow="fold")

        for s in order:
            st = status.get(s, "pending")
            if st == "running":
                status_cell: Any = Spinner("dots", text=Text(" testing", style="cyan"))
            else:
                label, style = self._STATUS_CELL.get(st, ("?", "white"))
                status_cell = Text(label, style=style)
            table.add_row(self.LABELS.get(s, s), status_cell, findings.get(s, ""))

        done = sum(1 for s in order if status.get(s) in ("granted", "denied", "error"))
        granted = sum(1 for s in order if status.get(s) == "granted")
        elapsed = time.monotonic() - self.start_time
        subtitle = Text.assemble(
            (f" {done}/{len(order)} probed ", "white"),
            ("· ", "dim"),
            (f"{granted} accessible ", "green"),
            ("· ", "dim"),
            (f"{elapsed:4.1f}s ", "yellow"),
        )
        return Panel(
            table,
            title="[bold cyan]AWS Service Permission Probe[/]",
            subtitle=subtitle,
            border_style="cyan",
            box=box.ROUNDED,
        )

    # -- persistence -------------------------------------------------------- #

    def save_results(self, output_dir: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        accessible = sum(1 for s in self.order if self.status.get(s) == "granted")
        total = len(self.order)
        duration = time.monotonic() - self.start_time

        payload = dict(self.results)
        payload["summary"] = {
            "tested_services": total,
            "accessible_services": accessible,
            "scan_duration": f"{duration:.2f}s",
            "timestamp": datetime.now().isoformat(),
        }

        json_file = output_dir / f"scan_results_{timestamp}.json"
        json_file.write_text(json.dumps(payload, indent=4, default=str), encoding="utf-8")
        self.log.good(f"Results saved to {json_file}")

        summary_file = output_dir / f"summary_{timestamp}.txt"
        with open(summary_file, "w", encoding="utf-8") as f:
            pct = (accessible / total * 100) if total else 0.0
            f.write("=== PoolDiver Scan Summary ===\n\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {duration:.2f}s\n")
            f.write(f"Services tested: {total}\n")
            f.write(f"Accessible: {accessible}/{total} ({pct:.1f}%)\n\n")
            f.write("Service Access:\n")
            for s in self.order:
                st = self.status.get(s, "pending")
                if st == "granted":
                    f.write(f"- {s}: ACCESSIBLE ({self.findings.get(s, '')})\n")
                else:
                    f.write(f"- {s}: {st.upper()} ({self.findings.get(s, '')})\n")
        self.log.good(f"Summary report saved to {summary_file}")

        self._print_summary_table(accessible, total, duration)
        return json_file

    def _print_summary_table(self, accessible: int, total: int, duration: float) -> None:
        table = Table(box=box.MINIMAL_DOUBLE_HEAD, title="Scan Complete",
                      title_style="bold cyan", expand=True)
        table.add_column("Service", style="bold white")
        table.add_column("Result")
        table.add_column("Findings", style="cyan")
        for s in self.order:
            st = self.status.get(s, "pending")
            label, style = self._STATUS_CELL.get(
                st, ("?", "white")) if st != "running" else ("running", "cyan")
            table.add_row(self.LABELS.get(s, s), Text(label, style=style),
                          self.findings.get(s, ""))
        console.print(table)
        if accessible:
            console.print(
                f"[bold green]✓ {accessible}/{total} services accessible[/] "
                f"[dim]in {duration:.2f}s[/]"
            )
        else:
            console.print(f"[bold red]✗ No accessible services found[/] "
                          f"[dim]in {duration:.2f}s[/]")


# --------------------------------------------------------------------------- #
# Main orchestrator
# --------------------------------------------------------------------------- #


class PoolDiver:
    def __init__(self, config: Config, log: Log) -> None:
        self.config = config
        self.log = log

    def get_pool_credentials(self, region: str, identity_pool: str) -> AWSCredentials:
        self.log.info(f"Fetching credentials for pool [bold]{identity_pool}[/] in [bold]{region}[/]")
        client = boto3.client("cognito-identity", region_name=region)

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

    def run(self, args: argparse.Namespace) -> None:
        self.log.info(f"PoolDiver v{__version__} starting...")

        creds = self.get_pool_credentials(args.region, args.identity)
        self.log.good(f"Obtained credentials for identity: [bold]{creds.identity_id}[/]")

        session = creds.boto_session()

        # Confirm what these credentials map to.
        try:
            identity = session.client("sts").get_caller_identity()
            self.log.good(f"Authenticated as: [bold]{identity['Arn']}[/]")
        except (ClientError, BotoCoreError) as e:
            self.log.warn(f"Could not determine identity: {e}")

        if args.test:
            self.log.info("Starting AWS service permission tests...")
            tester = ServiceTester(session, self.log, self.config.max_workers)
            tester.run(self.config.services)
            enum_output = tester.save_results(self.config.output_dir)

            if args.no_enumerate:
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
                    cmd, env=env, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
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


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="PoolDiver.py",
        description="Extract and test AWS credentials from a Cognito Identity Pool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  ./PoolDiver.py -r us-east-1 -id us-east-1:00000000-0000-0000-0000-000000000000
  ./PoolDiver.py -r us-east-1 -id us-east-1:0000...0000 -t
  ./PoolDiver.py -r us-east-1 -id us-east-1:0000...0000 -t -s s3,ec2,lambda

For authorized security testing only.
""",
    )
    parser.add_argument("-r", "--region", required=True, help="AWS region")
    parser.add_argument("-id", "--identity", required=True,
                        help="Cognito Identity Pool ID")
    parser.add_argument("-t", "--test", action="store_true",
                        help="Run AWS service permission tests")
    parser.add_argument("-s", "--services",
                        help="Comma-separated services to test (default: all)")
    parser.add_argument("--no-enumerate", action="store_true",
                        help="Skip running enumerate-iam")
    parser.add_argument("--enumerate-path",
                        help="Path to the enumerate-iam directory "
                             "(or set POOLDIVER_ENUMERATE_IAM)")
    parser.add_argument("--output", help="Custom output directory for results")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--version", action="version",
                        version=f"PoolDiver {__version__}")
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> Config:
    config = Config()
    if args.services:
        config.services = [s.strip() for s in args.services.split(",") if s.strip()]
    if args.output:
        config.output_dir = Path(args.output)
    if args.enumerate_path:
        config.enumerate_iam_path = Path(args.enumerate_path).expanduser()
    else:
        config.enumerate_iam_path = Config.default_enumerate_path()
    config.ensure_dirs()
    return config


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_arguments(argv)
    print_banner()
    config = build_config(args)
    log = Log(config.log_file, verbose=args.verbose)
    try:
        PoolDiver(config, log).run(args)
        return 0
    except KeyboardInterrupt:
        log.warn("Operation cancelled by user")
        return 130
    except NoCredentialsError:
        log.error("No AWS credentials available")
        return 1
    except (ClientError, BotoCoreError) as e:
        log.error(f"AWS error: {e}")
        return 1
    except Exception as e:  # noqa: BLE001
        log.error(f"Fatal error: {e}")
        if args.verbose:
            console.print_exception()
        return 1
    finally:
        log.close()


if __name__ == "__main__":
    sys.exit(main())
