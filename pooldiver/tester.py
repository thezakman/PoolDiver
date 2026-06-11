"""Parallel AWS service permission probing with a live status bar."""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
)
from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from .console import console
from .logger import Log


class ServiceTester:
    """Probes AWS service permissions in parallel with a live status bar."""

    LABELS = {
        "s3": "S3", "ec2": "EC2", "lambda": "Lambda", "dynamodb": "DynamoDB",
        "iam": "IAM", "ssm": "SSM", "secretsmanager": "Secrets Manager",
        "sqs": "SQS", "sns": "SNS", "rds": "RDS",
    }

    _STATUS_CELL = {
        "pending": ("⏳ pending", "dim"),
        "granted": ("✓ granted", "bold green"),
        "denied": ("✗ denied", "red"),
        "error": ("⚠ error", "yellow"),
    }

    def __init__(self, session: boto3.Session, log: Log, max_workers: int = 5) -> None:
        self.session = session
        self.log = log
        self.max_workers = max_workers
        self.results: Dict[str, dict] = {}
        self.status: Dict[str, str] = {}     # service -> pending/running/granted/denied/error
        self.findings: Dict[str, str] = {}   # service -> short summary
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

        counts = {
            "s3": ("buckets", "bucket"),
            "ec2": ("instances", "instance"),
            "lambda": ("functions", "function"),
            "dynamodb": ("tables", "table"),
            "ssm": ("parameters", "parameter"),
            "secretsmanager": ("secrets", "secret"),
            "sqs": ("queues", "queue"),
            "sns": ("topics", "topic"),
            "rds": ("instances", "instance"),
        }
        if service in counts:
            key, noun = counts[service]
            return plural(len(result.get(key, [])), noun)
        if service == "iam":
            roles = result.get("roles")
            return plural(len(roles), "role") if isinstance(roles, list) else "user/roles"
        return ""

    # -- orchestration ------------------------------------------------------ #

    def run(self, services: List[str]) -> None:
        probes = self._probes()
        self.order = [s for s in services if s in probes]
        for s in (s for s in services if s not in probes):
            self.log.warn(f"Unknown service '{s}', skipping")

        with self._lock:
            for s in self.order:
                self.status[s] = "pending"
                self.findings[s] = ""

        if not self.order:
            self.log.warn("No valid services to test")
            return

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
                        fut.result()
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
                tag = "ACCESSIBLE" if st == "granted" else st.upper()
                f.write(f"- {s}: {tag} ({self.findings.get(s, '')})\n")
        self.log.good(f"Summary report saved to {summary_file}")

        # The live probe table is already on screen (transient=False); just
        # print a concise one-line verdict instead of repeating the table.
        if accessible:
            console.print(
                f"[bold green]✓ {accessible}/{total} services accessible[/] "
                f"[dim]in {duration:.2f}s[/]"
            )
        else:
            console.print(f"[bold red]✗ No accessible services found[/] "
                          f"[dim]in {duration:.2f}s[/]")
        return json_file
