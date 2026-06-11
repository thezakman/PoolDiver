"""Lightweight logger: rich for the console, a plain file for the audit trail."""

from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path

from .console import console


class Log:
    """Console output via rich plus an append-only file audit log."""

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

    def __enter__(self) -> "Log":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
