"""Runtime configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Services PoolDiver knows how to probe. Keep in sync with ServiceTester._probes.
SUPPORTED_SERVICES: List[str] = [
    "s3", "ec2", "lambda", "dynamodb", "iam", "ssm",
    "secretsmanager", "sqs", "sns", "rds",
]

ENUMERATE_IAM_ENV = "POOLDIVER_ENUMERATE_IAM"


@dataclass
class Config:
    """Runtime configuration, populated from CLI args and environment."""

    enumerate_iam_path: Optional[Path] = None
    log_file: Path = Path("pooldiver_output.log")
    output_dir: Path = Path("pool_diver_results")
    credentials_dir: Path = Path("credentials")
    max_workers: int = 5
    services: List[str] = field(default_factory=lambda: list(SUPPORTED_SERVICES))

    def ensure_dirs(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def default_enumerate_path() -> Optional[Path]:
        """Resolve the enumerate-iam location from the environment, if set."""
        env = os.environ.get(ENUMERATE_IAM_ENV)
        return Path(env).expanduser() if env else None
