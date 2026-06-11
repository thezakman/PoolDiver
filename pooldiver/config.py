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
        """Resolve the enumerate-iam location.

        Order of precedence:
          1. the POOLDIVER_ENUMERATE_IAM environment variable,
          2. the copy bundled with PoolDiver (pooldiver/_vendor/enumerate-iam),
          3. a few common install locations.

        Returns the first directory that contains enumerate-iam.py, or None.
        """
        env = os.environ.get(ENUMERATE_IAM_ENV)
        if env:
            return Path(env).expanduser()

        from ._vendor import ENUMERATE_IAM_DIR

        home = Path.home()
        candidates = [
            ENUMERATE_IAM_DIR,
            home / "Toolz" / "enumerate-iam",
            home / "tools" / "enumerate-iam",
            home / "enumerate-iam",
            Path.cwd() / "enumerate-iam",
        ]
        for path in candidates:
            if (path / "enumerate-iam.py").is_file():
                return path
        return None
