"""AWS credential container."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import boto3


@dataclass
class AWSCredentials:
    access_key: str
    secret_key: str
    session_token: str
    identity_id: str
    region: str
    expiration: Optional[datetime] = None
    identity_pool: Optional[str] = None  # the pool these creds were obtained from

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
            "IdentityPoolId": self.identity_pool,
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
