"""Discover S3 bucket names from Amplify app configuration.

Amplify front-ends ship their backend config in `aws-exports.js` or
`amplifyconfiguration.json`, which usually names the user-files S3 bucket.
Point PoolDiver at that file (URL or local path) to recover the bucket.
"""

from __future__ import annotations

import re
import urllib.request
from pathlib import Path
from typing import List

# A valid S3 bucket name: 3-63 chars, lowercase letters, digits, dots, hyphens.
_BUCKET = r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
_PATTERNS = [
    re.compile(r'aws_user_files_s3_bucket["\']?\s*[:=]\s*["\']' + _BUCKET, re.I),
    re.compile(r'["\'][Bb]ucket["\']\s*:\s*["\']' + _BUCKET + r'["\']'),
    re.compile(r'[Bb]ucket[-_ ]?[Nn]ame["\']?\s*[:=]\s*["\']?' + _BUCKET, re.I),
    # MobileHub bucket names appearing anywhere (e.g. in mobile-hub-project.yml).
    re.compile(r'\b([a-z0-9][a-z0-9.\-]*-(?:userfiles|deployments|hosting)'
               r'-mobilehub-\d+)\b', re.I),
]


def extract_buckets_from_text(text: str) -> List[str]:
    """Return unique S3 bucket names referenced anywhere in a config blob."""
    found: List[str] = []
    for pattern in _PATTERNS:
        for match in pattern.findall(text):
            if match not in found:
                found.append(match)
    return found


def _read(source: str, timeout: float = 15.0) -> str:
    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"User-Agent": "PoolDiver"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read().decode("utf-8", "replace")
    return Path(source).expanduser().read_text(encoding="utf-8", errors="replace")


def discover_buckets(source: str) -> List[str]:
    """Return unique S3 bucket names referenced in an Amplify config file."""
    return extract_buckets_from_text(_read(source))
