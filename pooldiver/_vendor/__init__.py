"""Vendored third-party tools invoked by PoolDiver as subprocesses.

See README.md in this directory for provenance and licensing.
"""

from pathlib import Path

VENDOR_DIR = Path(__file__).resolve().parent

# Bundled enumerate-iam (GPLv3, https://github.com/andresriancho/enumerate-iam)
ENUMERATE_IAM_DIR = VENDOR_DIR / "enumerate-iam"
