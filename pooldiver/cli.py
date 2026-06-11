"""Command-line interface."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from . import __version__
from .banner import print_banner
from .config import SUPPORTED_SERVICES, Config
from .console import console
from .core import PoolDiver
from .logger import Log

# AWS region, e.g. us-east-1, ap-southeast-2, us-gov-east-1, cn-north-1
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z-]+-\d+$")
# Cognito Identity Pool ID: <region>:<uuid>
_IDENTITY_RE = re.compile(
    r"^[a-z]{2}-[a-z-]+-\d+:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pooldiver",
        description="Extract and test AWS credentials from a Cognito Identity Pool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  pooldiver -r us-east-1 -id us-east-1:00000000-0000-0000-0000-000000000000
  pooldiver -r us-east-1 -id us-east-1:0000...0000 -t
  pooldiver -r us-east-1 -id us-east-1:0000...0000 -t -s s3,ec2,lambda

For authorized security testing only.
""",
    )
    parser.add_argument("-r", "--region", required=True, help="AWS region")
    parser.add_argument("-id", "--identity", required=True,
                        help="Cognito Identity Pool ID")
    parser.add_argument("-t", "--test", action="store_true",
                        help="Run AWS service permission tests")
    parser.add_argument("-s", "--services",
                        help=f"Comma-separated services to test "
                             f"(default: all). Supported: {', '.join(SUPPORTED_SERVICES)}")
    parser.add_argument("--no-enumerate", action="store_true",
                        help="Skip running enumerate-iam")
    parser.add_argument("--enumerate-path",
                        help="Path to the enumerate-iam directory "
                             "(or set POOLDIVER_ENUMERATE_IAM)")
    parser.add_argument("--output", help="Custom output directory for results")
    parser.add_argument("-w", "--workers", type=int, default=5,
                        help="Max parallel workers for service probing (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--version", action="version",
                        version=f"PoolDiver {__version__}")

    args = parser.parse_args(argv)

    if not _REGION_RE.match(args.region):
        parser.error(f"invalid region format: '{args.region}' (expected e.g. us-east-1)")
    if not _IDENTITY_RE.match(args.identity):
        parser.error(
            f"invalid identity pool id: '{args.identity}' "
            "(expected <region>:<uuid>, e.g. us-east-1:0000...0000)"
        )
    if args.workers < 1:
        parser.error("--workers must be >= 1")
    return args


def build_config(args: argparse.Namespace) -> Config:
    config = Config(max_workers=args.workers)
    if args.services:
        requested = [s.strip().lower() for s in args.services.split(",") if s.strip()]
        unknown = [s for s in requested if s not in SUPPORTED_SERVICES]
        if unknown:
            console.print(
                f"[yellow]⚠ Unsupported service(s): {', '.join(unknown)} "
                f"(supported: {', '.join(SUPPORTED_SERVICES)})[/]"
            )
        config.services = [s for s in requested if s in SUPPORTED_SERVICES]
    if args.output:
        config.output_dir = Path(args.output)
    config.enumerate_iam_path = (
        Path(args.enumerate_path).expanduser() if args.enumerate_path
        else Config.default_enumerate_path()
    )
    config.ensure_dirs()
    return config


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_arguments(argv)
    print_banner()
    config = build_config(args)
    with Log(config.log_file, verbose=args.verbose) as log:
        try:
            PoolDiver(config, log).run(
                region=args.region,
                identity=args.identity,
                test=args.test,
                no_enumerate=args.no_enumerate,
            )
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


if __name__ == "__main__":
    sys.exit(main())
