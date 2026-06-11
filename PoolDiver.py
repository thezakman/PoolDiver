#!/usr/bin/env python3
"""
PoolDiver launcher.

Lets you run PoolDiver straight from a checkout without installing it:

    ./PoolDiver.py -r us-east-1 -id us-east-1:0000...0000 -t

Once installed (`pip install .`), prefer the `pooldiver` console command.
"""

import sys

from pooldiver.cli import main

if __name__ == "__main__":
    sys.exit(main())
