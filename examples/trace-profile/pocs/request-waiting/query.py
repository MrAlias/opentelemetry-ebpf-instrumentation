#!/usr/bin/env python3
"""Requery a recorded absolute interval while this example's backend is running."""
import argparse
from pathlib import Path
from run import query_window

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--start-ms", type=int, required=True)
parser.add_argument("--end-ms", type=int, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if args.end_ms <= args.start_ms or args.end_ms - args.start_ms > 900000:
    parser.error("interval must be positive and at most 15 minutes")
args.output.mkdir(parents=True, exist_ok=False)
query_window(args.output, args.start_ms, args.end_ms)
