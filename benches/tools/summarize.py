"""Median, min and max of Criterion medians across runs: summarize.py <out>."""
import json
import pathlib
import statistics
import sys

out = pathlib.Path(sys.argv[1])
for config in sorted(p for p in out.iterdir() if p.is_dir()):
    rows = {}
    for f in config.glob("run*/criterion/**/new/estimates.json"):
        bench = "/".join(f.relative_to(config).parts[2:-2])
        rows.setdefault(bench, []).append(json.loads(f.read_text())["median"]["point_estimate"])
    for bench, ns in sorted(rows.items()):
        print(f"{config.name:<12} {bench:<60} n={len(ns)} median={statistics.median(ns):>14.1f}ns "
              f"min={min(ns):>14.1f} max={max(ns):>14.1f}")
