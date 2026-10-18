#!/bin/sh
# Every benchmark the paper cites, `runs` times per configuration, with raw
# Criterion estimates and stderr logs archived under <out>/<config>/run<N>/.
# Usage: benches/tools/run-all.sh <out> [runs] [first]; NELEUS_BENCH_DATA for datasets.
set -eu
out=$1
runs=${2:-5}
first=${3:-1}
cd "$(dirname "$0")/../.."
mkdir -p "$out"
short="--warm-up-time 1 --measurement-time 3 --sample-size 10"
writes='point_set|semantic_recorded|coalesced'

archive() {
  dest=$1
  mkdir -p "$dest"
  find target/criterion -path '*/new/estimates.json' | while read -r f; do
    id=${f#target/criterion/}
    mkdir -p "$dest/criterion/$(dirname "$id")"
    cp "$f" "$dest/criterion/$id"
  done
  rm -rf target/criterion
}

cargo build -q --release --benches --bins
rustc --version > "$out/env.txt"
sw_vers >> "$out/env.txt"
sysctl -n machdep.cpu.brand_string hw.memsize >> "$out/env.txt"
sqlite3 --version >> "$out/env.txt"

for i in $(seq "$first" "$runs"); do
  NELEUS_BENCH_DURABILITY=os cargo bench --bench compare_sql --bench state \
    --bench scale --bench verifiability --bench agent 2> "$out/fast-run$i.log" >/dev/null
  archive "$out/fast/run$i"
  for mode in full barrier; do
    NELEUS_BENCH_DURABILITY=$mode NELEUS_BENCH_ENCRYPT=1 NELEUS_BENCH_WRITES_ONLY=1 \
      cargo bench --bench compare_sql --bench scale -- "$writes" $short \
      2> "$out/$mode-run$i.log" >/dev/null
    archive "$out/$mode/run$i"
  done
  NELEUS_BENCH_DURABILITY=full NELEUS_BENCH_ENCRYPT=1 cargo bench --bench agent \
    -- $short 2> "$out/agent-full-run$i.log" >/dev/null
  archive "$out/agent-full/run$i"
done

benches/tools/sync-count.sh 200 > "$out/sync-count.txt" 2>&1
NELEUS_BENCH_DURABILITY=os cargo bench --bench datasets 2> "$out/datasets.log" >/dev/null
