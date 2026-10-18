#!/bin/sh
# Durability syscalls per operation: runs each operation 0 and N times under a
# counting preload and reports (count(N) - count(0)) / N. macOS only.
set -eu
n=${1:-200}
cd "$(dirname "$0")/../.."
lib=target/synccount.dylib
cc -O2 -dynamiclib -o "$lib" benches/tools/synccount.c
cargo build -q --release --example sync_count
bin=target/release/examples/sync_count
count() { DYLD_INSERT_LIBRARIES="$lib" "$bin" "$1" "$2" 2>&1 >/dev/null | grep '^\[sync\]' | tail -1; }
for op in state search commit-empty commit-objects commit-manifest sqlite-wal sqlite-rollback; do
  base=$(count "$op" 0)
  full=$(count "$op" "$n")
  echo "$op $n $base | $full" | awk '{
    split($4,a,"="); split($5,b,"="); split($6,c,"=");
    split($9,d,"="); split($10,e,"="); split($11,f,"=");
    printf "[sync] %-16s per op: F_FULLFSYNC %.2f  F_BARRIERFSYNC %.2f  fsync %.2f\n",
      $1, (d[2]-a[2])/$2, (e[2]-b[2])/$2, (f[2]-c[2])/$2 }'
done
