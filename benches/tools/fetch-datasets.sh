#!/bin/sh
# Download and convert the public datasets benches/datasets.rs reads.
# Usage: benches/tools/fetch-datasets.sh <dir>; then NELEUS_BENCH_DATA=<dir>.
set -eu
dir=$1
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dir/beir" "$dir/ann" "$dir/raw"
for name in scifact fiqa; do
  [ -f "$dir/raw/$name.zip" ] || curl -sSfL -o "$dir/raw/$name.zip" \
    "https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/$name.zip"
  [ -d "$dir/beir/$name" ] || unzip -q "$dir/raw/$name.zip" -d "$dir/beir"
done
python3 -m venv "$dir/venv"
"$dir/venv/bin/pip" install -q h5py numpy
for name in nytimes-256-angular glove-100-angular; do
  [ -f "$dir/raw/$name.hdf5" ] || curl -sSfL -o "$dir/raw/$name.hdf5" \
    "http://ann-benchmarks.com/$name.hdf5"
  [ -f "$dir/ann/$name.train.f32" ] || \
    "$dir/venv/bin/python" -I "$here/convert_ann.py" "$dir/raw/$name.hdf5" "$dir/ann/$name"
done
