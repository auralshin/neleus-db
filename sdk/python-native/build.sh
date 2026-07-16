#!/usr/bin/env bash
# Build the native module and place neleus_native.so next to this script so
# `import neleus_native` works without maturin installed.
#
# In production use maturin (`pip install maturin && maturin develop`), which
# handles naming and the ABI3 forward-compat flag for you.
set -euo pipefail
cd "$(dirname "$0")"

# abi3 forward-compat lets pyo3 0.22 build against newer CPython (e.g. 3.14).
PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 cargo build --release

# Rust emits lib<name>.{dylib,so}; Python imports <name>.so.
if [[ -f target/release/libneleus_native.dylib ]]; then
  cp target/release/libneleus_native.dylib neleus_native.so
elif [[ -f target/release/libneleus_native.so ]]; then
  cp target/release/libneleus_native.so neleus_native.so
else
  echo "build: could not find the built library under target/release/" >&2
  exit 1
fi
echo "built neleus_native.so"
