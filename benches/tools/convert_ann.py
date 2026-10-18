"""Convert an ann-benchmarks HDF5 file to the raw matrices benches/datasets.rs reads."""
import struct
import sys

import h5py
import numpy as np


def write(path, array, dtype):
    array = np.ascontiguousarray(array, dtype=dtype)
    with open(path, "wb") as f:
        f.write(struct.pack("<II", *array.shape))
        f.write(array.astype(array.dtype.newbyteorder("<")).tobytes())


src, out = sys.argv[1], sys.argv[2]
with h5py.File(src, "r") as h:
    write(out + ".train.f32", h["train"][:], np.float32)
    write(out + ".test.f32", h["test"][:], np.float32)
    write(out + ".gt.u32", h["neighbors"][:, :100], np.uint32)
