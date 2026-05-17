use std::borrow::Cow;

use anyhow::{Result, anyhow};

/// zstd frame magic bytes: 0xFD2FB528 in little-endian order.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Compress `bytes` with zstd at the default compression level.
pub fn compress(bytes: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(bytes, 0).map_err(|e| anyhow!("zstd compress failed: {e}"))
}

/// Decompress `bytes` if they start with the zstd magic, otherwise borrow the
/// input unchanged. Returning `Cow` avoids a full copy of every uncompressed
/// blob — the common case when compression is off.
pub fn decompress_if_compressed(bytes: &[u8]) -> Result<Cow<'_, [u8]>> {
    if bytes.starts_with(&ZSTD_MAGIC) {
        zstd::decode_all(bytes)
            .map(Cow::Owned)
            .map_err(|e| anyhow!("zstd decompress failed: {e}"))
    } else {
        Ok(Cow::Borrowed(bytes))
    }
}

/// Returns true when `bytes` appear to be a zstd-compressed frame.
pub fn is_compressed(bytes: &[u8]) -> bool {
    bytes.starts_with(&ZSTD_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_decompress_roundtrip() {
        let data = b"hello world hello world hello world";
        let compressed = compress(data).unwrap();
        assert!(is_compressed(&compressed));
        let back = decompress_if_compressed(&compressed).unwrap();
        assert!(matches!(back, Cow::Owned(_)));
        assert_eq!(&*back, data);
    }

    #[test]
    fn uncompressed_bytes_pass_through_without_copy() {
        let data = b"plain bytes without zstd magic";
        let out = decompress_if_compressed(data).unwrap();
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "uncompressed input should be borrowed, not copied"
        );
        assert_eq!(&*out, data);
    }

    #[test]
    fn compressed_is_smaller_for_repetitive_data() {
        let data = b"aaaa".repeat(512);
        let compressed = compress(&data).unwrap();
        assert!(compressed.len() < data.len());
    }
}
