use std::borrow::Cow;

use anyhow::{Result, anyhow};

/// Frame tags for stored CAS payloads. The compression decision is recorded
/// explicitly rather than sniffed: a plaintext that happens to begin with the
/// zstd magic would otherwise be inflated on read, breaking `hash(get(h)) == h`.
const FRAME_RAW: u8 = 0x00;
const FRAME_ZSTD: u8 = 0x01;

/// Compress `bytes` with zstd at the default compression level.
pub fn compress(bytes: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(bytes, 0).map_err(|e| anyhow!("zstd compress failed: {e}"))
}

/// Inflate a zstd frame. Callers that store their own compressed/raw flag use
/// this directly; CAS payloads go through [`frame`] / [`unframe`].
pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(bytes).map_err(|e| anyhow!("zstd decompress failed: {e}"))
}

/// Tag `bytes` for storage, compressing when `compressed` is set.
pub fn frame(bytes: &[u8], compressed: bool) -> Result<Vec<u8>> {
    let body: Cow<'_, [u8]> = if compressed {
        Cow::Owned(compress(bytes)?)
    } else {
        Cow::Borrowed(bytes)
    };
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(if compressed { FRAME_ZSTD } else { FRAME_RAW });
    out.extend_from_slice(&body);
    Ok(out)
}

/// Inverse of [`frame`]. Borrows for the uncompressed case so the common path
/// pays no copy.
pub fn unframe(stored: &[u8]) -> Result<Cow<'_, [u8]>> {
    match stored.split_first() {
        Some((&FRAME_RAW, body)) => Ok(Cow::Borrowed(body)),
        Some((&FRAME_ZSTD, body)) => Ok(Cow::Owned(decompress(body)?)),
        Some((tag, _)) => Err(anyhow!("unknown storage frame tag {tag:#04x}")),
        None => Err(anyhow!("stored payload is empty")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_decompress_roundtrip() {
        let data = b"hello world hello world hello world";
        let compressed = compress(data).unwrap();
        assert_eq!(decompress(&compressed).unwrap(), data);
    }

    #[test]
    fn frame_roundtrip_both_modes() {
        let data = b"hello world hello world hello world";
        for compressed in [false, true] {
            let stored = frame(data, compressed).unwrap();
            assert_eq!(&*unframe(&stored).unwrap(), data);
        }
    }

    #[test]
    fn uncompressed_frame_is_borrowed() {
        let stored = frame(b"plain bytes", false).unwrap();
        let out = unframe(&stored).unwrap();
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn plaintext_that_looks_like_zstd_survives_roundtrip() {
        // The exact failure the frame tag exists to prevent.
        let looks_compressed = compress(b"inner payload").unwrap();
        let stored = frame(&looks_compressed, false).unwrap();
        assert_eq!(&*unframe(&stored).unwrap(), &looks_compressed[..]);
    }

    #[test]
    fn unknown_tag_is_rejected() {
        assert!(unframe(b"\x7ftampered").is_err());
        assert!(unframe(b"").is_err());
    }

    #[test]
    fn compressed_is_smaller_for_repetitive_data() {
        let data = b"aaaa".repeat(512);
        let compressed = compress(&data).unwrap();
        assert!(compressed.len() < data.len());
    }
}
