use anyhow::Result;
use serde::{Serialize, de::DeserializeOwned};

pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // DAG-CBOR requires deterministic encoding and map key ordering.
    Ok(serde_ipld_dagcbor::to_vec(value)?)
}

pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_ipld_dagcbor::from_slice(bytes)?)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct T {
        a: String,
        b: Vec<u8>,
    }

    #[test]
    fn canonical_roundtrip() {
        let t = T {
            a: "x".into(),
            b: vec![1, 2, 3],
        };
        let bytes = to_cbor(&t).unwrap();
        let t2: T = from_cbor(&bytes).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn canonical_is_repeatable() {
        let t = T {
            a: "same".into(),
            b: vec![9, 8, 7],
        };
        assert_eq!(to_cbor(&t).unwrap(), to_cbor(&t).unwrap());
    }

    #[test]
    fn canonical_golden_bytes_struct_t() {
        let t = T {
            a: "x".into(),
            b: vec![1, 2, 3],
        };
        let bytes = to_cbor(&t).unwrap();
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

        // Golden bytes lock deterministic canonical serialization for this shape.
        assert_eq!(hex, "a261616178616283010203");
    }

    #[test]
    fn canonical_golden_bytes_nested() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct Nested {
            version: u32,
            tags: Vec<String>,
        }

        let n = Nested {
            version: 7,
            tags: vec!["alpha".into(), "beta".into()],
        };
        let bytes = to_cbor(&n).unwrap();
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

        assert_eq!(
            hex,
            "a264746167738265616c70686164626574616776657273696f6e07"
        );
    }

    #[test]
    fn malformed_cbor_is_rejected() {
        let malformed = vec![0xa2, 0x61, 0x61, 0xff];
        assert!(from_cbor::<T>(&malformed).is_err());
    }
}
