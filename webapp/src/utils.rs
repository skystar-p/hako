pub const BLOCK_SIZE: usize = 1024 * 1024 * 10;
// pub const BLOCK_SIZE: usize = 1024 * 128;
pub const BLOCK_OVERHEAD: usize = 16;

pub fn join_uri<P, Q>(base_uri: P, rest: Q) -> String
where
    P: AsRef<str>,
    Q: AsRef<str>,
{
    let base_uri = base_uri.as_ref();
    let rest = rest.as_ref();
    if base_uri.ends_with('/') {
        if let Some(stripped) = rest.strip_prefix('/') {
            format!("{}{}", base_uri, stripped)
        } else {
            format!("{}{}", base_uri, rest)
        }
    } else if rest.starts_with('/') {
        format!("{}{}", base_uri, rest)
    } else {
        format!("{}/{}", base_uri, rest)
    }
}

pub mod base64 {
    use serde::Deserialize;
    use serde::Deserializer;

    // pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    //     let base64 = base64::encode(v);
    //     String::serialize(&base64, s)
    // }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)
    }
}
