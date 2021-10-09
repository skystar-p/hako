pub const BLOCK_SIZE: usize = 1024 * 1024 * 10;
// pub const BLOCK_SIZE: usize = 1024 * 128;
pub const BLOCK_OVERHEAD: usize = 16;

const BASE_URL: &str = "http://localhost:12321";

pub fn build_url(relative: &str) -> String {
    format!("{}{}", BASE_URL, relative)
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
