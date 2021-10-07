pub mod base64 {
    use serde::Serialize;
    use serde::Serializer;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    // pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    //     let base64 = String::deserialize(d)?;
    //     base64::decode(base64.as_bytes())
    //         .map_err(|e| serde::de::Error::custom(e))
    // }
}
