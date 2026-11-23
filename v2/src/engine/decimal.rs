macro_rules! scalar {
    ($name:ident,$ty:ty) => {
        pub mod $name {
            use serde::{Deserialize, Deserializer, Serializer, de::Error};
            pub fn serialize<S: Serializer>(v: &$ty, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&v.to_string())
            }
            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<$ty, D::Error> {
                let text = String::deserialize(d)?;
                let v = text.parse::<$ty>().map_err(D::Error::custom)?;
                if v.to_string() != text {
                    return Err(D::Error::custom("noncanonical decimal"));
                }
                Ok(v)
            }
        }
    };
}
scalar!(u64, u64);
scalar!(i64, i64);
pub mod vec_u64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
    pub fn serialize<S: Serializer>(v: &[u64], s: S) -> Result<S::Ok, S::Error> {
        v.iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|text| {
                let v = text.parse::<u64>().map_err(D::Error::custom)?;
                if v.to_string() != text {
                    return Err(D::Error::custom("noncanonical decimal"));
                }
                Ok(v)
            })
            .collect()
    }
}
