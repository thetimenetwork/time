//! Wide integer JSON values are strings so browser verification never rounds.
//! Readers also accept exact JSON integer tokens for old bank-only fixtures.
macro_rules! integer_module {
    ($name:ident, $ty:ty, $visit:ident) => {
        pub mod $name {
            use serde::{Deserializer, Serializer, de};
            use std::fmt;
            pub fn serialize<S: Serializer>(value: &$ty, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&value.to_string())
            }
            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<$ty, D::Error> {
                struct DecimalVisitor;
                impl<'de> de::Visitor<'de> for DecimalVisitor {
                    type Value = $ty;
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("canonical decimal string or exact integer")
                    }
                    fn visit_str<E: de::Error>(self, value: &str) -> Result<$ty, E> {
                        let parsed = value.parse::<$ty>().map_err(E::custom)?;
                        if parsed.to_string() != value {
                            return Err(E::custom("noncanonical decimal string"));
                        }
                        Ok(parsed)
                    }
                    fn visit_u64<E: de::Error>(self, value: u64) -> Result<$ty, E> {
                        <$ty>::try_from(value).map_err(E::custom)
                    }
                    fn visit_i64<E: de::Error>(self, value: i64) -> Result<$ty, E> {
                        <$ty>::try_from(value).map_err(E::custom)
                    }
                }
                deserializer.deserialize_any(DecimalVisitor)
            }
        }
    };
}
integer_module!(u64, u64, visit_u64);
integer_module!(i64, i64, visit_i64);

pub mod u64_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error> {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
        #[derive(Deserialize)]
        struct Decimal(#[serde(with = "super::u64")] u64);
        Ok(Vec::<Decimal>::deserialize(deserializer)?
            .into_iter()
            .map(|v| v.0)
            .collect())
    }
}

pub mod option_u64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(|v| v.to_string()).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        #[derive(Deserialize)]
        struct Decimal(#[serde(with = "super::u64")] u64);
        Ok(Option::<Decimal>::deserialize(deserializer)?.map(|v| v.0))
    }
}
