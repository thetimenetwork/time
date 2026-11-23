//! Canonical extensions to the existing action header. New network domain 4
//! isolates signatures; legacy kinds 1..16 retain their original exact encoding.
use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;

pub const DOMAIN: &[u8] = b"TCDEVNET-ACTION-V1\0";
pub const HEADER: usize = DOMAIN.len() + 32 + 1 + 24 + 32 + 4;
pub const MAX_PAYLOAD: usize = 512 * 1024;
pub fn extension_kind(kind: u8) -> bool {
    matches!(
        kind,
        17 | 18 | 19 | 20 | 21 | 23 | 24 | 40 | 41 | 42 | 44 | 60 | 61 | 62 | 63
    )
}
#[derive(Clone, Debug)]
pub struct SignedAction {
    pub network_id: String,
    pub from: u64,
    pub nonce: u64,
    pub auth_epoch: u64,
    pub public_key: String,
    pub kind: u8,
    pub payload: Value,
    pub raw_signing_bytes: Vec<u8>,
    pub signature: Vec<u8>,
}
impl SignedAction {
    pub fn verify_signer(&self) -> Result<()> {
        ensure!(
            self.kind != 40,
            "public header relay does not authorize an account"
        );
        let raw: [u8; 32] = hex::decode(&self.public_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signer"))?;
        let key = VerifyingKey::from_bytes(&raw)?;
        ensure!(!key.is_weak(), "weak signer");
        key.verify_strict(
            &self.raw_signing_bytes,
            &Signature::from_slice(&self.signature)?,
        )?;
        Ok(())
    }
    pub fn is_public_headers(&self) -> bool {
        self.kind == 40
            && self.from == u64::MAX
            && self.nonce == 0
            && self.auth_epoch == 0
            && self.public_key == "00".repeat(32)
            && self.signature == vec![0; 64]
    }
}
pub fn decode(raw: &[u8]) -> Result<SignedAction> {
    ensure!(
        raw.len() >= HEADER + 64
            && raw.len() <= HEADER + MAX_PAYLOAD + 64
            && raw.starts_with(DOMAIN),
        "v4 action envelope bounds/domain"
    );
    let mut offset = DOMAIN.len();
    let network_id = hex::encode(&raw[offset..offset + 32]);
    offset += 32;
    let kind = raw[offset];
    offset += 1;
    ensure!(extension_kind(kind), "unsupported extension kind");
    let mut next = || {
        let value = u64::from_be_bytes(raw[offset..offset + 8].try_into().unwrap());
        offset += 8;
        value
    };
    let from = next();
    let nonce = next();
    let auth_epoch = next();
    let public_key = hex::encode(&raw[offset..offset + 32]);
    offset += 32;
    let length = u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    ensure!(
        length <= MAX_PAYLOAD && raw.len() == offset + length + 64,
        "action length/trailing bytes"
    );
    let payload: Value = serde_json::from_slice(&raw[offset..offset + length])?;
    ensure!(
        payload.is_object() && serde_json::to_vec(&payload)? == raw[offset..offset + length],
        "extension payload must use recursively sorted canonical JSON"
    );
    let action = SignedAction {
        network_id,
        from,
        nonce,
        auth_epoch,
        public_key,
        kind,
        payload,
        raw_signing_bytes: raw[..offset + length].to_vec(),
        signature: raw[offset + length..].to_vec(),
    };
    ensure!(
        kind != 40 || action.is_public_headers(),
        "invalid public relay authority"
    );
    Ok(action)
}
fn bytes(
    network: &str,
    from: u64,
    nonce: u64,
    epoch: u64,
    public: &[u8; 32],
    kind: u8,
    payload: &Value,
) -> Result<Vec<u8>> {
    ensure!(
        extension_kind(kind) && payload.is_object(),
        "unsupported action kind/payload"
    );
    let net = hex::decode(network)?;
    ensure!(
        net.len() == 32 && hex::encode(&net) == network,
        "invalid network"
    );
    let json = serde_json::to_vec(payload)?;
    ensure!(json.len() <= MAX_PAYLOAD, "extension payload too large");
    let mut raw = DOMAIN.to_vec();
    raw.extend(net);
    raw.push(kind);
    for value in [from, nonce, epoch] {
        raw.extend(value.to_be_bytes());
    }
    raw.extend(public);
    raw.extend((json.len() as u32).to_be_bytes());
    raw.extend(json);
    Ok(raw)
}
pub fn sign(
    network: &str,
    from: u64,
    nonce: u64,
    epoch: u64,
    kind: u8,
    payload: &Value,
    key: &SigningKey,
) -> Result<Vec<u8>> {
    ensure!(kind != 40, "header relay must use public encoding");
    let mut raw = bytes(
        network,
        from,
        nonce,
        epoch,
        key.verifying_key().as_bytes(),
        kind,
        payload,
    )?;
    let signature = key.sign(&raw);
    raw.extend(signature.to_bytes());
    decode(&raw)?
        .verify_signer()
        .context("self-check extension")?;
    Ok(raw)
}
pub fn public_headers(network: &str, payload: &Value) -> Result<Vec<u8>> {
    let mut raw = bytes(network, u64::MAX, 0, 0, &[0; 32], 40, payload)?;
    raw.extend([0; 64]);
    decode(&raw)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extension_signature_covers_all_coordinates() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let raw = sign(
            &"01".repeat(32),
            4,
            9,
            3,
            18,
            &serde_json::json!({"amount":"1000000"}),
            &key,
        )
        .unwrap();
        decode(&raw).unwrap().verify_signer().unwrap();
        for at in [
            DOMAIN.len(),
            DOMAIN.len() + 32 + 1,
            HEADER - 5,
            HEADER + 5,
            raw.len() - 1,
        ] {
            let mut bad = raw.clone();
            bad[at] ^= 1;
            assert!(decode(&bad).and_then(|a| a.verify_signer()).is_err());
        }
    }
    #[test]
    fn relay_has_no_account_authority_or_ambiguous_trailing_bytes() {
        let mut raw = public_headers(&"02".repeat(32), &serde_json::json!({"headers":[]})).unwrap();
        assert!(decode(&raw).unwrap().is_public_headers());
        assert!(decode(&raw).unwrap().verify_signer().is_err());
        raw.push(0);
        assert!(decode(&raw).is_err());
    }
}
