# Encrypted vault backup format 1

This format transports an existing encrypted random Ed25519 device key between compatible wallets. It does not derive a key from a username/password, enroll a new key, or bypass revocation. Import requires the existing password and independently verified current authority on the already configured network.

The UTF-8 JSON file has exactly `format`, `version` and `vault` fields:

```json
{
  "format": "timecurrency-encrypted-vault",
  "version": 1,
  "vault": {
    "version": 1,
    "binding": { "networkId": "64 lowercase hex", "name": "canonical_name", "publicKey": "64 lowercase hex" },
    "kdf": { "algorithm": "argon2id", "version": 19, "memoryKiB": 65536, "iterations": 3, "parallelism": 1, "hashLength": 32 },
    "salt": "canonical padded standard base64 of 16 bytes",
    "iv": "canonical padded standard base64 of 12 bytes",
    "ciphertext": "canonical padded standard base64 of ciphertext followed by the 16-byte GCM tag"
  }
}
```

The file limit is 16 KiB and the decoded ciphertext limit is 4,096 bytes. Unknown fields/versions, duplicate JSON keys, different KDF profiles, noncanonical base64 and malformed bindings are rejected before password derivation. JSON field order is irrelevant on disk. Numbers in this envelope are JSON integers, not strings.

Derive 32 bytes with Argon2id v19 from the exact UTF-8 password, without trimming or normalization, and the stored salt. Parameters are 65,536 KiB, three passes and one lane. Use the result as an AES-256-GCM key with the stored 96-bit IV and a 128-bit tag. No weaker fallback is allowed.

Reconstruct additional authenticated data with UTF-8 bytes of compact `JSON.stringify` in this exact fixed field order:

```text
{"version":1,"binding":{"networkId":"...","name":"...","publicKey":"..."},"kdf":{"algorithm":"argon2id","version":19,"memoryKiB":65536,"iterations":3,"parallelism":1,"hashLength":32}}
```

Decrypted UTF-8 JSON contains `pkcs8`, the canonical base64 of an Ed25519 PKCS8 DER key. Optional `nameSalt` is 32 bytes of lowercase hex; optional `intent` is `device` or `recovery`. Other plaintext fields are unsupported. Import the signing key as nonextractable and prove it matches `binding.publicKey` by signing and verifying the UTF-8 challenge `TCDEVNET-VAULT-CHECK-V1`.

Before storage, obtain a fresh independently verified account proof for `binding.name` on `binding.networkId`. The exact public key must be in that account's current `devices`; the immutable original-registration-key index is insufficient. Revoked/replaced keys fail even with a correct password. The file cannot choose a gateway, network, trust manifest or executable verifier.

Take the exclusive Web Lock `timecurrency:vault:<networkId>:<name>`. Check `timecurrency.vault.v1:<networkId>:<name>` before derivation and again immediately before writing. An existing record must never be overwritten, even by an identical backup. Store only the encrypted vault record; do not persist the password or decrypted key. Fence asynchronous work against lock, account/network changes and replacement inputs.

Export reopens the stored envelope with its existing password, checks the unlocked binding and fresh enrolled-device authority, then writes only this encrypted envelope. This validates that the exported bytes are usable. Import stores the same device identity; use enrollment to obtain an independently revocable key on another device.

The backup does not include local activity, pending signed actions or payment markers. Check current balances and retained receipts before repeating uncertain payments; V4 nonce-bound order references protect the same payer/order across wallets. Public receipt evidence can be saved separately from Activity. It records a verification event, not a new trust anchor. Historical evidence is reanchored against fresh canonical history; the current checkpoint still expires after seven days.

Password guessing against a stolen file remains possible at the stated KDF cost. This is portable software custody, not hardware protection or guaranteed memory erasure. Possession of both the file and password permits use of the enrolled key until it is revoked.

## Vault records, version 2 (secured accounts)

An account that has adopted the security rules keeps two keys on a device, each in its own record: the sign-in key under the login password (`timecurrency.vault.v1:<networkId>:<name>`, the slot above) and the spend key under a separate payment password (`timecurrency.spend-vault.v1:<networkId>:<name>`). Such a record has `"version": 2` and one more field, `"intent"`, which is `"signin"` or `"spend"`; a version-1 record has the implicit intent `device` (a protocol-4 key with both powers). Every other rule above is unchanged: the same KDF with no weaker fallback, the same sizes and encodings.

The intent is authenticated. The additional data of a version-2 record is, in this fixed order:

```text
{"version":2,"intent":"spend","binding":{"networkId":"...","name":"...","publicKey":"..."},"kdf":{...}}
```

so relabelling a record breaks its decryption. Its plaintext holds `pkcs8` only. A caller states which intents it accepts and the record is refused before any derivation otherwise. Unlocking the wallet, exporting and importing a backup accept `device` and `signin` only, so a backup file can carry a sign-in key but never a spend key, and a payment password is never tried on a login record. Wallets that predate version 2 refuse these records as an unsupported version.
