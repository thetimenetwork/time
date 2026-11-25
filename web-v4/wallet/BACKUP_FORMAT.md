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

## Vault records, version 3 (keys locked to a device)

"Lock my keys to this device" (`device-lock.mjs`) keeps an account's sign-in key and spend key so that each opens only with the password and the device together. Such a record has `"version": 3`, the `"intent"` of version 2 (`"signin"` or `"spend"`; a version-1 key cannot be locked) and one more field, `"device": { "credential": "<WebAuthn credential id, unpadded base64url, 22 to 1,364 characters>" }`, which names the device's key. Its fields are exactly `binding`, `ciphertext`, `device`, `intent`, `iv`, `kdf`, `salt`, `version`; the KDF profile, sizes and encodings are those above.

The additional data is the whole header, in this fixed order:

```text
{"version":3,"intent":"spend","binding":{"networkId":"...","name":"...","publicKey":"..."},"kdf":{...},"device":{"credential":"..."}}
```

The vault key: first the 32 bytes of Argon2id from the password and the record's salt, as above. Then the device gives 32 bytes for this vault: WebAuthn PRF (CTAP2 hmac-secret) of the key named in `device`, evaluated with the salt

```text
TIME-DEVICE-LOCK-V1 \0 <purpose: login | spend> \0 <networkId> \0 <name> \0 <binding.publicKey>
```

(UTF-8, `\0` a zero byte; `login` for a `signin` record), after the device checked the person (user verification required, the UV flag checked). The AES-256-GCM key is HKDF-SHA-256 with input key material the Argon2id output followed by the device's 32 bytes, salt the record's 16-byte salt, and info the UTF-8 bytes of `TCDEVNET-VAULT-DEVICE-LOCK-V1`, a zero byte and the header above. No weaker fallback: a version-3 record that comes without the device's 32 bytes is refused before any derivation, and a record changed to look like version 1 or 2 fails its authentication (its header is the additional data). Wallets that predate version 3 refuse these records as an unsupported version.

A backup file never carries a version-3 record: a file opens with a password alone. While the lock is on, export is not offered, and an import of a file holding such a record is refused before any derivation ("This backup holds a key locked to a device. A backup file cannot carry one: it would open with a password alone.").

## The rule, and passwords the wallet made (since 24 November 2026)

From this version on the wallet never seals a key under a password a person chose, alone. Every record it writes, in the browser or in a file, is sealed one of three ways: (i) with the device's secret and the password together (version 3); (ii) under a password the wallet made, of 72 random bits (the mark below); (iii) under a key derived from another key of the same account that is itself sealed one of those ways (version 4). The wallet's `sealVault` refuses anything else before any derivation. Records of versions 1 and 2 without the mark, sealed before this version under passwords people chose, keep opening exactly as above.

### The mark of a password the wallet made

A record of version 1, 2 or 3 whose password the wallet made has one more field, `"password": "made"` (the only value), so its fields are those of its version plus `password`. The mark is part of the header, after `version` and `intent` and before `binding`, so it is in the additional authenticated data and cannot be added or removed without failing decryption:

```text
{"version":2,"intent":"spend","password":"made","binding":{"networkId":"...","name":"...","publicKey":"..."},"kdf":{...}}
{"version":1,"password":"made","binding":{...},"kdf":{...}}
{"version":3,"intent":"signin","password":"made","binding":{...},"kdf":{...},"device":{"credential":"..."}}
```

A made password is four words of three syllables each; a syllable is one of the 16 consonants `b d f g h j k l m n p r s t v z` followed by one of the 4 vowels `a e i o` (6 bits), so a word carries 18 bits and the password 72. It comes from 9 bytes of the browser's own `crypto.getRandomValues`, cut into twelve 6-bit values in order, most significant first: every value is reachable and none is likelier. One made password seals one record, once: the wallet never puts two records under the same made password. Its one canonical form is the four words in lower case joined by single dashes (`kerine-netoji-nesimo-vebine`), which is how the wallet shows it. Before Argon2id, a reader of a marked record takes what was typed, applies Unicode NFKC, lowers its case, removes every space and every dash (Unicode dash punctuation and U+2212), and requires exactly twelve such syllables; the canonical form of those is the password, as UTF-8. Text that does not reduce so is refused before any derivation, with a sentence that says the password is one the wallet made. Everything else (Argon2id, AES-256-GCM, the device's part of version 3) is as above, with the canonical form in place of the exact typed text. A record without the mark is read with the exact typed text, as always.

A made password is only shown: once, before what it seals is kept or sent, and what it seals is kept only once the person pressed "I have them". The login password is offered to the browser's password manager under the account's name; the payment password is in no field.

### Wallets from before this version

A wallet from before this version (`main` before 24 November 2026) refuses every record that has the mark (versions 1, 2 and 3) and every record of version 4, as an unsupported vault ("Unsupported vault version, intent or KDF. No weaker fallback is permitted."); it opens a record of version 3 without the mark. So going back to such a page leaves every key sealed since unopenable there (the records stay in the browser, and a page of this version opens them again), and such a wallet cannot restore a backup file made since: every file made now holds a record with the mark.

### Version 4: a key kept under another key

The registration key of a protected sign-up, kept until the chain holds the account, is sealed under the account's new login key, not under a password. Such a record has exactly the fields `binding`, `ciphertext`, `iv`, `salt`, `under` and `version` (4), with `"under": { "intent": "signin", "publicKey": "<64 lowercase hex>" }` naming that login key (never the record's own key). There is no `kdf`. The additional data is the header in this fixed order:

```text
{"version":4,"binding":{"networkId":"...","name":"...","publicKey":"..."},"under":{"intent":"signin","publicKey":"..."}}
```

The AES-256-GCM key is HKDF-SHA-256 with input key material the 32-byte Ed25519 seed of the login key named in `under` (the private key octet string inside its PKCS#8), salt the record's 16-byte salt, and info the UTF-8 bytes of `TCDEVNET-VAULT-UNDER-KEY-V1`, a zero byte and the header above. No Argon2id: the seed has 256 bits. The plaintext is that of version 1 (`pkcs8`, `nameSalt`, `intent`). It opens only once the login key it names was opened itself (with its password, and the device when it is locked); nothing typed opens it, and a wallet asked to open it with a password refuses at once. Wallets that predate version 4 refuse it as an unsupported version.

### What a backup file may carry now

Export makes a file only of a record whose password the wallet made (the mark above); a record of a chosen password, from before, makes no file ("This browser makes a backup file only of a key whose password the wallet made: a file of a key under a password you chose could be guessed on another computer. Let the wallet make your passwords, under Keys, first."). A file never carries a version-3 or a version-4 record; both are refused before any derivation on export and on import. A file made before this version, of a chosen password, still opens with its password, and restores; but its record is not written as it is: once the file opened and the account's fresh authority was checked, the same key is sealed again under a password the wallet makes (with the mark), which is shown before that record is kept, and the restored browser opens with that password. Without a way to show it, such a file is refused ("This backup file is locked with a password you chose. The wallet keeps its key only under a password it makes for it, which it shows first."). The file itself is unchanged and keeps opening with its old password.
