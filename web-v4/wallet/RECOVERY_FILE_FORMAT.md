# Recovery Kit format 1

A Recovery Kit is a file that holds the recovery sheet of one account, locked with that account's recovery words. It is an option: by default both recovery keys of an account come from its words alone, written on paper ("words only", `security-flows.mjs`, `recoveryWordsSecondKey`). A person who wants the paper alone not to be enough chooses "Words and a Recovery Kit" under Keys, "New recovery words": the wallet then makes a random recovery sheet as the second key, locks it in a kit and has the person save the kit anywhere they will find it again; the words are written on paper and kept apart. Recovering such an account needs both: the words open the kit, and the sheet in it and the words are the account's two recovery keys. Losing either one ends recovery. A person who prints the kit instead keeps the same sheet on paper (the printed recovery sheet); nothing else is in the kit. The code is `recovery-file.mjs`.

The UTF-8 JSON file has exactly these fields, written in this order with two spaces of indentation and a final line feed:

```json
{
  "format": "time-recovery-kit",
  "version": 1,
  "note": "This is the Recovery Kit of one Time account. It opens only with the recovery words that were shown with it. To use it, open the Time wallet, press Recover my account, and choose this file.",
  "networkId": "64 lowercase hex",
  "accountName": "canonical_name",
  "kdf": { "algorithm": "argon2id", "version": 19, "memoryKiB": 262144, "iterations": 4, "parallelism": 1, "hashLength": 32 },
  "salt": "canonical padded standard base64 of 16 bytes",
  "iv": "canonical padded standard base64 of 12 bytes",
  "ciphertext": "canonical padded standard base64 of 97 bytes: the ciphertext followed by the 16-byte GCM tag"
}
```

`note` is that sentence exactly, for a person who opens the file in a text editor. It carries no account number: an account signed up protected has none when its kit is made. The file is named `time-recovery-kit-<accountName>-<first 8 hex of networkId>.json`.

**Reading.** Before anything is derived the reader refuses: a file over 4,096 bytes; text that is not JSON; a field named twice in an object; another `format`; another `version` (a JSON integer); any field missing or added, here or in `kdf`; another `note`; another `kdf` than the one above (no other profile, and none weaker, is ever tried); a `networkId` that is not 64 lowercase hex; an `accountName` that is not a canonical name (2 to 15 of `a-z`, `0-9`, `_`); base64 that is not canonical, or bytes of other lengths than 16, 12 and 97. The caller states the network and the account name it expects, and a kit of another one is refused, before anything is derived, with a sentence that names the account and the network the kit is of. Words that are not words the wallet makes, five of them or four (the words of an account made before 24 November 2026), are refused too (`security-flows.mjs`, `parsePassphrase`).

**The key.** Argon2id v19, 262,144 KiB, four passes, one lane, 32 bytes, of the UTF-8 bytes of the recovery words in their canonical form (lower case, one space between the words, as `parsePassphrase` gives them: five words, or four for words made before 24 November 2026), with the salt

```text
UTF-8 "TIME-RECOVERY-KIT-WORDS-V1" || 0x00 || the 16 bytes of "salt"
```

The result is an AES-256-GCM key, used with the stored 96-bit IV and a 128-bit tag.

The same words give the account's recovery key on the chain through the same Argon2id with other salts (`passphraseSalt`, which begins with `TCDEVNET-RECOVERY-PASSPHRASE-V1`, and `registrationPassphraseSalt`, which begins with `TCDEVNET-RECOVERY-PASSPHRASE-REGISTRATION-V1`; and for an account that is words only the second key too, `TCDEVNET-RECOVERY-WORDS-SECOND-V1` and `...-REGISTRATION-V1`). The domains differ, so the key that locks the kit is never a recovery key, and the kit's bytes tell nothing about one.

**Additional authenticated data.** The UTF-8 bytes of compact `JSON.stringify` of the header in this fixed order, so that a kit whose network, name or way of locking was changed does not open:

```text
{"format":"time-recovery-kit","version":1,"networkId":"...","accountName":"...","kdf":{"algorithm":"argon2id","version":19,"memoryKiB":262144,"iterations":4,"parallelism":1,"hashLength":32}}
```

**Plaintext.** Compact JSON with one field, the sheet in its printed form (14 groups of 4 characters of `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, one space between), 81 bytes:

```text
{"sheet":"XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX"}
```

The reader takes it only in exactly this form and only with a checksum that holds (`security-flows.mjs`, `decodeSheet`). Wrong words and a damaged file are told in one sentence: "These recovery words do not open this Recovery Kit, or the file is damaged."

**Writing.** A new kit has 16 random bytes of salt and 12 random bytes of IV. The wallet writes it from memory and stores nothing of it; this module touches no network and no storage. The key bytes, the bytes of the words and the plaintext are overwritten after use, as far as JavaScript lets a buffer be.

**What it protects, and what not.** The kit alone opens nothing: guessing 90 bits of words (72 for four) at 256 MiB a guess is out of reach. The words alone are one recovery key: they can freeze the account, and with the payment password pay above the limit or make new words, as before. Whoever has the kit and the words has both recovery keys, which ask for new keys of the account; that waits the account's waiting period, frozen, and the payment password with one recovery key cancels it. Keep the words on paper only, and the kit somewhere the words are not.

## Test vector

Words `kerine netoji nesimo vebine`; salt the bytes `10 11 … 1f`; IV the bytes `20 21 … 2b`. The sheet is the one of the seed `00 01 … 1f` (`000G 40R4 0M30 E209 185G R38E 1W81 24GK 2GAH C5RR 34D1 P70X 3RFM VEE0`). The key is `c8282aaf2905507d47402637ec21434180131c1c3f9bcb0dc2830debca342621`.

```json
{
  "format": "time-recovery-kit",
  "version": 1,
  "note": "This is the Recovery Kit of one Time account. It opens only with the recovery words that were shown with it. To use it, open the Time wallet, press Recover my account, and choose this file.",
  "networkId": "c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6",
  "accountName": "alice",
  "kdf": {
    "algorithm": "argon2id",
    "version": 19,
    "memoryKiB": 262144,
    "iterations": 4,
    "parallelism": 1,
    "hashLength": 32
  },
  "salt": "EBESExQVFhcYGRobHB0eHw==",
  "iv": "ICEiIyQlJicoKSor",
  "ciphertext": "avJdjTQgQm9MEX4pOGYRivd1H7HiFXEmVybEOaq+eat0GneUI3lWSHGFjtKgzhq+mYspbwXe2TRVMEZCbvFB/6GcpkWtIXtxERmDRxmQJ9Gi2s8grc2hOgPO3AynM98w3g=="
}
```

`recovery-file.test.mjs` opens this vector with Node's own Argon2id and WebCrypto, following this document only.
