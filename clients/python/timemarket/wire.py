"""The envelope of an action, and its signature (spec/protocol-4.md, section 4; the engine is v5/src/wire.rs).

An action of the market is these bytes, in this order::

    "TCDEVNET-ACTION-V1\\0"      19 bytes, the same on every network
    network id                   32 bytes
    kind                         1 byte (50 to 58 here)
    from, nonce, authority epoch 8 bytes each, big-endian
    public key of the signer     32 bytes (Ed25519)
    length of the payload        4 bytes, big-endian
    payload                      canonical JSON: keys ascending, no spaces, every number a decimal string
    signature                    64 bytes, Ed25519 over every byte before it

``sign_action`` writes them, byte for byte as the engine (``wire::sign``) and the SDK (``signAction``)
do; spec/market-vectors.json holds all three to the same bytes.

Signing needs Ed25519, which Python's standard library does not have: the ``cryptography`` package is
used if it can be imported, else ``PyNaCl``. Nothing else here needs more than the standard library.
"""
from __future__ import annotations

import json
import re

from . import actions, keys

DOMAIN = b"TCDEVNET-ACTION-V1\x00"
"""The first bytes of every action."""
HEADER_BYTES = len(DOMAIN) + 32 + 1 + 24 + 32 + 4
"""The bytes of an action before its payload."""
MAX_PAYLOAD_BYTES = 512 * 1024
_U64_MAX = 2**64 - 1
_NO_ED25519 = (
    "Signing needs Ed25519, which Python's standard library does not have. Install the 'cryptography' package "
    "(pip install cryptography) or 'PyNaCl' (pip install pynacl); this package uses whichever it finds, and "
    "writes no Ed25519 of its own."
)
BACKENDS = ("cryptography", "pynacl")
MINIMUM_VERSIONS = {"cryptography": (42, 0, 0), "pynacl": (1, 5, 0)}
"""The oldest release of each Ed25519 library this package signs with. An older one is refused."""


def _recent(name: str, version) -> None:
    """Refuses a release of the Ed25519 library ``name`` that is older than this package accepts."""
    numbers = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version if isinstance(version, str) else "")
    found = tuple(int(part or 0) for part in numbers.groups()) if numbers else (0, 0, 0)
    if found < MINIMUM_VERSIONS[name]:
        least = ".".join(str(part) for part in MINIMUM_VERSIONS[name])
        raise RuntimeError(f"The installed {name} is older than {least}, the oldest release this package signs with: install a current one")


# ---------------------------------------------------------------- canonical JSON
def _canonical(value, depth: int):
    if depth > 32:
        raise ValueError("Canonical JSON is nested at most 32 deep")
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        if value < 0 or value > _U64_MAX:
            raise ValueError("A number in canonical JSON is a whole number from 0 to 2^64-1")
        return value
    if isinstance(value, (list, tuple)):
        return [_canonical(item, depth + 1) for item in value]
    if type(value) is dict:
        if not all(isinstance(key, str) for key in value):
            raise ValueError("The keys of canonical JSON are strings")
        return {key: _canonical(value[key], depth + 1) for key in sorted(value)}
    raise ValueError(f"Canonical JSON holds objects, lists, strings, whole numbers, true, false and null: not {type(value).__name__}")


def canonical_json(value) -> bytes:
    """The bytes of a JSON value as the chain writes one: keys ascending at every depth, no spaces, UTF-8.

    The chain writes amounts as decimal strings; a ``float`` is refused. (The market's payloads go
    through ``canonical_payload``, which also checks them.)
    """
    return json.dumps(_canonical(value, 0), separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_payload(kind: int, payload: dict) -> bytes:
    """The bytes of a market payload (kind 50 to 58) as they are signed, after it is checked."""
    return actions.payload_bytes(kind, payload)


# ---------------------------------------------------------------- Ed25519, from a library
def _seed_bytes(seed) -> bytes:
    if isinstance(seed, keys.Seed):
        return seed.reveal()
    if isinstance(seed, str) and re.fullmatch(r"[0-9a-f]{64}", seed):
        seed = bytes.fromhex(seed)
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("A signing key is its seed: 32 bytes, or 64 lowercase hexadecimal characters")
    return bytes(seed)


def _backend(name: str | None = None):
    """(sign, public key, verify) of the Ed25519 library found, or of the one named."""
    if name is not None and name not in BACKENDS:
        raise ValueError(f"The Ed25519 libraries this package knows are {', '.join(BACKENDS)}")
    if name in (None, "cryptography"):
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
            import cryptography
        except ImportError:
            if name == "cryptography":
                raise RuntimeError(_NO_ED25519) from None
        else:
            _recent("cryptography", getattr(cryptography, "__version__", None))
            raw = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)

            def verify(public: bytes, signature: bytes, message: bytes) -> bool:
                try:
                    Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
                except (InvalidSignature, ValueError):
                    return False
                return True

            return (
                lambda seed, message: Ed25519PrivateKey.from_private_bytes(seed).sign(message),
                lambda seed: Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(*raw),
                verify,
            )
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import SigningKey, VerifyKey
        import nacl
    except ImportError:
        raise RuntimeError(_NO_ED25519) from None
    _recent("pynacl", getattr(nacl, "__version__", None))

    def verify(public: bytes, signature: bytes, message: bytes) -> bool:
        try:
            VerifyKey(public).verify(message, signature)
        except (BadSignatureError, ValueError, TypeError):
            return False
        return True

    return (
        lambda seed, message: SigningKey(seed).sign(message).signature,
        lambda seed: bytes(SigningKey(seed).verify_key),
        verify,
    )


def public_key(seed, *, backend: str | None = None) -> str:
    """The public key of a signing key, 64 lowercase hexadecimal characters: what the account's row lists.

    It makes no signature. ``seed`` is taken as ``sign_action`` takes it.
    """
    return _backend(backend)[1](_seed_bytes(seed)).hex()


# ---------------------------------------------------------------- the envelope
def _u64(value, name: str) -> bytes:
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        value = int(value)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > _U64_MAX:
        raise ValueError(f"{name} is a whole number from 0 to 2^64-1: an int, or a decimal string without leading zeros")
    return value.to_bytes(8, "big")


def _hex32(value, name: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{name} is 64 lowercase hexadecimal characters")
    return bytes.fromhex(value)


def build_action(*, network_id: str, kind: int, sender, nonce, auth_epoch, public_key: str, payload: dict) -> bytes:
    """The bytes of an action that are signed: everything but the signature.

    ``sender`` is the account's number (the field ``from`` of the envelope), ``nonce`` the account's
    nonce plus one, ``auth_epoch`` the account's authority epoch, all read from the chain just before.
    """
    body = canonical_payload(kind, payload)
    return b"".join(
        (
            DOMAIN,
            _hex32(network_id, "network_id"),
            bytes([kind]),
            _u64(sender, "sender"),
            _u64(nonce, "nonce"),
            _u64(auth_epoch, "auth_epoch"),
            _hex32(public_key, "public_key"),
            len(body).to_bytes(4, "big"),
            body,
        )
    )


def sign_action(*, network_id: str, kind: int, sender, nonce, auth_epoch, payload: dict, seed, backend: str | None = None) -> bytes:
    """A signed action of the market, ready to submit: the envelope and its signature.

    THIS IS THE ONE FUNCTION OF THE PACKAGE THAT SIGNS. Nothing else here makes a signature, and a
    program built on the package should sign nowhere else: then one place decides what your key puts
    its name to, and it only ever signs a payload that ``actions.action_payload`` has checked.

    ``seed`` is the signing key of a key of the account that can spend: a ``keys.Seed`` (what
    ``keys.seed_from_key_store`` and ``keys.seed_from_env`` return), 32 bytes, or 64 lowercase
    hexadecimal characters. Ed25519 signatures are deterministic: the same arguments give the same
    bytes, which is what lets spec/market-vectors.json check this function, and any other program
    that claims to do the same, byte for byte. ``backend`` names the Ed25519 library ('cryptography'
    or 'pynacl'); left out, the first that can be imported is used.
    """
    sign, public, verify = _backend(backend)
    seed = _seed_bytes(seed)
    key = public(seed)
    body = build_action(network_id=network_id, kind=kind, sender=sender, nonce=nonce, auth_epoch=auth_epoch, public_key=key.hex(), payload=payload)
    signature = sign(seed, body)
    if len(signature) != 64 or not verify(key, signature, body):
        raise RuntimeError("The signature just made does not verify: the Ed25519 library is not working")
    return body + signature


def decode_action(raw: bytes) -> dict:
    """Reads a signed action of the market back, strictly.

    Returns ``{"network_id", "kind", "sender", "nonce", "auth_epoch", "public_key", "payload",
    "signature"}`` (numbers as decimal strings, as the chain writes them). Raises ``ValueError`` for
    bytes that are not exactly one action of kind 50 to 58 with its payload in its one form. The
    signature is not checked here: ``verify_action`` does.
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < HEADER_BYTES + 64 or not bytes(raw).startswith(DOMAIN):
        raise ValueError("These bytes are not an action: too short, or without the domain every action begins with")
    raw, at = bytes(raw), len(DOMAIN)
    network_id, kind = raw[at : at + 32].hex(), raw[at + 32]
    at += 33
    sender, nonce, auth_epoch = (int.from_bytes(raw[at + 8 * i : at + 8 * i + 8], "big") for i in range(3))
    at += 24
    key, length = raw[at : at + 32].hex(), int.from_bytes(raw[at + 32 : at + 36], "big")
    at += 36
    if length > MAX_PAYLOAD_BYTES or len(raw) != at + length + 64:
        raise ValueError("These bytes are not one action: its length is not what its header says")
    if not 50 <= kind <= 58:
        raise ValueError(f"This is an action of kind {kind}: this package reads the kinds of the market, 50 to 58")
    try:
        payload = json.loads(raw[at : at + length].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("The payload of this action is not JSON") from None
    if canonical_payload(kind, payload) != raw[at : at + length]:
        raise ValueError("The payload of this action is not written the one way a payload is written")
    return {
        "network_id": network_id,
        "kind": kind,
        "sender": str(sender),
        "nonce": str(nonce),
        "auth_epoch": str(auth_epoch),
        "public_key": key,
        "payload": payload,
        "signature": raw[at + length :].hex(),
    }


def verify_action(raw: bytes, *, backend: str | None = None) -> dict:
    """Reads a signed action back (``decode_action``) and checks that its signature is one of the key it names.

    It does not say that the key is a key of the account, or that the chain will take the action.
    """
    action = decode_action(raw)
    if not _backend(backend)[2](bytes.fromhex(action["public_key"]), bytes(raw[-64:]), bytes(raw[:-64])):
        raise ValueError("The signature of this action is not one of the key it names")
    return action


def transaction_hash(raw: bytes) -> str:
    """The hash under which the chain and the API know a signed action: SHA-256, 64 capital hexadecimal characters."""
    import hashlib

    return hashlib.sha256(bytes(raw)).hexdigest().upper()
