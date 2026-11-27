"""Bitcoin addresses and receiving scripts, for the market of seconds against bitcoin (spec/market.md).

An order of the market lists receiving scripts, in lowercase hexadecimal; a person knows an address.
This module turns one into the other, for the five standard forms of spec/market.md, section 5.1, and
no other, on the three Bitcoin networks the chain knows: ``mainnet``, ``testnet3``, ``regtest``.

    p2pkh   76a914 <20 bytes> 88ac   Base58Check, version 0x00 (mainnet), 0x6f (testnet3, regtest)
    p2sh    a914 <20 bytes> 87       Base58Check, version 0x05 (mainnet), 0xc4 (testnet3, regtest)
    p2wpkh  0014 <20 bytes>          Bech32 (BIP173), witness version 0; prefix bc, tb, bcrt
    p2wsh   0020 <32 bytes>          Bech32 (BIP173), witness version 0
    p2tr    5120 <32 bytes>          Bech32m (BIP350), witness version 1

THIS CODE DECIDES WHERE A PERSON'S BITCOIN GOES. It refuses whatever it is not sure of: a wrong
checksum, mixed case, a prefix of another network, a program of another length, a witness version
above 1, a version-0 address with a Bech32m checksum or a version-1 address with a Bech32 one, a
character or a space that does not belong. It never corrects.

What it cannot know:

- The legacy addresses (p2pkh, p2sh) of testnet3 and regtest are the same texts: the two networks
  share their version bytes. Such an address is accepted on both.
- Whether anyone holds the key of an address.
- A Bech32 address written all in capitals is valid (BIP173) and is accepted; ``script_to_address``
  writes small letters. So ``address_to_script(script_to_address(s))`` is ``s``, always, and
  ``script_to_address(address_to_script(a))`` is ``a`` in small letters for a Bech32 address, and
  ``a`` itself for a Base58Check one.

The same rules, messages and test vectors as web-v4/shared/bitcoin-address.mjs. Standard library only.
Every refusal is a ``ValueError`` that says why.
"""
from __future__ import annotations

import hashlib
import re

NETWORKS = ("mainnet", "testnet3", "regtest")
"""The Bitcoin networks, by the names the chain's genesis uses (``bitcoin.network``)."""
FORMS = ("p2pkh", "p2sh", "p2tr", "p2wpkh", "p2wsh")
"""The five forms of receiving script, by the names of spec/market.md, section 5.1, ascending."""

_PARAMS = {
    "mainnet": {"hrp": "bc", "p2pkh": 0x00, "p2sh": 0x05},
    "testnet3": {"hrp": "tb", "p2pkh": 0x6F, "p2sh": 0xC4},
    "regtest": {"hrp": "bcrt", "p2pkh": 0x6F, "p2sh": 0xC4},
}
_HEX = re.compile(r"[0-9a-f]*")
_SCRIPT_FORMS = (
    ("p2pkh", re.compile(r"76a914[0-9a-f]{40}88ac")),
    ("p2sh", re.compile(r"a914[0-9a-f]{40}87")),
    ("p2wpkh", re.compile(r"0014[0-9a-f]{40}")),
    ("p2wsh", re.compile(r"0020[0-9a-f]{64}")),
    ("p2tr", re.compile(r"5120[0-9a-f]{64}")),
)
_NOT_STANDARD = (
    "A receiving script is one of the five standard forms (p2pkh, p2sh, p2wpkh, p2wsh, p2tr), in lowercase hexadecimal"
)


def _params(network: str) -> dict:
    if not isinstance(network, str) or network not in _PARAMS:
        raise ValueError(f"Unknown Bitcoin network: name one of {', '.join(NETWORKS)}")
    return _PARAMS[network]


def _elsewhere(network: str, test) -> str | None:
    """The networks other than ``network`` on which ``test`` holds, as words for a refusal."""
    names = [name for name in NETWORKS if name != network and test(_PARAMS[name])]
    return " or ".join(names) if names else None


def hex_bytes(text: str, what: str) -> bytes:
    """The bytes of lowercase hexadecimal, or a refusal that names ``what``."""
    if not isinstance(text, str) or len(text) % 2 != 0 or not _HEX.fullmatch(text):
        raise ValueError(f"{what} is lowercase hexadecimal, two characters for each byte")
    return bytes.fromhex(text)


def sha256d(data: bytes) -> bytes:
    """SHA-256 of SHA-256, as Bitcoin hashes."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------- receiving scripts
def script_form(script_hex: str) -> str:
    """The form of a receiving script in lowercase hexadecimal: 'p2pkh', 'p2sh', 'p2tr', 'p2wpkh' or 'p2wsh'.

    Raises ``ValueError`` for anything else: another script, capital letters, a byte too many or too
    few. The engine's ``market::form_of`` over ``bitcoin_bridge::standard_script``, and its rule that a
    script is written in lowercase.
    """
    if isinstance(script_hex, str):
        for form, pattern in _SCRIPT_FORMS:
            if pattern.fullmatch(script_hex):
                return form
    raise ValueError(_NOT_STANDARD)


# ---------------------------------------------------------------- Bech32 and Bech32m (BIP173, BIP350)
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_CHECKSUM = {"bech32": 1, "bech32m": 0x2BC830A3}


def _polymod(values) -> int:
    check = 1
    for value in values:
        top = check >> 25
        check = ((check & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                check ^= _GENERATOR[i]
    return check


def _expand(hrp: str) -> list[int]:
    return [ord(letter) >> 5 for letter in hrp] + [0] + [ord(letter) & 31 for letter in hrp]


def decode_bech32(text: str) -> tuple[str, list[int], str]:
    """Reads a Bech32 or Bech32m text (BIP173, BIP350): ``(hrp, words, encoding)``.

    ``hrp`` is in small letters, ``words`` are the five-bit values of the data part without its
    checksum, and ``encoding`` is 'bech32' or 'bech32m', whichever checksum the text carries. Raises
    ``ValueError`` for every other text. Not an address yet: ``address_to_script`` reads what the
    words mean.
    """
    if not isinstance(text, str):
        raise ValueError("A Bech32 text is a string")
    if len(text) > 90:
        raise ValueError("A Bech32 text has at most 90 characters")
    if any(ord(letter) < 33 or ord(letter) > 126 for letter in text):
        raise ValueError(
            "A Bech32 text holds a character that does not belong in one (a space, a control character, or a letter outside ASCII)"
        )
    lower = text.lower()
    if text != lower and text != text.upper():
        raise ValueError("A Bech32 text is written all in small letters or all in capitals: this one mixes them")
    at = lower.rfind("1")
    if at < 0:
        raise ValueError("A Bech32 text has a prefix, the separator 1 and a data part: this one has no separator")
    if at == 0:
        raise ValueError("A Bech32 text has a prefix before its separator: this one has none")
    if at + 7 > len(lower):
        raise ValueError("A Bech32 text ends with a checksum of six characters: this one is too short")
    hrp, words = lower[:at], []
    for letter in lower[at + 1 :]:
        value = _CHARSET.find(letter)
        if value < 0:
            raise ValueError(f"A Bech32 text holds a character that its alphabet does not have: {letter}")
        words.append(value)
    check = _polymod(_expand(hrp) + words)
    if check == _CHECKSUM["bech32"]:
        encoding = "bech32"
    elif check == _CHECKSUM["bech32m"]:
        encoding = "bech32m"
    else:
        raise ValueError("The checksum of this Bech32 text is wrong: a character was mistyped, left out or added")
    return hrp, words[:-6], encoding


def encode_bech32(hrp: str, words, encoding: str) -> str:
    """Writes a Bech32 ('bech32') or Bech32m ('bech32m') text in small letters."""
    if not isinstance(encoding, str) or encoding not in _CHECKSUM:
        raise ValueError("The encoding is bech32 or bech32m")
    if not isinstance(hrp, str) or not re.fullmatch(r"[\x21-\x7e]{1,83}", hrp) or hrp != hrp.lower():
        raise ValueError("A Bech32 prefix is 1 to 83 printable ASCII characters, in small letters")
    if not isinstance(words, (list, tuple)) or not all(
        isinstance(word, int) and not isinstance(word, bool) and 0 <= word < 32 for word in words
    ):
        raise ValueError("Bech32 data is a list of five-bit values")
    words = list(words)
    check = _polymod(_expand(hrp) + words + [0] * 6) ^ _CHECKSUM[encoding]
    everything = words + [(check >> (5 * (5 - i))) & 31 for i in range(6)]
    text = hrp + "1" + "".join(_CHARSET[word] for word in everything)
    if len(text) > 90:
        raise ValueError("A Bech32 text has at most 90 characters")
    return text


def _from_words(words) -> bytes:
    """Five-bit values to bytes, as BIP173 has it: at most four bits of padding, all zero."""
    out, acc, bits = bytearray(), 0, 0
    for word in words:
        acc = (acc << 5) | word
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
            acc &= (1 << bits) - 1
    if bits >= 5:
        raise ValueError("This address has more padding than Bech32 allows")
    if acc != 0:
        raise ValueError("This address has padding bits that are not zero")
    return bytes(out)


def _to_words(data: bytes) -> list[int]:
    words, acc, bits = [], 0, 0
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((acc >> bits) & 31)
            acc &= (1 << bits) - 1
    if bits > 0:
        words.append((acc << (5 - bits)) & 31)
    return words


def _witness_script(address: str, network: str) -> str:
    params = _params(network)
    hrp, words, encoding = decode_bech32(address)
    if hrp != params["hrp"]:
        other = _elsewhere(network, lambda p: p["hrp"] == hrp)
        if other:
            raise ValueError(
                f"This is an address of Bitcoin {other} (it begins with {hrp}1); the network here is {network}, whose addresses begin with {params['hrp']}1"
            )
        raise ValueError(
            f"This is not a Bitcoin {network} address: those begin with {params['hrp']}1, and this one with {hrp}1"
        )
    if not words:
        raise ValueError("This address has no data after its prefix")
    version = words[0]
    if version > 16:
        raise ValueError("This address names a witness version that does not exist")
    if version > 1:
        raise ValueError(
            f"This address is of witness version {version}: the market takes versions 0 and 1 only (p2wpkh, p2wsh, p2tr)"
        )
    # The checksum says which rules the writer followed: a version-0 address under BIP350's checksum,
    # or a version-1 address under BIP173's, is refused by every wallet, and here.
    if version == 0 and encoding != "bech32":
        raise ValueError(
            "A version-0 address (bc1q…) carries a Bech32 checksum (BIP173): this one carries a Bech32m checksum"
        )
    if version == 1 and encoding != "bech32m":
        raise ValueError(
            "A version-1 address (bc1p…) carries a Bech32m checksum (BIP350): this one carries a Bech32 checksum"
        )
    program = _from_words(words[1:])
    if version == 0 and len(program) not in (20, 32):
        raise ValueError(f"A version-0 address holds 20 or 32 bytes: this one holds {len(program)}")
    if version == 1 and len(program) != 32:
        raise ValueError(f"A version-1 address (taproot) holds 32 bytes: this one holds {len(program)}")
    return ("00" if version == 0 else "51") + bytes([len(program)]).hex() + program.hex()


# ---------------------------------------------------------------- Base58Check
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_bytes(text: str) -> bytes:
    value, zeros = 0, 0
    while zeros < len(text) and text[zeros] == "1":
        zeros += 1
    for letter in text:
        digit = _BASE58.find(letter)
        if digit < 0:
            raise ValueError(
                f"This address holds a character that Base58 does not have: {'a space' if letter == ' ' else letter}"
            )
        value = value * 58 + digit
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes(zeros) + body


def _base58_text(data: bytes) -> str:
    zeros = 0
    while zeros < len(data) and data[zeros] == 0:
        zeros += 1
    value, text = int.from_bytes(data, "big"), ""
    while value > 0:
        value, digit = divmod(value, 58)
        text = _BASE58[digit] + text
    return "1" * zeros + text


def _legacy_script(address: str, network: str) -> str:
    params = _params(network)
    if len(address) < 26 or len(address) > 35:
        raise ValueError("A Base58Check address has 26 to 35 characters")
    data = _base58_bytes(address)
    if len(data) != 25:
        raise ValueError(
            "A Base58Check address holds 25 bytes: a version, a hash of 20 bytes and a checksum of 4"
        )
    if sha256d(data[:21])[:4] != data[21:]:
        raise ValueError("The checksum of this address is wrong: a character was mistyped, left out or added")
    version, digest = data[0], data[1:21].hex()
    if version == params["p2pkh"]:
        return f"76a914{digest}88ac"
    if version == params["p2sh"]:
        return f"a914{digest}87"
    other = _elsewhere(network, lambda p: version in (p["p2pkh"], p["p2sh"]))
    if other:
        raise ValueError(f"This is an address of Bitcoin {other}; the network here is {network}")
    raise ValueError(f"This is not a Bitcoin {network} address (its version byte is 0x{version:02x})")


# ---------------------------------------------------------------- addresses
_LEGACY_START = "13mn2"


def address_to_script(address: str, network: str) -> str:
    """The receiving script of a Bitcoin address on ``network``, in lowercase hexadecimal.

    ``network`` is 'mainnet', 'testnet3' or 'regtest'. Raises ``ValueError``, with the reason, for a
    text that is not an address of one of the five standard forms on that network.
    """
    _params(network)
    if not isinstance(address, str) or len(address) == 0:
        raise ValueError("An address is a text")
    if re.search(r"\s", address) or any(letter in address for letter in "   ﻿"):
        raise ValueError("An address holds no space and no line break: remove them and check the address again")
    # An address that begins with 1, 3, m, n or 2 is a Base58Check one or nothing: no Bech32 prefix begins so.
    legacy = address[0] in _LEGACY_START
    script = _legacy_script(address, network) if legacy else _witness_script(address, network)
    script_form(script)
    if script_to_address(script, network) != (address if legacy else address.lower()):
        raise ValueError("This address is not written the one way an address is written")
    return script


def script_to_address(script_hex: str, network: str) -> str:
    """The address of a receiving script (lowercase hexadecimal, a standard form) on ``network``.

    Bech32 addresses are written in small letters.
    """
    params, form = _params(network), script_form(script_hex)
    if form in ("p2pkh", "p2sh"):
        digest = script_hex[6:46] if form == "p2pkh" else script_hex[4:44]
        body = bytes([params[form]]) + bytes.fromhex(digest)
        return _base58_text(body + sha256d(body)[:4])
    program = bytes.fromhex(script_hex[4:])
    taproot = form == "p2tr"
    return encode_bech32(params["hrp"], [1 if taproot else 0] + _to_words(program), "bech32m" if taproot else "bech32")
