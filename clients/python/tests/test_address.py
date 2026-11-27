"""The Bitcoin address codec. It decides where a person's bitcoin goes, so it is held to:

- the test vectors of BIP173 and BIP350 and Bitcoin Core's own address data;
- the engine's Bitcoin library: the address of every standard script on each network, and the form of scripts;
- an independent Base58Check written here;
- every single wrong, missing, added or swapped character of an address of each form on each network.
"""
import hashlib
import unittest

from timemarket.address import (
    FORMS,
    NETWORKS,
    address_to_script,
    decode_bech32,
    encode_bech32,
    script_form,
    script_to_address,
)

from . import ADDRESSES, ENGINE

HRP = {"bc": "mainnet", "tb": "testnet3", "bcrt": "regtest"}
SCRIPT = {
    "p2pkh": lambda h: f"76a914{h}88ac",
    "p2sh": lambda h: f"a914{h}87",
    "p2wpkh": lambda h: f"0014{h}",
    "p2wsh": lambda h: f"0020{h}",
    "p2tr": lambda h: f"5120{h}",
}
HASH_BYTES = {"p2pkh": 20, "p2sh": 20, "p2wpkh": 20, "p2wsh": 32, "p2tr": 32}


def standard(script):
    try:
        return script_form(script)
    except ValueError:
        return None


def source(label):
    """A generator of bytes that gives the same bytes on every run."""
    counter = [0]

    def take(length):
        out = b""
        while len(out) < length:
            out += hashlib.sha256(f"{label}/{counter[0]}".encode()).digest()
            counter[0] += 1
        return out[:length]

    return take


class Codec(unittest.TestCase):
    def refused(self, address, network, why=""):
        with self.assertRaisesRegex(ValueError, why, msg=f"{address!r} on {network}"):
            address_to_script(address, network)

    def refused_everywhere(self, address, why=""):
        for network in NETWORKS:
            self.refused(address, network, why)

    def test_the_lists_are_the_chains_names(self):
        self.assertEqual(NETWORKS, ("mainnet", "testnet3", "regtest"))
        self.assertEqual(FORMS, ("p2pkh", "p2sh", "p2tr", "p2wpkh", "p2wsh"))
        self.assertEqual(sorted(FORMS), list(FORMS))

    def test_bip173_and_bip350_texts(self):
        for texts, encoding in ((ADDRESSES["bech32_valid"], "bech32"), (ADDRESSES["bech32m_valid"], "bech32m")):
            self.assertEqual(len(texts), 7)
            for text in texts:
                hrp, words, found = decode_bech32(text)
                self.assertEqual(found, encoding, text)
                self.assertEqual(encode_bech32(hrp, words, encoding), text.lower())
                other = "bech32m" if encoding == "bech32" else "bech32"
                twin = encode_bech32(hrp, words, other)
                self.assertNotEqual(twin, text.lower())
                self.assertEqual(decode_bech32(twin)[2], other)
        for text, why in ADDRESSES["bech32_invalid"] + ADDRESSES["bech32m_invalid"]:
            with self.assertRaises(ValueError, msg=f"{text!r}: {why}"):
                decode_bech32(text)
        for text in (None, 7, ["a12uel5l"], b"a12uel5l", "", "1", "a1", "a12uel5", "a12uel5l ", " a12uel5l", "a12uel5l\n", "a12uel5L", "a12uel5K"):
            with self.assertRaises(ValueError, msg=repr(text)):
                decode_bech32(text)
        for arguments, why in ((("BC", [0], "bech32"), "small letters"), (("bc", [32], "bech32"), "five-bit"), (("bc", [True], "bech32"), "five-bit"), (("bc", [0], "bech32x"), "bech32 or bech32m"), (("bc", [0] * 90, "bech32"), "at most 90")):
            with self.assertRaisesRegex(ValueError, why):
                encode_bech32(*arguments)

    def test_bip_addresses_of_a_standard_form_give_their_script_on_their_network_alone(self):
        taken = 0
        for address, script, bip in ADDRESSES["segwit_valid"]:
            network = HRP[decode_bech32(address)[0]]
            if bip == 350 and standard(script):
                taken += 1
                self.assertEqual(address_to_script(address, network), script, address)
                self.assertEqual(script_to_address(script, network), address.lower())
                for other in NETWORKS:
                    if other != network:
                        self.refused(address, other, f"This is an address of Bitcoin {network} .*the network here is {other}")
            else:
                self.refused_everywhere(address)
        self.assertEqual(taken, 8)
        says = {
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y": r"taproot\) holds 32 bytes: this one holds 40",
            "BC1SW50QGDZ25J": "witness version 16: the market takes versions 0 and 1 only",
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs": "witness version 2",
            "bc1pfeessrawgf": "holds 32 bytes: this one holds 2",
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx": r"carries a Bech32m checksum \(BIP350\): this one carries a Bech32 checksum",
            "BC1SW50QA3JX3S": "witness version 16",
            "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj": "witness version 2",
        }
        for address, why in says.items():
            self.assertTrue(any(text == address for text, _, _ in ADDRESSES["segwit_valid"]), address)
            self.refused(address, "mainnet", why)

    def test_every_invalid_bip_address_is_refused_for_its_own_reason(self):
        says = {
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty": r"not a Bitcoin \w+ address: those begin with \w+1, and this one with tc1",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5": "checksum of this Bech32 text is wrong",
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2": "witness version that does not exist",
            "bc1rw5uspcuh": "witness version 3",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90": "witness version 15",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P": "holds 20 or 32 bytes: this one holds 16",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7": "mixes",
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3t4": "mixes",
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du": "witness version 2",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv": "padding bits that are not zero",
            "bc1gmk9yu": "no data after its prefix",
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut": "this one with tc1",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd": r"carries a Bech32m checksum \(BIP350\): this one carries a Bech32 checksum",
            "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf": "witness version 2",
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL": "witness version 16",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh": r"carries a Bech32 checksum \(BIP173\): this one carries a Bech32m checksum",
            "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47": r"carries a Bech32 checksum \(BIP173\): this one carries a Bech32m checksum",
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4": "alphabet does not have: o",
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R": "witness version that does not exist",
            "bc1pw5dgrnzv": "holds 32 bytes: this one holds 1",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav": "holds 32 bytes: this one holds 41",
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq": "mixes",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf": "more padding than Bech32 allows",
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j": "padding bits that are not zero",
        }
        self.assertEqual(len(ADDRESSES["segwit_invalid"]), 24)
        for address, why in ADDRESSES["segwit_invalid"]:
            self.assertIn(address, says, why)
            self.refused_everywhere(address)
            self.refused(address, HRP.get(address.lower().split("1")[0], "mainnet"), says[address])

    def test_bitcoin_cores_addresses_both_ways(self):
        seen = {}
        for address, script, network in ADDRESSES["core_addresses"]:
            form, legacy = standard(script), address[0] in "13mn2"
            if not form:
                self.refused_everywhere(address)
                self.refused(address, network, "witness version")
                self.assertFalse(legacy)
                continue
            seen[(network, form)] = seen.get((network, form), 0) + 1
            self.assertEqual(address_to_script(address, network), script, address)
            self.assertEqual(script_to_address(script, network), address)
            self.assertEqual(legacy, form in ("p2pkh", "p2sh"))
            for other in NETWORKS:
                if other == network:
                    continue
                # The legacy addresses of testnet3 and regtest are the same texts.
                if legacy and network != "mainnet" and other != "mainnet":
                    self.assertEqual(address_to_script(address, other), script)
                else:
                    self.refused(address, other, f"This is an address of Bitcoin .*{network}.*the network here is {other}")
            # All in capitals: Bech32 allows it and the script is the same; a Base58Check address is another text.
            if legacy:
                self.refused_everywhere(address.upper())
                self.refused_everywhere(address.lower())
            else:
                self.assertEqual(address_to_script(address.upper(), network), script)
        for network in NETWORKS:
            for form in FORMS:
                self.assertGreaterEqual(seen.get((network, form), 0), 2, (network, form))
        self.assertEqual(len(ADDRESSES["core_private_keys"]), 16)
        self.assertEqual(len(ADDRESSES["core_invalid"]), 70)
        for text in ADDRESSES["core_private_keys"] + ADDRESSES["core_invalid"]:
            self.refused_everywhere(text)

    def test_the_engines_bitcoin_library_writes_the_same_addresses(self):
        self.assertEqual(len(ENGINE["addresses"]), 30)
        seen = set()
        for entry in ENGINE["addresses"]:
            seen.add((entry["network"], script_form(entry["script"])))
            self.assertEqual(script_to_address(entry["script"], entry["network"]), entry["address"])
            self.assertEqual(address_to_script(entry["address"], entry["network"]), entry["script"])
        self.assertEqual(len(seen), 15)

    def test_the_form_of_a_script_is_the_engines(self):
        self.assertGreaterEqual(len(ENGINE["forms"]), 39)
        for entry in ENGINE["forms"]:
            if entry["form"] is None:
                with self.assertRaisesRegex(ValueError, "five standard forms", msg=entry["script"]):
                    script_form(entry["script"])
            else:
                self.assertEqual(script_form(entry["script"]), entry["form"])
        good = [entry["script"] for entry in ENGINE["forms"] if entry["form"]]
        self.assertEqual(sorted({entry["form"] for entry in ENGINE["forms"] if entry["form"]}), list(FORMS))
        for script in good:
            for bad in (script.upper(), script[:-1], script[:-2], script + "00", script + " ", " " + script, "0x" + script, script + "\n", "zz" + script[2:]):
                if bad != script:
                    with self.assertRaisesRegex(ValueError, "five standard forms", msg=repr(bad)):
                        script_form(bad)
        for bad in (None, 0, [], {}, [good[0]], bytes.fromhex(good[0])):
            with self.assertRaisesRegex(ValueError, "five standard forms"):
                script_form(bad)

    def test_an_unknown_network_and_what_is_not_an_address(self):
        script, address = "0014751e76e8199196d454941c45d1b3a323f1433bd6", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        for network in (None, "", "main", "bitcoin", "testnet", "testnet4", "signet", "Mainnet", "MAINNET", "mainnet ", "__class__", 0, ["mainnet"], ("mainnet",)):
            with self.assertRaisesRegex(ValueError, "Unknown Bitcoin network: name one of mainnet, testnet3, regtest"):
                address_to_script(address, network)
            with self.assertRaisesRegex(ValueError, "Unknown Bitcoin network"):
                script_to_address(script, network)
        for bad in (None, 5, "", [address], address.encode()):
            with self.assertRaisesRegex(ValueError, "An address is a text"):
                address_to_script(bad, "mainnet")
        for bad in (" " + address, address + " ", address + "\n", address + "\t", address.replace("q", "q ", 1), " " + address, address + " ", "﻿" + address):
            with self.assertRaisesRegex(ValueError, "no space"):
                address_to_script(bad, "mainnet")
        for bad in ("6a0100", script.upper().replace("0014", "0014", 1) + "", "0014" + "AB" * 20):
            if bad != script:
                with self.assertRaisesRegex(ValueError, "five standard forms"):
                    script_to_address(bad, "mainnet")

    def test_addresses_everyone_knows(self):
        self.assertEqual(address_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "mainnet"), "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac")
        zero = "76a914" + "00" * 20 + "88ac"
        self.assertEqual(script_to_address(zero, "mainnet"), "1111111111111111111114oLvT2")
        self.assertEqual(address_to_script("1111111111111111111114oLvT2", "mainnet"), zero)
        # One 1 more or fewer is another number of zero bytes, not the same address written otherwise.
        self.refused_everywhere("111111111111111111114oLvT2")
        self.refused_everywhere("11111111111111111111114oLvT2")
        self.assertEqual(address_to_script("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet3"), "0014751e76e8199196d454941c45d1b3a323f1433bd6")
        # The example of the README.
        self.assertEqual(address_to_script("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "regtest"), "0014751e76e8199196d454941c45d1b3a323f1433bd6")

    def test_the_package_gives_what_its_readme_names(self):
        import timemarket

        for name in timemarket.__all__:
            self.assertTrue(hasattr(timemarket, name), name)
        for name in ("sell_order", "buy_order", "cancel", "take", "sell", "proof", "expire", "release", "settle", "new_scripts", "action_payload", "action_fee"):
            self.assertTrue(callable(getattr(timemarket.actions, name)), name)
        self.assertIs(timemarket.address_to_script, address_to_script)

    @staticmethod
    def reference_base58check(version, hash_hex):
        """An independent Base58Check."""
        body = bytes([version]) + bytes.fromhex(hash_hex)
        whole = body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        number, text = int(whole.hex(), 16), ""
        while number:
            number, digit = divmod(number, 58)
            text = alphabet[digit] + text
        for byte in whole:
            if byte:
                break
            text = "1" + text
        return text

    def test_every_byte_of_a_base58check_checksum_is_compared_and_an_address_holds_25_bytes(self):
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        def text(whole):
            number, out = int.from_bytes(whole, "big"), ""
            while number:
                number, digit = divmod(number, 58)
                out = alphabet[digit] + out
            return "1" * (len(whole) - len(whole.lstrip(b"\x00"))) + out

        def checked(body):
            return body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]

        for version, network in ((0x00, "mainnet"), (0x05, "mainnet"), (0x6F, "testnet3"), (0xC4, "regtest")):
            body = bytes([version]) + hashlib.sha256(f"checksum {version}".encode()).digest()[:20]
            whole = checked(body)
            self.assertRegex(address_to_script(text(whole), network), "^(76a914|a914)")
            # One bit of each of the four checksum bytes, by itself.
            for at in range(21, 25):
                for bit in (1, 0x80):
                    wrong = bytearray(whole)
                    wrong[at] ^= bit
                    self.refused(text(bytes(wrong)), network, "The checksum of this address is wrong")
            # A byte fewer or a byte more, with a checksum of its own: another text altogether, and no address.
            self.refused_everywhere(text(whole[:24]))
            self.refused_everywhere(text(whole + b"\x00"))
            self.refused_everywhere(text(checked(body + b"\x07")))
            # One zero byte more in front is one 1 more: 26 bytes.
            if version == 0x00:
                self.refused("1" + text(whole), network, "A Base58Check address holds 25 bytes")

    def test_round_trips_of_every_form_on_every_network(self):
        version = {"mainnet": {"p2pkh": 0x00, "p2sh": 0x05}, "testnet3": {"p2pkh": 0x6F, "p2sh": 0xC4}, "regtest": {"p2pkh": 0x6F, "p2sh": 0xC4}}
        hrp = {"mainnet": "bc", "testnet3": "tb", "regtest": "bcrt"}
        take, everything = source("round trips"), set()
        for network in NETWORKS:
            for form in FORMS:
                size = HASH_BYTES[form]
                hashes = ["00" * size, "ff" * size, "00" * (size - 1) + "01", "0000" + "ab" * (size - 2)] + [take(size).hex() for _ in range(150)]
                for digest in hashes:
                    script = SCRIPT[form](digest)
                    address = script_to_address(script, network)
                    self.assertEqual(address_to_script(address, network), script, address)
                    if form in ("p2pkh", "p2sh"):
                        self.assertEqual(address, self.reference_base58check(version[network][form], digest))
                        everything.add(("testnet3" if network == "regtest" else network, address))
                    else:
                        self.assertTrue(address.startswith(hrp[network] + ("1p" if form == "p2tr" else "1q")))
                        self.assertEqual(len(address), len(hrp[network]) + 1 + (39 if form == "p2wpkh" else 59))
                        everything.add((network, address))
        self.assertEqual(len(everything), 3 * 5 * 154 - 2 * 4)

    def test_one_wrong_missing_added_or_swapped_character_is_never_another_address(self):
        bech32, base58 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        take, tried = source("mutations"), 0
        for network in NETWORKS:
            for form in FORMS:
                script = SCRIPT[form](take(HASH_BYTES[form]).hex())
                address = script_to_address(script, network)
                legacy = form in ("p2pkh", "p2sh")
                alphabet, others = (base58 if legacy else bech32), set()
                for at in range(len(address)):
                    for letter in alphabet:
                        others.add(address[:at] + letter + address[at + 1 :])
                    others.add(address[:at] + address[at + 1 :])
                    if at + 1 < len(address):
                        others.add(address[:at] + address[at + 1] + address[at] + address[at + 2 :])
                # A character added at every place: three of the alphabet (the SDK's test adds every one).
                for at in range(len(address) + 1):
                    for letter in (alphabet[0], alphabet[at % len(alphabet)], alphabet[-1]):
                        others.add(address[:at] + letter + address[at:])
                others.discard(address)
                for other in others:
                    tried += 1
                    with self.assertRaises(ValueError, msg=f"{other!r} on {network}"):
                        address_to_script(other, network)
                if not legacy:
                    at = max(index for index, letter in enumerate(address) if letter.isalpha())
                    self.refused(address[:at] + address[at].upper() + address[at + 1 :], network, "mixes")
                    self.assertEqual(address_to_script(address.upper(), network), script)
        self.assertGreater(tried, 30_000)


if __name__ == "__main__":
    unittest.main()
