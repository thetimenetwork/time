"""The envelope and its signature: the same bytes as the engine (``wire::sign``) and the SDK, for every vector.

Both Ed25519 libraries the package can use are tried when both can be imported; one that cannot be imported
is skipped, and the test of that says so.
"""
import importlib.util
import os
import stat
import sys
import tempfile
import unittest

from timemarket import keys, wire

from . import ENGINE

HAVE = {"cryptography": importlib.util.find_spec("cryptography") is not None, "pynacl": importlib.util.find_spec("nacl") is not None}


def fields(vector: dict) -> dict:
    return {"network_id": ENGINE["network_id"], "kind": vector["kind"], "sender": vector["from"], "nonce": vector["nonce"], "auth_epoch": vector["auth_epoch"], "payload": vector["payload"]}


class Envelope(unittest.TestCase):
    def test_at_least_one_ed25519_library_is_here(self):
        self.assertTrue(any(HAVE.values()), "install cryptography or PyNaCl to run these tests")

    def test_the_signed_bytes_are_the_engines_with_every_library(self):
        tried = 0
        for backend in (None, *wire.BACKENDS):
            if backend is not None and not HAVE[backend]:
                continue
            tried += 1
            for vector in ENGINE["actions"]:
                signed = wire.sign_action(**fields(vector), seed=vector["seed_hex"], backend=backend)
                self.assertEqual(signed.hex(), vector["signed_hex"], f"{vector['name']} with {backend}")
                self.assertEqual(wire.public_key(vector["seed_hex"], backend=backend), vector["public_key"])
                # The seed as bytes, and the numbers as int.
                again = wire.sign_action(network_id=ENGINE["network_id"], kind=vector["kind"], sender=int(vector["from"]), nonce=int(vector["nonce"]), auth_epoch=int(vector["auth_epoch"]), payload=vector["payload"], seed=bytes.fromhex(vector["seed_hex"]), backend=backend)
                self.assertEqual(again, signed)
        self.assertGreaterEqual(tried, 2)

    def test_an_old_release_of_a_library_is_refused(self):
        self.assertEqual(wire.MINIMUM_VERSIONS, {"cryptography": (42, 0, 0), "pynacl": (1, 5, 0)})
        for name, version in (("cryptography", "41.0.7"), ("cryptography", "3.4.8"), ("cryptography", None), ("cryptography", "unknown"), ("pynacl", "1.4.0"), ("pynacl", "0.3")):
            with self.assertRaisesRegex(RuntimeError, f"The installed {name} is older than"):
                wire._recent(name, version)
        for name, version in (("cryptography", "42.0.0"), ("cryptography", "46.0.5"), ("cryptography", "100.0"), ("pynacl", "1.5.0"), ("pynacl", "1.6.2"), ("pynacl", "2.0.0.dev1")):
            wire._recent(name, version)

    def test_only_one_function_of_the_package_signs(self):
        # The source of the package names an Ed25519 signing call in one module, and that module has one public
        # function that makes a signature.
        import pathlib
        import re as expressions

        package = pathlib.Path(wire.__file__).parent
        signing = expressions.compile(r"\.sign\(|SigningKey|Ed25519PrivateKey")
        self.assertEqual(sorted(path.name for path in package.glob("*.py") if signing.search(path.read_text(encoding="utf-8"))), ["wire.py"])
        public = [name for name, value in vars(wire).items() if callable(value) and not name.startswith("_") and getattr(value, "__module__", "") == wire.__name__]
        self.assertEqual(sorted(public), ["build_action", "canonical_json", "canonical_payload", "decode_action", "public_key", "sign_action", "transaction_hash", "verify_action"])
        source = (package / "wire.py").read_text(encoding="utf-8")
        self.assertEqual(source.count("sign(seed, body)"), 1)
        self.assertEqual(len(expressions.findall(r"\bsign\(", source)), 3, "the call in sign_action, and the two libraries' own")

    def test_a_library_that_is_not_installed_is_named(self):
        for backend in wire.BACKENDS:
            if not HAVE[backend]:
                with self.assertRaisesRegex(RuntimeError, "cryptography.*PyNaCl"):
                    wire.public_key("00" * 32, backend=backend)
        with self.assertRaisesRegex(ValueError, "cryptography, pynacl"):
            wire.public_key("00" * 32, backend="ed25519")

    def test_the_envelope_and_what_is_read_back(self):
        for vector in ENGINE["actions"]:
            raw = bytes.fromhex(vector["signed_hex"])
            body = wire.build_action(**fields(vector), public_key=vector["public_key"])
            self.assertEqual(body, raw[:-64], vector["name"])
            self.assertEqual(len(body), wire.HEADER_BYTES + len(vector["payload_json"]))
            self.assertEqual(wire.canonical_payload(vector["kind"], vector["payload"]).decode(), vector["payload_json"])
            self.assertEqual(wire.canonical_json(vector["payload"]).decode(), vector["payload_json"])
            read = wire.verify_action(raw)
            self.assertEqual(read, {"network_id": ENGINE["network_id"], "kind": vector["kind"], "sender": vector["from"], "nonce": vector["nonce"], "auth_epoch": vector["auth_epoch"], "public_key": vector["public_key"], "payload": vector["payload"], "signature": vector["signed_hex"][-128:]})
            self.assertEqual(wire.decode_action(raw), read)
            self.assertRegex(wire.transaction_hash(raw), "^[0-9A-F]{64}$")
            # One bit of any part changed: the signature is not the key's, or the bytes are no action.
            for at in (0, 19, 19 + 32, 19 + 33, 19 + 33 + 8, 19 + 33 + 16, 19 + 33 + 24, wire.HEADER_BYTES - 1, wire.HEADER_BYTES + 3, len(raw) - 70, len(raw) - 1):
                changed = bytearray(raw)
                changed[at] ^= 1
                with self.assertRaises(ValueError, msg=f"{vector['name']} byte {at}"):
                    wire.verify_action(bytes(changed))
            for bad in (raw[:-1], raw + b"\x00", raw[1:], b"", raw[: wire.HEADER_BYTES + 60], None, vector["signed_hex"]):
                with self.assertRaises(ValueError):
                    wire.decode_action(bad)

    def test_a_payload_that_is_not_in_its_one_form_is_not_read_back(self):
        vector = next(entry for entry in ENGINE["actions"] if entry["name"] == "take")
        raw = bytes.fromhex(vector["signed_hex"])
        head = raw[: wire.HEADER_BYTES - 4]

        def around(text: str) -> bytes:
            body = text.encode()
            return head + len(body).to_bytes(4, "big") + body + bytes(64)

        self.assertEqual(wire.decode_action(around(vector["payload_json"]))["payload"], vector["payload"])
        for text in ('{"to":"6","sats":"5000","order":"1","amount_micros":"20000000"}', vector["payload_json"].replace('"5000"', "5000"), vector["payload_json"].replace("{", "{ "), vector["payload_json"].replace("}", ',"more":"1"}'), vector["payload_json"] + " ", "{}", "[]", "not json", '{"amount_micros":"20000000","amount_micros":"20000000","order":"1","sats":"5000","to":"6"}'):
            with self.assertRaises(ValueError, msg=text):
                wire.decode_action(around(text))
        # Another kind than the market's.
        other = bytearray(around(vector["payload_json"]))
        other[19 + 32] = 3
        with self.assertRaisesRegex(ValueError, "kind 3: this package reads the kinds of the market"):
            wire.decode_action(bytes(other))

    def test_what_an_action_is_built_from(self):
        vector = next(entry for entry in ENGINE["actions"] if entry["name"] == "cancel")
        good = {**fields(vector), "seed": vector["seed_hex"]}
        self.assertEqual(wire.sign_action(**good).hex(), vector["signed_hex"])
        for name, bad, why in (
            ("network_id", ENGINE["network_id"].upper(), "network_id is 64 lowercase hexadecimal characters"),
            ("network_id", ENGINE["network_id"][2:], "network_id is 64 lowercase"),
            ("network_id", ENGINE["network_id"] + "\n", "network_id is 64 lowercase"),
            ("network_id", bytes.fromhex(ENGINE["network_id"]), "network_id is 64 lowercase"),
            ("kind", 59, "The kinds of the market are 50 to 58"),
            ("kind", 3, "The kinds of the market are 50 to 58"),
            ("kind", "51", "The kinds of the market are 50 to 58"),
            ("sender", -1, "sender is a whole number"),
            ("sender", "05", "sender is a whole number"),
            ("sender", 2**64, "sender is a whole number"),
            ("sender", 5.0, "sender is a whole number"),
            ("sender", True, "sender is a whole number"),
            ("nonce", "1\n", "nonce is a whole number"),
            ("nonce", None, "nonce is a whole number"),
            ("auth_epoch", "", "auth_epoch is a whole number"),
            ("payload", {"order": "0"}, "order is from 1"),
            ("payload", {"fill": "1"}, "has exactly the fields order"),
            ("seed", "AB" * 32, "A signing key is its seed"),
            ("seed", vector["seed_hex"][2:], "A signing key is its seed"),
            ("seed", vector["seed_hex"] + "\n", "A signing key is its seed"),
            ("seed", bytes(31), "A signing key is its seed"),
            ("seed", None, "A signing key is its seed"),
        ):
            with self.assertRaisesRegex(ValueError, why, msg=f"{name}={bad!r}"):
                wire.sign_action(**{**good, name: bad})
        with self.assertRaises(TypeError):
            wire.sign_action(**{**good, "from": "5"})
        # Another key signs other bytes under another public key.
        other = wire.sign_action(**{**good, "seed": "07" * 32})
        self.assertNotEqual(other, bytes.fromhex(vector["signed_hex"]))
        self.assertEqual(wire.verify_action(other)["public_key"], wire.public_key("07" * 32))

    def test_canonical_json(self):
        self.assertEqual(wire.canonical_json({"b": "1", "a": {"d": [3, True, None, "x"], "c": "é\u0001\"\\"}}), '{"a":{"c":"é\\u0001\\"\\\\","d":[3,true,null,"x"]},"b":"1"}'.encode())
        self.assertEqual(wire.canonical_json({}), b"{}")
        for bad in ({"a": 1.5}, {"a": -1}, {"a": 2**64}, {1: "a"}, {"a": {1, 2}}, {"a": b"x"}, {"a": float("nan")}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                wire.canonical_json(bad)
        deep = "x"
        for _ in range(40):
            deep = [deep]
        with self.assertRaisesRegex(ValueError, "nested at most 32 deep"):
            wire.canonical_json(deep)


class Keys(unittest.TestCase):
    SEED = "0b" * 32

    def test_a_key_does_not_show_itself(self):
        seed = keys.Seed(bytes.fromhex(self.SEED))
        for text in (repr(seed), str(seed), f"{seed}", f"{seed!r:>40}", "%s" % seed, "%r" % (seed,), repr([seed]), repr({"seed": seed})):
            self.assertIn("<signing key: not shown>", text)
            self.assertNotIn("0b0b", text)
            self.assertNotIn(repr(bytes.fromhex(self.SEED))[2:10], text)
        self.assertEqual(seed.reveal(), bytes.fromhex(self.SEED))
        import copy
        import pickle

        for write in (pickle.dumps, copy.copy, copy.deepcopy):
            with self.assertRaisesRegex(TypeError, "A signing key is not written out"):
                write(seed)
        with self.assertRaises(AttributeError):
            seed.other = 1
        with self.assertRaises(AttributeError):
            seed._value = bytes(32)
        self.assertFalse(hasattr(seed, "__dict__"))
        for bad in (self.SEED, bytes(31), bytes(33), None, 5):
            with self.assertRaisesRegex(ValueError, "32 bytes"):
                keys.Seed(bad)
        # It signs as its bytes do, and an error about another argument does not show it.
        vector = next(entry for entry in ENGINE["actions"] if entry["name"] == "cancel")
        held = keys.Seed(bytes.fromhex(vector["seed_hex"]))
        self.assertEqual(wire.sign_action(**fields(vector), seed=held).hex(), vector["signed_hex"])
        self.assertEqual(wire.public_key(held), vector["public_key"])
        for change in ({"payload": {"order": "0"}}, {"nonce": -1}, {"network_id": "x"}, {"kind": 3}):
            with self.assertRaises(ValueError) as caught:
                wire.sign_action(**{**fields(vector), **change}, seed=vector["seed_hex"])
            self.assertNotIn(vector["seed_hex"], str(caught.exception))
            self.assertNotIn(vector["seed_hex"], repr(caught.exception))
        # A key that is not one: the message says what a key is, and nothing of what was given.
        for bad in ("AB" * 32, vector["seed_hex"][:-2] + "zz", vector["seed_hex"] + "00", bytes(31)):
            with self.assertRaises(ValueError) as caught:
                wire.sign_action(**fields(vector), seed=bad)
            self.assertNotIn(str(bad)[:16], str(caught.exception))

    def test_a_key_from_the_key_store_of_the_system(self):
        from unittest import mock

        class Answer:
            def __init__(self, returncode, stdout):
                self.returncode, self.stdout, self.stderr = returncode, stdout, "said on the side: " + stdout

        for platform, tool, asked in (
            ("darwin", "/usr/bin/security", ["/usr/bin/security", "find-generic-password", "-s", "time-bot", "-a", "account-12", "-w"]),
            ("linux", "/usr/bin/secret-tool", ["/usr/bin/secret-tool", "lookup", "service", "time-bot", "account", "account-12"]),
        ):
            with mock.patch.object(keys.sys, "platform", platform), mock.patch.object(keys.shutil, "which", return_value=tool), mock.patch.object(keys.os.path, "isfile", return_value=True):
                with mock.patch.object(keys.subprocess, "run", return_value=Answer(0, self.SEED + "\n")) as run:
                    self.assertEqual(keys.seed_from_key_store("time-bot", "account-12").reveal(), bytes.fromhex(self.SEED))
                    self.assertEqual(run.call_args.args[0], asked)
                    self.assertNotIn("shell", {name for name, value in run.call_args.kwargs.items() if value})
                    self.assertGreater(run.call_args.kwargs["timeout"], 0)
                for answer, error, why in ((Answer(1, ""), RuntimeError, "was not found, or the key store is locked"), (Answer(0, ""), RuntimeError, "was not found"), (Answer(0, "not a key " + self.SEED.upper()), ValueError, "does not hold a signing key"), (Answer(44, self.SEED), RuntimeError, "was not found")):
                    with mock.patch.object(keys.subprocess, "run", return_value=answer):
                        with self.assertRaisesRegex(error, why) as caught:
                            keys.seed_from_key_store("time-bot", "account-12")
                        # What the key store answered is never repeated.
                        self.assertNotIn(self.SEED, str(caught.exception).lower())
                        self.assertNotIn("said on the side", str(caught.exception))
                with mock.patch.object(keys.subprocess, "run", side_effect=keys.subprocess.TimeoutExpired("x", 30)):
                    with self.assertRaisesRegex(RuntimeError, "the key store did not answer"):
                        keys.seed_from_key_store("time-bot", "account-12")
        with mock.patch.object(keys.sys, "platform", "linux"), mock.patch.object(keys.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "install secret-tool"):
                keys.seed_from_key_store("time-bot", "account-12")
        with mock.patch.object(keys.sys, "platform", "win32"):
            with mock.patch.object(keys, "_windows_credential", return_value=("account-12", self.SEED)) as read:
                self.assertEqual(keys.seed_from_key_store("time-bot", "account-12").reveal(), bytes.fromhex(self.SEED))
                self.assertEqual(read.call_args.args, ("time-bot",))
                with self.assertRaisesRegex(RuntimeError, "for another user name"):
                    keys.seed_from_key_store("time-bot", "someone-else")
            with mock.patch.object(keys, "_windows_credential", side_effect=LookupError("Windows error 1168")):
                with self.assertRaisesRegex(RuntimeError, "was not found in the Windows Credential Manager"):
                    keys.seed_from_key_store("time-bot", "account-12")
        # A name that a tool could take for an option, or that is no name, is refused before anything is asked.
        for service, account in (("-s", "a"), ("time-bot", "--help"), ("", "a"), ("time bot", "a"), ("time-bot", "a\nb"), (None, "a"), ("time-bot", 5), ("x" * 200, "a")):
            with self.assertRaisesRegex(ValueError, "is a name of letters, digits"):
                keys.seed_from_key_store(service, account)

    @unittest.skipUnless(sys.platform == "win32", "the Windows Credential Manager")
    def test_the_windows_credential_manager_is_read_and_an_entry_that_is_not_there_is_not_found(self):
        with self.assertRaisesRegex(RuntimeError, "was not found in the Windows Credential Manager"):
            keys.seed_from_key_store("timemarket-test-entry-that-does-not-exist", "nobody")

    def test_a_key_from_the_environment(self):
        name = "TIMEMARKET_TEST_SEED"
        os.environ.pop(name, None)
        with self.assertRaisesRegex(RuntimeError, f"{name} is not set"):
            keys.seed_from_env(name)
        try:
            os.environ[name] = self.SEED + "\n"
            self.assertEqual(keys.seed_from_env(name).reveal(), bytes.fromhex(self.SEED))
            with self.assertRaises(TypeError):
                keys.seed_from_env()  # no variable is looked for by itself
            for bad in ("", "A B", "1X", "X=1", None, 5):
                with self.assertRaisesRegex(ValueError, "The name of an environment variable"):
                    keys.seed_from_env(bad)
            for bad in (self.SEED.upper(), self.SEED[2:], self.SEED + "00", "", "0x" + self.SEED[2:]):
                os.environ[name] = bad
                with self.assertRaises(ValueError) as caught:
                    keys.seed_from_env(name)
                # The value is never repeated in the message.
                self.assertNotIn(bad or "never", str(caught.exception))
        finally:
            os.environ.pop(name, None)

    def test_a_key_from_a_file_only_its_owner_can_read(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "seed")
            with open(path, "w", encoding="ascii") as file:
                file.write(self.SEED + "\n")
            os.chmod(path, 0o600)
            self.assertEqual(keys.seed_from_file(path).reveal(), bytes.fromhex(self.SEED))
            with self.assertRaises(TypeError):
                keys.seed_from_file()  # no file is looked for by itself
            if os.name == "posix":
                for mode in (0o640, 0o604, 0o660, 0o644, 0o620):
                    os.chmod(path, mode)
                    with self.assertRaisesRegex(PermissionError, "chmod 600"):
                        keys.seed_from_file(path)
                os.chmod(path, 0o400)
                self.assertEqual(keys.seed_from_file(path).reveal(), bytes.fromhex(self.SEED))
                os.chmod(path, 0o600)
            for bad in (self.SEED.upper(), self.SEED[2:], self.SEED + "\n" + self.SEED, "", "x" * 5000):
                with open(path, "w", encoding="ascii") as file:
                    file.write(bad)
                os.chmod(path, 0o600)
                with self.assertRaisesRegex(ValueError, "does not hold a signing key") as caught:
                    keys.seed_from_file(path)
                self.assertNotIn(self.SEED[2:], str(caught.exception))
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                keys.seed_from_file(folder)
            with self.assertRaises(FileNotFoundError):
                keys.seed_from_file(os.path.join(folder, "nothing"))
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)


if __name__ == "__main__":
    unittest.main()
