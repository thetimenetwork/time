"""Transactions without witness data, Merkle proofs, and the payload of a proof from what a Bitcoin node gives.

Held to the engine's Bitcoin library (spec/market-vectors.json): its serializations, its transaction ids, what
its Merkle proofs prove, and the proofs the engine accepted.
"""
import hashlib
import unittest

from timemarket.bitcoin import merkle_proof_matches, proof_payload, strip_witness, transaction_id, transaction_outputs

from . import ENGINE


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def named(name: str) -> dict:
    return next(entry for entry in ENGINE["transactions"] if entry["name"] == name)


INPUT = "01" + "11" * 36 + "00ffffffff"
PROOFS = [entry for entry in ENGINE["actions"] if entry["kind"] == 54]
SCRIPT = next(entry for entry in ENGINE["actions"] if entry["name"] == "sell_order")["payload"]["scripts"][0]


def given(vector: dict) -> dict:
    payload, node = vector["payload"], vector["bitcoin_node"]
    return {"fill": payload["fill"], "script": SCRIPT, "block_hash": payload["block_hash"], "transaction": node["transaction"], "coinbase": node["coinbase"], "merkle_proof": payload["merkle_proof"]}


class Transactions(unittest.TestCase):
    def test_without_witness_data_is_what_the_engines_library_writes(self):
        names = [entry["name"] for entry in ENGINE["transactions"]]
        for name in ("p2wpkh_spend", "p2tr_key_spend", "p2tr_script_spend", "legacy", "some_inputs_without_witness", "an_empty_witness_item", "253_outputs", "253_inputs_and_a_long_script"):
            self.assertIn(name, names)
        for entry in ENGINE["transactions"]:
            whole, bare, name = entry["transaction"], entry["without_witness"], entry["name"]
            self.assertEqual(strip_witness(whole), bare, name)
            self.assertEqual(strip_witness(bare), bare, name)
            self.assertEqual(transaction_id(whole), entry["txid"], name)
            self.assertEqual(transaction_id(bare), entry["txid"], name)
            self.assertEqual(sha256d(bytes.fromhex(bare))[::-1].hex(), entry["txid"])
            self.assertEqual(name == "legacy", whole == bare, name)
            if whole != bare:
                self.assertEqual(whole[8:12], "0001")

    def test_what_is_not_exactly_one_transaction_is_refused(self):
        spend, legacy = named("p2wpkh_spend"), named("legacy")
        for entry in (spend, legacy, named("some_inputs_without_witness"), named("p2tr_script_spend")):
            for whole in {entry["transaction"], entry["without_witness"]}:
                for length in range(0, len(whole), 2):
                    with self.assertRaisesRegex(ValueError, "ends too early|not a Bitcoin transaction|at least one", msg=f"{length // 2} bytes"):
                        strip_witness(whole[:length])
                with self.assertRaisesRegex(ValueError, "bytes follow its end"):
                    strip_witness(whole + "00")
                with self.assertRaisesRegex(ValueError, "bytes follow its end|ends too early"):
                    strip_witness(whole + whole)
                with self.assertRaisesRegex(ValueError, "lowercase hexadecimal"):
                    strip_witness(whole[:-2] + "AB")
                with self.assertRaises(ValueError):
                    strip_witness(whole[1:])
        with self.assertRaisesRegex(ValueError, "a marker this code does not know"):
            strip_witness(spend["transaction"][:10] + "02" + spend["transaction"][12:])
        bare = legacy["without_witness"]
        with self.assertRaisesRegex(ValueError, "marked as having witness data and has none"):
            strip_witness(bare[:8] + "0001" + bare[8:-8] + "0000" + bare[-8:])
        with self.assertRaisesRegex(ValueError, "no input, or a marker"):
            strip_witness("02000000" + "00" + "00" + "00000000")
        with self.assertRaisesRegex(ValueError, "at least one input"):
            strip_witness("02000000" + "0001" + "00" + "00" + "00000000")
        with self.assertRaisesRegex(ValueError, "at least one output"):
            strip_witness("02000000" + INPUT + "00" + "00000000")
        self.assertEqual(bare[8:10], "02")
        for longer, why in (("fd0200", "longer form than needed"), ("fe02000000", "longer form than needed"), ("ff0200000000000000", "a size nothing has")):
            with self.assertRaisesRegex(ValueError, why):
                strip_witness(bare[:8] + longer + bare[10:])
        with self.assertRaisesRegex(ValueError, "ends too early"):
            strip_witness("02000000feffffff7f" + "00" * 64)
        for bad in (None, 5, "", "zz", "0", [spend["transaction"]], bytes.fromhex(spend["transaction"])):
            with self.assertRaisesRegex(ValueError, "lowercase hexadecimal|ends too early"):
                strip_witness(bad)
        with self.assertRaisesRegex(ValueError, "bytes follow its end"):
            transaction_id(spend["transaction"] + "00")

    def test_the_outputs_of_a_transaction(self):
        spend = named("p2wpkh_spend")
        outputs = [{"sats": 10000, "script": "0014" + "01" * 20}, {"sats": 89000, "script": "5120" + "44" * 32}]
        self.assertEqual(transaction_outputs(spend["transaction"]), outputs)
        self.assertEqual(transaction_outputs(spend["without_witness"]), outputs)
        self.assertEqual(len(transaction_outputs(named("253_outputs")["transaction"])), 253)

        def paying(value_hex):
            return "01000000" + INPUT + "01" + value_hex + "16" + "0014" + "07" * 20 + "00000000"

        self.assertEqual(transaction_outputs(paying("0040075af0750700")), [{"sats": 2_100_000_000_000_000, "script": "0014" + "07" * 20}])
        self.assertEqual(transaction_outputs(paying("ffffffffffffffff"))[0]["sats"], 2**64 - 1)


class MerkleProofs(unittest.TestCase):
    def test_a_proof_proves_what_the_engines_library_reads_from_it(self):
        self.assertGreaterEqual(len(ENGINE["merkle_proofs"]), 13)
        sizes = set()
        for entry in ENGINE["merkle_proofs"]:
            block_hash, proof, matched = entry["block_hash"], entry["merkle_proof"], entry["matched"]
            sizes.add(entry["transactions"])
            self.assertEqual(merkle_proof_matches(proof, block_hash), matched, entry["transactions"])
            data = bytes.fromhex(proof)
            flags_from = 85 + 32 * data[84] + 1
            self.assertEqual(data[flags_from - 1], len(data) - flags_from)
            for at in range(80, len(data)):
                changed = bytearray(data)
                changed[at] ^= 1 << (at % 8)
                try:
                    answer = merkle_proof_matches(changed.hex(), block_hash)
                except ValueError as error:
                    self.assertIn("merkle_proof", str(error))
                    continue
                # The number of transactions is not in the block's Merkle root, and the flags say which leaves are meant.
                self.assertTrue(at < 84 or at >= flags_from, f"byte {at} of {len(data)}")
                if at < 84:
                    self.assertEqual(answer, matched)
                else:
                    self.assertTrue(all(match["hash"] in proof for match in answer))
            for length in range(0, len(proof), 2):
                with self.assertRaisesRegex(ValueError, "merkle_proof"):
                    merkle_proof_matches(proof[:length], block_hash)
            with self.assertRaisesRegex(ValueError, "merkle_proof"):
                merkle_proof_matches(proof + "00", block_hash)
            other = ENGINE["merkle_proofs"][0]["block_hash"]
            if other == block_hash:
                other = ENGINE["merkle_proofs"][1]["block_hash"]
            with self.assertRaisesRegex(ValueError, "for another block"):
                merkle_proof_matches(proof, other)
        for size in (1, 2, 3, 7, 12, 33, 100):
            self.assertIn(size, sizes)
        first = ENGINE["merkle_proofs"][0]
        for bad in (None, 5, "", first["merkle_proof"].upper(), first["merkle_proof"] + "0"):
            with self.assertRaisesRegex(ValueError, "merkle_proof is lowercase hexadecimal|merkle_proof is 86 to 4,096 bytes"):
                merkle_proof_matches(bad, first["block_hash"])
        for bad in (None, "", first["block_hash"][2:], first["block_hash"] + "00", first["block_hash"] + "\n", "AB" + first["block_hash"][2:]):
            with self.assertRaisesRegex(ValueError, "block_hash is 64 lowercase hexadecimal characters"):
                merkle_proof_matches(first["merkle_proof"], bad)


class ProofPayload(unittest.TestCase):
    def refused(self, why, **changes):
        with self.assertRaisesRegex(ValueError, why, msg=sorted(changes)):
            proof_payload(**{**given(PROOFS[1]), **changes})

    def test_the_payload_is_the_one_the_engine_accepted(self):
        self.assertEqual([entry["name"] for entry in PROOFS], ["proof_of_a_part", "proof"])
        for vector in PROOFS:
            payload, node, arguments = vector["payload"], vector["bitcoin_node"], given(vector)
            self.assertNotEqual(node["transaction"], payload["transaction"])
            self.assertNotEqual(node["coinbase"], payload["coinbase"])
            made = proof_payload(**arguments)
            self.assertEqual(made, payload, vector["name"])
            self.assertEqual(list(made), ["block_hash", "coinbase", "fill", "merkle_proof", "transaction", "vout"])
            for vout in (payload["vout"], int(payload["vout"]), None):
                self.assertEqual(proof_payload(**arguments, vout=vout), payload)
            self.assertEqual(proof_payload(**{**arguments, "fill": int(payload["fill"])}), payload)
            self.assertEqual(proof_payload(**{**arguments, "transaction": payload["transaction"], "coinbase": payload["coinbase"]}), payload)
            self.assertEqual(transaction_outputs(node["transaction"])[int(payload["vout"])]["script"], SCRIPT)
        self.assertEqual(PROOFS[1]["payload"]["vout"], "1")

    def test_a_proof_that_would_not_pay_for_the_fill_is_refused(self):
        part, whole = given(PROOFS[0]), given(PROOFS[1])
        other = "5120" + "44" * 32
        self.refused("No output of this transaction pays the receiving script of the fill", script="0014" + "09" * 20)
        self.refused("Output 0 of this transaction does not pay the receiving script of the fill: output 1 does", vout=0)
        self.refused("Output 1 of this transaction does not pay the receiving script of the fill: output 0 does", script=other, vout=1)
        self.assertEqual(proof_payload(**{**whole, "script": other})["vout"], "0")
        self.refused("does not pay the receiving script of the fill, and no other output does", script="0014" + "09" * 20, vout=1)
        self.refused("This transaction has 82 outputs: it has no output 82", vout=82)
        for vout in (-1, 1.5, "01", "1 ", "1\n", "one", 2**32, True, [1], {}):
            self.refused("vout is the place of an output", vout=vout)
        for bad in ("6a0100", "0014" + "AB" * 20, SCRIPT + "00", SCRIPT + "\n", None, 5):
            self.refused("five standard forms", script=bad)
        # The two transactions in each other's place, the same one twice, and those of another block.
        self.refused("coinbase is the first transaction of the block, which spends nothing", transaction=whole["coinbase"], coinbase=whole["transaction"])
        self.refused("coinbase is the first transaction of the block", coinbase=whole["transaction"])
        self.refused("The payment is a coinbase transaction", transaction=whole["coinbase"], script=transaction_outputs(whole["coinbase"])[0]["script"])
        self.refused("does not hold the coinbase transaction", coinbase=part["coinbase"])
        self.refused("does not hold the payment", transaction=part["transaction"])
        self.refused("merkle_proof is for another block than block_hash", merkle_proof=part["merkle_proof"])
        self.refused("merkle_proof is for another block than block_hash", block_hash=part["block_hash"])
        self.refused("merkle_proof is for another block than block_hash", block_hash=bytes.fromhex(whole["block_hash"])[::-1].hex())
        for bad in ("AB" + whole["block_hash"][2:], whole["block_hash"] + "\n", whole["block_hash"][2:], None):
            self.refused("block_hash is 64 lowercase hexadecimal characters", block_hash=bad)
        proof = whole["merkle_proof"]
        self.assertEqual(len(proof), 2 * (80 + 4 + 1 + 64 + 1 + 1))
        self.assertEqual(proof[-2:], "07")
        self.refused("does not end where its own sizes say", merkle_proof=proof + "00")
        self.refused("does not end where its own sizes say", merkle_proof=proof[:-2])
        self.refused("a number of hashes that no proof of two transactions has", merkle_proof=proof[:-4])
        self.refused("86 to 4,096 bytes", merkle_proof=proof[:170])
        self.refused("86 to 4,096 bytes", merkle_proof=proof[:172] + "00" * 4096)
        self.refused("merkle_proof is lowercase hexadecimal", merkle_proof=proof.upper())
        for count in ("41", "00"):
            self.refused("a number of hashes that no proof of two transactions has", merkle_proof=proof[:168] + count + proof[170:])
        # A proof of the payment alone, as gettxoutproof gives it for one id (05), and of the coinbase alone (03).
        self.refused("merkle_proof does not hold the coinbase transaction: ask gettxoutproof for both ids", merkle_proof=proof[:-2] + "05")
        self.refused("merkle_proof does not hold the payment: ask gettxoutproof for both ids", merkle_proof=proof[:-2] + "03")
        self.refused("does not hold the coinbase transaction", merkle_proof=proof[:-2] + "01")
        self.refused("holds hashes or flag bytes that nothing uses", merkle_proof=proof[:-2] + "00")
        self.refused("holds hashes or flag bytes that nothing uses", merkle_proof=proof[:-4] + "020700")
        self.assertEqual(proof_payload(**{**whole, "merkle_proof": proof[:-2] + "f7"})["merkle_proof"], proof[:-2] + "f7")
        self.refused("does not lead to the Merkle root of its block", merkle_proof=proof[:170] + format(int(proof[170], 16) ^ 1, "x") + proof[171:])
        header = bytearray.fromhex(proof[:160])
        header[40] ^= 1
        self.refused("does not lead to the Merkle root of its block", merkle_proof=header.hex() + proof[160:], block_hash=sha256d(bytes(header))[::-1].hex())
        for total in ("03000000", "01000000", "00000000", "1b410000", "ffffffff"):
            self.refused("Merkle", merkle_proof=proof[:160] + total + proof[168:])
        self.refused("does not lead to the Merkle root", merkle_proof=proof[:170] + proof[234:298] + proof[170:234] + proof[298:])
        for fill in ("0", "01", "", "1\n", -1, 1.5, "18446744073709551616", [1], True):
            self.refused("fill is the id of a fill", fill=fill)
        with self.assertRaises(TypeError):
            proof_payload(**whole, blockHash=whole["block_hash"])
        with self.assertRaises(TypeError):
            proof_payload(**{name: value for name, value in whole.items() if name != "coinbase"})
        with self.assertRaises(TypeError):
            proof_payload(whole)
        # Two outputs to the fill's script: each is proven by itself. An output of nothing.

        def pay(sats):
            return format(sats, "02x") + "00000000000000" + "16" + SCRIPT

        twice = "01000000" + INPUT + "03" + pay(5) + pay(0) + pay(7) + "00000000"
        self.assertEqual([output["sats"] for output in transaction_outputs(twice)], [5, 0, 7])
        self.refused("Outputs 0, 1, 2 of this transaction pay the receiving script of the fill: name one with vout", transaction=twice)
        self.refused("The output that pays the fill has no value", transaction=twice, vout=1)
        self.refused("does not hold the payment", transaction=twice, vout=2)
        # What the engine's sizes refuse.
        self.refused("too short to be proven", transaction="01000000" + INPUT + "01" + "0500000000000000" + "04" + "00" * 4 + "00000000")
        huge = "01000000" + INPUT + "01" + "0500000000000000" + "fe00c00300" + "51" * 0x3C000 + "00000000"
        self.assertEqual(strip_witness(huge), huge)
        self.refused("The payment is larger than a proof may carry \\(100,000 bytes without its witness data\\)", transaction=huge)
        self.refused("The coinbase transaction is larger than a proof may carry \\(150,000 bytes", coinbase=huge)

        # A payment of 100,000 bytes and a coinbase of 60 are within the sizes: what is refused is something else.
        def sized(total):
            return "01000000" + INPUT + "01" + "0500000000000000" + "fe" + (total - 64).to_bytes(4, "little").hex() + "51" * (total - 64) + "00000000"

        self.assertEqual(len(sized(100000)), 200000)
        self.refused("No output of this transaction pays the receiving script of the fill", transaction=sized(100000))
        self.refused("The payment is larger than a proof may carry", transaction=sized(100001))
        shortest = "01000000" + "01" + "00" * 32 + "ffffffff" + "00" + "ffffffff" + "01" + "00" * 8 + "00" + "00000000"
        self.assertEqual(len(shortest), 120)
        self.refused("merkle_proof does not hold the coinbase transaction", coinbase=shortest)
        self.refused("sum to more bitcoin than exists", transaction="01000000" + INPUT + "02" + "0040075af0750700" + "16" + SCRIPT + "0100000000000000" + "16" + SCRIPT + "00000000", vout=1)
        self.refused("spends one output twice", transaction="01000000" + "02" + ("11" * 36 + "00ffffffff") * 2 + "01" + pay(5) + "00000000")


if __name__ == "__main__":
    unittest.main()
