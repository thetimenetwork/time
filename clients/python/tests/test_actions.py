"""The price arithmetic and the payloads of the market's actions, held to the engine's vectors and to every refusal."""
import json
import unittest

from timemarket import actions, amounts

from . import ENGINE

PRICE = 250_000_000


def W(byte: str) -> str:
    return "0014" + byte * 20


def TR(byte: str) -> str:
    return "5120" + byte * 32


def action(name: str) -> dict:
    return next(entry for entry in ENGINE["actions"] if entry["name"] == name)


SELL = {"amount_micros": "100000000", "confirmations": "3", "deposit_ppm": "50000", "min_deposit_micros": "250000", "min_sats": "1000", "pay_blocks": "6", "price": "250000000", "scripts": [W("01"), TR("44")], "side": "sell"}
BUY = {"amount_micros": "50000000", "confirmations": "3", "deposit_ppm": "100000", "forms": ["p2tr", "p2wpkh"], "min_sats": "1000", "pay_blocks": "6", "price": "250000000", "side": "buy"}
TAKE = {"amount_micros": "40000000", "order": "1", "sats": "10000", "to": "8"}
SALE = {"amount_micros": "20000000", "confirmations": "2", "order": "2", "sats": "5000", "script": W("07")}
PROOF = dict(action("proof_of_a_part")["payload"])


def but(base: dict, **changes) -> dict:
    """``base`` with some fields changed; a value of ``...`` removes the field."""
    out = {**base, **changes}
    return {key: value for key, value in out.items() if value is not ...}


class Amounts(unittest.TestCase):
    def test_sats_is_the_engines(self):
        self.assertGreaterEqual(len(ENGINE["sats"]), 20)
        priced = refused = 0
        for entry in ENGINE["sats"]:
            amount, price = int(entry["amount_micros"]), int(entry["price"])
            if entry["sats"] is None:
                refused += 1
                with self.assertRaisesRegex(ValueError, "A price is from 1 to 10\\^15|more satoshis than exist"):
                    amounts.sats(amount, price)
            else:
                priced += 1
                self.assertEqual(amounts.sats(amount, price), int(entry["sats"]), entry)
                # Paying the price always buys the amount.
                self.assertGreaterEqual(amounts.bought(int(entry["sats"]), price), amount)
        self.assertGreaterEqual(priced, 12)
        self.assertGreaterEqual(refused, 5)

    def test_bought_is_the_engines(self):
        self.assertGreaterEqual(len(ENGINE["bought"]), 15)
        for entry in ENGINE["bought"]:
            self.assertEqual(amounts.bought(int(entry["sats"]), int(entry["price"])), int(entry["bought_micros"]), entry)
        self.assertIn(str(2**64 - 1), [entry["bought_micros"] for entry in ENGINE["bought"]], "a result that stops at the largest number")

    def test_a_payment_of_a_part_buys_a_part_and_the_fill_goes_on(self):
        # The numbers of the engine's test of the same name (v5/tests/market.rs): 80 seconds for 20,000
        # satoshis with a deposit of 8 seconds; 1,000 satoshis arrive, then 5,000, then the rest and more.
        second = 1_000_000
        fill = {"amount_micros": 80 * second, "sats": 20_000, "deposit_micros": 8 * second}
        self.assertEqual(amounts.part_seconds(80 * second, 20_000, 1_000), 4 * second)
        after = amounts.fill_after_payment(**fill, paid=1_000)
        self.assertEqual(after, {"seconds": 4 * second, "deposit_back": 400_000, "amount_micros": 76 * second, "sats": 19_000, "deposit_micros": 7_600_000, "ends": False})
        self.assertEqual(amounts.part_seconds(76 * second, 19_000, 5_000), 20 * second)
        after = amounts.fill_after_payment(76 * second, 19_000, 7_600_000, 5_000)
        self.assertEqual(after, {"seconds": 20 * second, "deposit_back": 2 * second, "amount_micros": 56 * second, "sats": 14_000, "deposit_micros": 5_600_000, "ends": False})
        # What is still to pay is what was agreed less what was paid, to the satoshi. It arrives, with a little more.
        self.assertEqual(amounts.fill_after_payment(56 * second, 14_000, 5_600_000, 14_500), {"seconds": 56 * second, "deposit_back": 5_600_000, "amount_micros": 0, "sats": 0, "deposit_micros": 0, "ends": True})
        self.assertTrue(amounts.fill_after_payment(56 * second, 14_000, 5_600_000, 14_000)["ends"])
        self.assertFalse(amounts.fill_after_payment(56 * second, 14_000, 5_600_000, 13_999)["ends"])
        # The engine's own fill, before and after the part the vectors prove.
        vector = next(entry for entry in ENGINE["actions"] if entry["name"] == "proof_of_a_part")["fill"]
        before, held = ({name: int(value) for name, value in vector[when].items()} for when in ("before", "after"))
        after = amounts.fill_after_payment(**before, paid=int(vector["paid_sats"]))
        self.assertEqual({name: after[name] for name in held}, held)
        self.assertEqual(after["seconds"], before["amount_micros"] - held["amount_micros"])
        # Which part the chain counts: at least the order's smallest trade, or at least half of what is still
        # to pay, or all of it. (The engine's test refuses 999 satoshis of 20,000 with a smallest trade of 1,000.)
        self.assertFalse(amounts.part_counts(20_000, 999, 1_000))
        self.assertTrue(amounts.part_counts(20_000, 1_000, 1_000))
        for sats, paid, least, counts in ((1_500, 749, 1_000, False), (1_500, 750, 1_000, True), (1_501, 750, 1_000, False), (1_501, 751, 1_000, True), (500, 250, 1_000, True), (500, 249, 1_000, False), (500, 500, 1_000, True), (500, 9_000, 1_000, True), (1, 1, 1_000, True), (3, 1, 1_000, False), (3, 2, 1_000, True)):
            self.assertEqual(amounts.part_counts(sats, paid, least), counts, (sats, paid, least))
        for bad in ((0, 1, 1), (1, 0, 1), (1, 1, 0), (1.0, 1, 1), (1, "1", 1), (1, 1, None)):
            with self.assertRaises((ValueError, TypeError), msg=bad):
                amounts.part_counts(*bad)
        # Parts round down, and never give more than the fill held: thirds of 10 microseconds for 3 satoshis.
        self.assertEqual(amounts.part_seconds(10, 3, 1), 3)
        self.assertEqual(amounts.fill_after_payment(10, 3, 5, 1), {"seconds": 3, "deposit_back": 1, "amount_micros": 7, "sats": 2, "deposit_micros": 4, "ends": False})
        with self.assertRaisesRegex(ValueError, "a payment in full, not a part"):
            amounts.part_seconds(10, 3, 3)
        with self.assertRaisesRegex(ValueError, "buys less than a microsecond"):
            amounts.fill_after_payment(1, 1_000, 0, 999)
        for bad in ((0, 3, 1), (10, 0, 1), (10, 3, 0), (10.0, 3, 1), ("10", 3, 1), (10, 3, True)):
            with self.assertRaises((ValueError, TypeError), msg=bad):
                amounts.part_seconds(*bad)

    def test_only_whole_numbers_within_their_bounds(self):
        self.assertEqual(amounts.sats(40_000_000, PRICE), 10_000)
        self.assertEqual(amounts.bought(4_000, PRICE), 16_000_000)
        for bad in (1.0, "1", None, True, 10**6 + 0.5):
            with self.assertRaises(TypeError):
                amounts.sats(bad, PRICE)
            with self.assertRaises(TypeError):
                amounts.sats(1, bad)
            with self.assertRaises(TypeError):
                amounts.bought(bad, PRICE)
            with self.assertRaises(TypeError):
                amounts.bought(1, bad)
        for arguments in ((-1, PRICE), (2**64, PRICE), (1, 0), (1, 10**15 + 1), (1, -1)):
            with self.assertRaises(ValueError):
                amounts.sats(*arguments)
            with self.assertRaises(ValueError):
                amounts.bought(*arguments)


class Payloads(unittest.TestCase):
    def refuses(self, kind, payload, why):
        with self.assertRaisesRegex(ValueError, why, msg=repr(payload)[:200]):
            actions.action_payload(kind, payload)

    def test_the_vectors_are_the_file_the_engines_test_pins(self):
        import hashlib
        import re

        from . import SPEC

        source = (SPEC.parent / "v5" / "tests" / "market.rs").read_text(encoding="utf-8")
        pinned = re.search(r'const MARKET_VECTORS_SHA256: &str = "([0-9a-f]{64})";', source)
        self.assertEqual(hashlib.sha256((SPEC / "market-vectors.json").read_bytes()).hexdigest(), pinned.group(1))

    def test_the_vectors_hold_every_kind(self):
        self.assertEqual(dict(actions.KINDS), {"order": 50, "cancel": 51, "take": 52, "sell": 53, "proof": 54, "expire": 55, "release": 56, "settle": 57, "scripts": 58})
        self.assertEqual(sorted({entry["kind"] for entry in ENGINE["actions"]}), list(range(50, 59)))
        with self.assertRaises(TypeError):
            actions.KINDS["order"] = 1

    def test_each_payload_is_written_as_the_engine_wrote_it(self):
        for vector in ENGINE["actions"]:
            kind, payload = vector["kind"], vector["payload"]
            self.assertEqual(actions.payload_bytes(kind, payload).decode(), vector["payload_json"], vector["name"])
            self.assertEqual(actions.action_payload(kind, payload), payload)
            shuffled = dict(reversed(list(payload.items())))
            self.assertEqual(actions.payload_bytes(kind, shuffled).decode(), vector["payload_json"])

    def test_each_builder_makes_the_payload_of_the_engines_vector(self):
        made = {
            "sell_order": lambda p: actions.sell_order(amount_micros=p["amount_micros"], price=p["price"], scripts=p["scripts"], confirmations=p["confirmations"], pay_blocks=p["pay_blocks"], min_sats=p["min_sats"], deposit_ppm=p["deposit_ppm"], min_deposit_micros=p["min_deposit_micros"]),
            "buy_order": lambda p: actions.buy_order(amount_micros=int(p["amount_micros"]), price=int(p["price"]), forms=list(reversed(p["forms"])), confirmations=int(p["confirmations"]), pay_blocks=int(p["pay_blocks"]), min_sats=int(p["min_sats"]), deposit_ppm=int(p["deposit_ppm"])),
            "new_scripts": lambda p: actions.new_scripts(order=p["order"], scripts=tuple(p["scripts"])),
            "take_for_another": lambda p: actions.take(order=p["order"], amount_micros=p["amount_micros"], price=PRICE, to=p["to"]),
            "take": lambda p: actions.take(order=int(p["order"]), amount_micros=int(p["amount_micros"]), price=str(PRICE), to=int(p["to"])),
            "sell": lambda p: actions.sell(order=p["order"], amount_micros=p["amount_micros"], price=PRICE, confirmations=p["confirmations"], script=p["script"]),
            "sell_the_rest": lambda p: actions.sell(order=p["order"], amount_micros=p["amount_micros"], price=PRICE, confirmations=p["confirmations"], script=p["script"]),
            "proof_of_a_part": lambda p: actions.proof(fill=p["fill"], block_hash=p["block_hash"], transaction=p["transaction"], coinbase=p["coinbase"], vout=p["vout"], merkle_proof=p["merkle_proof"]),
            "proof": lambda p: actions.proof(fill=int(p["fill"]), block_hash=p["block_hash"], transaction=p["transaction"], coinbase=p["coinbase"], vout=int(p["vout"]), merkle_proof=p["merkle_proof"]),
            "release": lambda p: actions.release(fill=p["fill"]),
            "settle": lambda p: actions.settle(fill=p["fill"]),
            "expire": lambda p: actions.expire(fill=p["fill"]),
            "cancel": lambda p: actions.cancel(order=p["order"]),
        }
        self.assertEqual(sorted(made), sorted(entry["name"] for entry in ENGINE["actions"]))
        for vector in ENGINE["actions"]:
            payload = made[vector["name"]](vector["payload"])
            self.assertEqual(payload, vector["payload"], vector["name"])
            self.assertEqual(json.dumps(payload, separators=(",", ":")), vector["payload_json"], "the fields in the order they are signed")

    def test_a_builder_takes_its_arguments_by_name_and_whole_numbers_as_int_or_decimal_string(self):
        with self.assertRaises(TypeError):
            actions.cancel("1")
        with self.assertRaises(TypeError):
            actions.cancel(order="1", fill="1")
        with self.assertRaises(TypeError):
            actions.take(order="1", amount_micros="1", price="1")
        with self.assertRaises(TypeError):
            actions.take(order="1", amountMicros="1", price="1", to="1")
        for bad in ("07", "+7", "7.0", "7 ", " 7", "7\n", "", "0x7", "7e0", "-7", -7, 7.5, float("nan"), 2**64, "18446744073709551616", True, None, [7], b"7"):
            with self.assertRaisesRegex(ValueError, "order is a whole number from 0 to 2\\^64-1", msg=repr(bad)):
                actions.cancel(order=bad)
            with self.assertRaisesRegex(ValueError, "fill is a whole number"):
                actions.expire(fill=bad)
        self.assertEqual(actions.cancel(order=2**64 - 1), {"order": "18446744073709551615"})
        # The lists are copied, and the forms of a buy order are sorted for the caller.
        scripts = [W("01"), W("02")]
        order = actions.sell_order(amount_micros=10**8, price=PRICE, scripts=scripts, confirmations=3, pay_blocks=6, min_sats=1000, deposit_ppm=0, min_deposit_micros=0)
        scripts.append(W("03"))
        self.assertEqual(order["scripts"], [W("01"), W("02")])
        forms = ["p2wsh", "p2pkh"]
        self.assertEqual(actions.buy_order(amount_micros=10**8, price=PRICE, forms=forms, confirmations=3, pay_blocks=6, min_sats=1000, deposit_ppm=0)["forms"], ["p2pkh", "p2wsh"])
        self.assertEqual(forms, ["p2wsh", "p2pkh"])
        for bad in (None, "p2wpkh", {"p2wpkh"}, {"p2wpkh": 1}):
            with self.assertRaisesRegex(ValueError, "forms is a list"):
                actions.buy_order(amount_micros=10**8, price=PRICE, forms=bad, confirmations=3, pay_blocks=6, min_sats=1000, deposit_ppm=0)
            with self.assertRaisesRegex(ValueError, "scripts is a list"):
                actions.new_scripts(order=1, scripts=bad)

    def test_the_satoshis_of_a_fill_are_the_engines(self):
        for entry in ENGINE["sats"]:
            amount, price = entry["amount_micros"], entry["price"]
            if entry["sats"] is None or amount == "0":
                with self.assertRaises(ValueError, msg=entry):
                    actions.take(order=1, amount_micros=amount, price=price, to=0)
                with self.assertRaises(ValueError):
                    actions.sell(order=1, amount_micros=amount, price=price, confirmations=1, script=W("07"))
                continue
            self.assertEqual(actions.take(order=1, amount_micros=amount, price=price, to=0)["sats"], entry["sats"])
            self.assertEqual(actions.sell(order=1, amount_micros=amount, price=price, confirmations=1, script=W("07"))["sats"], entry["sats"])
            order = {**SELL, "amount_micros": amount, "price": price, "min_deposit_micros": "0"}
            self.assertEqual(actions.action_payload(50, {**order, "min_sats": entry["sats"]})["min_sats"], entry["sats"])
            if int(entry["sats"]) < amounts.SATS_MAX:
                self.refuses(50, {**order, "min_sats": str(int(entry["sats"]) + 1)}, "worth at least its smallest trade")

    def test_kind_50_what_an_order_must_be(self):
        self.assertEqual(actions.action_payload(50, SELL), SELL)
        self.assertEqual(actions.action_payload(50, BUY), BUY)
        cases = [
            ({"price": "0"}, "price is from 1 to 1000000000000000"),
            ({"price": "1000000000000001"}, "price is from 1 to 1000000000000000"),
            ({"amount_micros": "0"}, "amount_micros is from 1"),
            ({"min_sats": "25001"}, "worth at least its smallest trade"),
            ({"min_sats": "0"}, "min_sats is from 1"),
            ({"confirmations": "0"}, "confirmations is from 1 to 100"),
            ({"confirmations": "101"}, "confirmations is from 1 to 100"),
            ({"pay_blocks": "0"}, "pay_blocks is from 1 to 144"),
            ({"pay_blocks": "145"}, "pay_blocks is from 1 to 144"),
            ({"deposit_ppm": "1000001"}, "deposit_ppm is from 0 to 1000000"),
            ({"amount_micros": "18446744073709551615", "price": "1000000000000000"}, "more satoshis than exist"),
            ({"side": "Sell"}, 'side of an order is "sell" or "buy"'),
            ({"side": ...}, "side of an order"),
            ({"side": ["sell"]}, "side of an order"),
        ]
        for base in (SELL, BUY):
            for change, why in cases:
                self.refuses(50, but(base, **change), why)
        sixteen = [W(format(index, "02x")) for index in range(16)]
        for change, why in [
            ({"scripts": []}, "1 to 16 receiving scripts"),
            ({"scripts": ["6a0100"]}, "five standard forms"),
            ({"scripts": [W("01"), W("01")]}, "listed once"),
            ({"scripts": [W("AB")]}, "five standard forms"),
            ({"scripts": [W("01") + "00"]}, "five standard forms"),
            ({"scripts": [W("01") + "\n"]}, "five standard forms"),
            ({"scripts": [W("01"), 5]}, "five standard forms"),
            ({"scripts": sixteen + [W("ff")]}, "1 to 16 receiving scripts"),
            ({"scripts": None}, "1 to 16 receiving scripts"),
            ({"scripts": W("01")}, "1 to 16 receiving scripts"),
            ({"scripts": {W("01")}}, "1 to 16 receiving scripts"),
            ({"scripts": ...}, "has exactly the fields amount_micros, confirmations, deposit_ppm, min_deposit_micros, min_sats, pay_blocks, price, scripts, side"),
            ({"min_deposit_micros": ...}, "has exactly the fields"),
            ({"forms": ["p2tr"]}, "has exactly the fields"),
            ({"forms": None}, "has exactly the fields"),
            ({"min_deposit_micros": "100000001"}, "least deposit of a fill is at most what the order offers"),
            ({"extra": "1"}, "has exactly the fields"),
        ]:
            self.refuses(50, but(SELL, **change), why)
        self.assertEqual(len(actions.action_payload(50, {**SELL, "scripts": sixteen})["scripts"]), 16)
        for change, why in [
            ({"forms": []}, "forms is a list of at least one of"),
            ({"forms": ["p2wpkh", "p2tr"]}, "in this order, each once"),
            ({"forms": ["p2tr", "p2tr"]}, "in this order, each once"),
            ({"forms": ["p2pk"]}, "forms is a list"),
            ({"forms": ["P2TR"]}, "forms is a list"),
            ({"forms": None}, "forms is a list"),
            ({"forms": "p2tr"}, "forms is a list"),
            ({"forms": [["p2tr"]]}, "forms is a list"),
            ({"forms": ...}, "has exactly the fields amount_micros, confirmations, deposit_ppm, forms, min_sats, pay_blocks, price, side"),
            ({"scripts": [W("04")]}, "has exactly the fields"),
            ({"scripts": None}, "has exactly the fields"),
            ({"min_deposit_micros": "0"}, "has exactly the fields"),
        ]:
            self.refuses(50, but(BUY, **change), why)
        self.assertEqual(actions.action_payload(50, {**BUY, "forms": list(actions.FORMS)})["forms"], list(actions.FORMS))
        # The outer bounds pass here; a production network asks more of each and refuses these itself.
        for change in ({"confirmations": "1"}, {"confirmations": "100"}, {"pay_blocks": "1"}, {"pay_blocks": "144"}, {"deposit_ppm": "0"}, {"deposit_ppm": "1000000"}, {"min_sats": "1"}):
            self.assertTrue(actions.action_payload(50, but(BUY, **change)))

    def test_every_number_of_a_payload_is_a_decimal_string(self):
        places = [
            (50, SELL, ["amount_micros", "confirmations", "deposit_ppm", "min_deposit_micros", "min_sats", "pay_blocks", "price"]),
            (50, BUY, ["amount_micros", "confirmations", "deposit_ppm", "min_sats", "pay_blocks", "price"]),
            (51, {"order": "1"}, ["order"]),
            (52, TAKE, ["amount_micros", "order", "sats", "to"]),
            (53, SALE, ["amount_micros", "confirmations", "order", "sats"]),
            (54, PROOF, ["fill", "vout"]),
            (55, {"fill": "1"}, ["fill"]),
            (56, {"fill": "1"}, ["fill"]),
            (57, {"fill": "1"}, ["fill"]),
            (58, {"order": "1", "scripts": [W("02")]}, ["order"]),
        ]
        for kind, base, fields in places:
            self.assertEqual(actions.action_payload(kind, base), base)
            for field in fields:
                good = base[field]
                for bad in (int(good), float(good), "0" + good, good + " ", good + "\n", "+" + good, good + ".0", "-1", "", "1e3", "0x10", "18446744073709551616", "9" * 23, None, True, [good], good.encode()):
                    self.refuses(kind, {**base, field: bad}, f"{field} is a whole number as a decimal string without leading zeros")
        for kind, base, field in [(51, {"order": "1"}, "order"), (52, TAKE, "order"), (53, SALE, "order"), (58, {"order": "1", "scripts": [W("02")]}, "order"), (54, PROOF, "fill"), (55, {"fill": "1"}, "fill"), (56, {"fill": "1"}, "fill"), (57, {"fill": "1"}, "fill")]:
            self.refuses(kind, {**base, field: "0"}, f"{field} is from 1")
        self.assertEqual(actions.action_payload(52, {**TAKE, "to": "0"})["to"], "0")
        self.assertEqual(actions.action_payload(54, {**PROOF, "vout": "4294967295"})["vout"], "4294967295")
        self.refuses(54, {**PROOF, "vout": "4294967296"}, "vout is from 0 to 4294967295")

    def test_kinds_51_to_53_and_55_to_58(self):
        good = {51: {"order": "1"}, 52: TAKE, 53: SALE, 55: {"fill": "1"}, 56: {"fill": "1"}, 57: {"fill": "1"}, 58: {"order": "1", "scripts": [W("02"), TR("03")]}}
        for kind, payload in good.items():
            self.assertEqual(actions.action_payload(kind, payload), payload)
            self.refuses(kind, {**payload, "more": "1"}, "has exactly the fields")
            for field in payload:
                self.refuses(kind, but(payload, **{field: ...}), "has exactly the fields")
            self.refuses(kind, {}, "has exactly the fields")
        self.refuses(55, {"fill": "1", "order": "1"}, "has exactly the fields fill")
        for kind in (55, 56, 57):
            self.refuses(kind, {"order": "1"}, "has exactly the fields fill")
        self.refuses(51, {"fill": "1"}, "has exactly the fields order")
        for kind, base in ((52, TAKE), (53, SALE)):
            self.refuses(kind, {**base, "amount_micros": "0"}, "amount_micros is from 1")
            self.refuses(kind, {**base, "sats": "0"}, "sats is from 1")
            self.refuses(kind, {**base, "sats": "2100000000000001"}, "sats is from 1 to 2100000000000000")
            self.refuses(kind, {**base, "amount_micros": "5", "sats": "5001"}, "sats is the price of amount_micros")
            self.assertTrue(actions.action_payload(kind, {**base, "amount_micros": "5", "sats": "5000"}))
            self.refuses(kind, {**base, "amount_micros": "2000000000001", "sats": "2"}, "sats is the price of amount_micros")
            self.assertTrue(actions.action_payload(kind, {**base, "amount_micros": "2000000000001", "sats": "3"}))
        for bad in ("0", "101"):
            self.refuses(53, {**SALE, "confirmations": bad}, "confirmations is from 1 to 100")
        for bad in ("6a0100", W("AB"), W("07") + "00", W("07")[2:], W("07") + "\n", "", None, 7, [W("07")]):
            self.refuses(53, {**SALE, "script": bad}, "five standard forms")
        for scripts, why in (([], "1 to 16"), (None, "1 to 16"), ([W("02"), W("02")], "listed once"), (["6a0100"], "five standard forms"), ([TR(format(index, "02x")) for index in range(17)], "1 to 16")):
            self.refuses(58, {"order": "1", "scripts": scripts}, why)

    def test_kind_54_a_proof(self):
        self.assertEqual(actions.action_payload(54, PROOF), PROOF)
        self.assertEqual(list(PROOF), ["block_hash", "coinbase", "fill", "merkle_proof", "transaction", "vout"])
        for field in PROOF:
            self.refuses(54, but(PROOF, **{field: ...}), "has exactly the fields block_hash, coinbase, fill, merkle_proof, transaction, vout")
        self.refuses(54, {**PROOF, "script": W("01")}, "has exactly the fields")
        block = PROOF["block_hash"]
        for bad in ("AB" + block[2:], block[2:], block + "00", block + "\n", "0x" + block[2:], "", None, 5, block[:-1] + "g"):
            self.refuses(54, {**PROOF, "block_hash": bad}, "block_hash is 64 lowercase hexadecimal characters")
        for field, least, most in (("transaction", 65, 100000), ("coinbase", 1, 150000)):
            good = PROOF[field]
            for bad in (good[:-2] + "AB", good + "0", good + "zz", good + "\n", "", None, 5, [good], bytes.fromhex(good), "01000000" + "11" * (most - 3)):
                self.refuses(54, {**PROOF, field: bad}, f"{field} is lowercase hexadecimal of {least} to {most} bytes")
            for vector in (entry for entry in ENGINE["actions"] if entry["kind"] == 54):
                self.refuses(54, {**vector["payload"], field: vector["bitcoin_node"][field]}, f"{field} is serialized without witness data")
            self.assertTrue(actions.action_payload(54, {**PROOF, field: "01000000" + "11" * 61}))
            self.assertTrue(actions.action_payload(54, {**PROOF, field: "01000000" + "11" * (most - 4)}))
        # The payment is longer than 64 bytes; the coinbase may be as short as a miner makes it.
        self.refuses(54, {**PROOF, "transaction": "01000000" + "11" * 60}, "transaction is lowercase hexadecimal of 65 to 100000 bytes")
        self.assertTrue(actions.action_payload(54, {**PROOF, "coinbase": "01000000" + "11" * 56}))
        merkle = PROOF["merkle_proof"]
        for bad in (merkle.upper(), merkle + "0", merkle + "\n", "", None, "00" * 85, "00" * 4097):
            self.refuses(54, {**PROOF, "merkle_proof": bad}, "merkle_proof is lowercase hexadecimal of 86 to 4096 bytes")
        self.assertTrue(actions.action_payload(54, {**PROOF, "merkle_proof": "00" * 86}))
        self.assertTrue(actions.action_payload(54, {**PROOF, "merkle_proof": "00" * 4096}))
        # The largest payment with the largest coinbase and the largest Merkle proof: in hexadecimal they fit one action.
        largest = {**PROOF, "transaction": "01000000" + "11" * (100000 - 4), "coinbase": "01000000" + "11" * (150000 - 4), "merkle_proof": "00" * 4096, "fill": str(2**64 - 1), "vout": "4294967295"}
        self.assertTrue(500000 < len(actions.payload_bytes(54, largest)) <= 512 * 1024)

    def test_what_is_not_a_payload_of_the_market(self):
        class Fill(dict):
            pass

        for kind in range(50, 59):
            for bad in (None, "x", 5, [], [{"fill": "1"}], Fill(fill="1"), {1: "1"}, (("fill", "1"),)):
                self.refuses(kind, bad, "A market payload is a plain dict")
        for kind in (49, 59, 0, -1, 50.5, "50", None, True):
            with self.assertRaisesRegex(ValueError, "The kinds of the market are 50 to 58"):
                actions.action_payload(kind, {"fill": "1"})

    def test_the_fee_of_an_action_is_what_the_engine_took(self):
        times = {}
        for vector in ENGINE["actions"]:
            self.assertEqual(actions.action_fee(vector["kind"], vector["payload"], vector["network_fee_micros"]), int(vector["fee_micros"]), vector["name"])
            times[vector["name"]] = int(vector["fee_micros"]) // int(vector["network_fee_micros"])
        self.assertEqual([times[name] for name in ("sell_order", "buy_order", "new_scripts")], [4, 1, 3])
        # A proof of an ordinary payment costs about a dozen fees; a larger one, more.
        self.assertTrue(4 <= times["proof_of_a_part"] <= 16, times["proof_of_a_part"])
        self.assertGreater(times["proof"], 20)
        self.assertEqual(actions.action_fee(50, SELL, "1000"), 3000)
        self.assertEqual(actions.action_fee(50, BUY, 1000), 1000)
        self.assertEqual(actions.action_fee(58, {"order": "1", "scripts": [W(format(index, "02x")) for index in range(16)]}, 1000), 17000)
        for kind, payload in ((51, {"order": "1"}), (52, TAKE), (53, SALE), (55, {"fill": "1"}), (56, {"fill": "1"}), (57, {"fill": "1"})):
            self.assertEqual(actions.action_fee(kind, payload, 1000), 1000)
        empty = len(actions.payload_bytes(54, {**PROOF, "merkle_proof": "00" * 86})) - 172
        for size, fees in ((1022, 4), (1024, 5), (1278, 5), (1280, 6), (2048, 9), (8192, 33)):
            sized = {**PROOF, "merkle_proof": "00" * ((size - empty) // 2)}
            self.assertEqual(len(actions.payload_bytes(54, sized)), size)
            self.assertEqual(actions.action_fee(54, sized, 1000), 1000 * fees, size)
        self.assertEqual(actions.action_fee(51, {"order": "1"}, 0), 0)
        with self.assertRaisesRegex(ValueError, "order is from 1"):
            actions.action_fee(51, {"order": "0"}, 1000)
        with self.assertRaisesRegex(ValueError, "network_fee_micros is a whole number"):
            actions.action_fee(51, {"order": "1"}, "01000")
        with self.assertRaisesRegex(ValueError, "more than a balance can hold"):
            actions.action_fee(50, SELL, 2**64 - 1)


if __name__ == "__main__":
    unittest.main()
