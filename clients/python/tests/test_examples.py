"""The example scripts, each run through its ``main`` against the stand-in for the API (tests/fake_api.py).

What is held here: a dry run sends nothing; every refusal the scripts promise (an account without the
security rules, a limit or a balance above the ceiling, an index that is not clean, a price above the
limit, an order or a fill that changed between the list and the act, an address file that ran out, an
address that would be used twice); what the scripts sign is, byte for byte, what the engine signed
and accepted for the same trade (spec/market-vectors.json); the amounts they print are the vectors'
numbers; and no key is ever in what they print.

The stand-in is a model, not the engine and not the API: see the top of tests/fake_api.py. No network
beyond 127.0.0.1 is used, and no Bitcoin node: the "node wallet" of the payment test is a few lines
that answer one JSON-RPC call.
"""
import base64
import contextlib
import io
import json
import os
import re
import shlex
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from examples import buy_taker, sell_maker, stop_loss, watch_market
from timemarket import actions, bot, script_to_address, transaction_outputs, wire

from . import ENGINE
from .fake_api import FakeApi, World, guide_world, seed_of, vector_world

VECTOR = {entry["name"]: entry for entry in ENGINE["actions"]}
SELLER, BUYER, OTHER = seed_of("sell_order"), seed_of("buy_order"), seed_of("sell_the_rest")  # accounts 5, 6 and 8 of the vectors
KEY_NAME = "TIME_EXAMPLE_TEST_KEY"
ORDER_SCRIPTS = VECTOR["sell_order"]["payload"]["scripts"]
# Receiving scripts of the tests' own: a p2pkh one first (a form the vectors' buy order cannot pay to), then others.
SPARE = ["76a914" + "a1" * 20 + "88ac", "0014" + "a2" * 20, "0014" + "a3" * 20, "0014" + "a4" * 20, "0014" + "a5" * 20, "0014" + "a6" * 20, "5120" + "a7" * 32, "0020" + "a8" * 32]


class _Addresses(dict):
    """The regtest address of a script: the vectors' own where they have one, else what the package's codec gives."""

    def __missing__(self, script):
        return script_to_address(script, "regtest")


ADDRESS = _Addresses({entry["script"]: entry["address"] for entry in ENGINE["addresses"] if entry["network"] == "regtest"})


def signed(world: World, seed: str, account: int, kind: int, payload: dict) -> bytes:
    """An action of another party of a test, signed for the stand-in's network with the account's next nonce."""
    return wire.sign_action(network_id=world.network_id, kind=kind, sender=account, nonce=world.accounts[account]["nonce"] + 1, auth_epoch=0, payload=payload, seed=seed)


class Examples(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.said = []

    def tearDown(self):
        # No key in anything any script printed, in any of its forms.
        text = "\n".join(self.said)
        for seed in (SELLER, BUYER, OTHER):
            for form in (seed, seed.upper(), repr(bytes.fromhex(seed)), base64.b64encode(bytes.fromhex(seed)).decode()):
                self.assertNotIn(form, text)

    def addresses(self, scripts, name="addresses.txt") -> str:
        path = os.path.join(self.folder.name, name)
        Path(path).write_text("# made by the operator's own wallet\n" + "\n".join(ADDRESS[script] for script in scripts) + "\n", encoding="utf-8")
        return path

    def run_script(self, module, world: World, arguments: list[str], *, seed: str | None = None, sleep=None, base: str | None = None):
        """(exit code, what was printed, the actions that were POSTed) of one run of a script's main."""
        out, before, pauses = io.StringIO(), len(world.posted), []
        environment = {KEY_NAME: seed} if seed else {}

        def pause(seconds):
            # No test waits in earnest, and none may go round for ever: a script that does not stop is a failed test, not a hung one.
            pauses.append(seconds)
            if len(pauses) > 500:
                raise AssertionError("the script paused more than 500 times: it does not stop")
            if sleep is not None:
                sleep(seconds)

        with FakeApi(world) as api, mock.patch.dict(os.environ, environment), contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            if module is not watch_market:
                arguments = ["--bitcoin-network", "regtest", "--max-daily-limit", "600", "--max-balance", "3000"] + arguments + (["--key-env", KEY_NAME] if seed else [])
            try:
                code = module.main(["--api", base or api.base] + arguments, sleep=pause)
            except SystemExit as stop:  # argparse refusing the command line
                code = stop.code
        self.said.append(out.getvalue())
        return code, out.getvalue(), world.posted[before:]

    # ------------------------------------------------------------ a dry run sends nothing
    def test_a_dry_run_is_the_default_and_sends_nothing(self):
        world = vector_world()
        world.add_account(9, OTHER, 100_000_000)
        world.apply(signed(world, OTHER, 9, 50, actions.sell_order(amount_micros=30_000_000, price=240_000_000, scripts=[SPARE[0]], confirmations=1, pay_blocks=6, min_sats=1000, deposit_ppm=0, min_deposit_micros=0)))
        file = self.addresses(SPARE[1:])
        before = Path(file).read_text(encoding="utf-8")
        runs = (
            (watch_market, [], None),
            (buy_taker, ["--account", "6", "--amount", "20", "--limit-price", "250000000"], BUYER),
            (buy_taker, ["--account", "6", "--amount", "20", "--limit-price", "250000000", "--dry-run"], None),
            (sell_maker, ["--account", "5", "--address-file", file, "--amount", "100", "--price", "260000000", "--scripts", "3"], SELLER),
            (sell_maker, ["--account", "5", "--address-file", file, "--amount", "100", "--price", "250000000", "--cancel-on-exit", "--expire-unpaid"], None),
            (stop_loss, ["--account", "5", "--address-file", file, "--amount", "20", "--stop-price", "250000000", "--limit-price", "240000000", "--size-floor", "20", "--allow-immediate", "--confirm-rounds", "1"], SELLER),
        )
        for module, arguments, seed in runs:
            code, text, posted = self.run_script(module, world, arguments, seed=seed)
            self.assertEqual((code, posted), (0, []), text)
            if module is not watch_market:
                self.assertIn("DRY RUN", text)
                self.assertIn("WOULD SEND", text)
                self.assertNotIn("SENDING", text)
        self.assertEqual([method for method, path in world.requests if method != "GET"], [], "a dry run only asks")
        self.assertEqual(Path(file).read_text(encoding="utf-8"), before, "a dry run marks no address")
        # A dry run of the taker says exactly what it would sign: the payload the engine accepted.
        _, text, _ = self.run_script(buy_taker, vector_world(), ["--account", "6", "--amount", "20", "--limit-price", "250000000"])
        self.assertIn(VECTOR["take"]["payload_json"], text)
        # Both at once is refused by the command line, and to act a key must be named.
        code, text, posted = self.run_script(buy_taker, world, ["--account", "6", "--amount", "20", "--limit-price", "250000000", "--act", "--dry-run"])
        self.assertEqual((code, posted), (2, []))
        code, text, posted = self.run_script(buy_taker, world, ["--account", "6", "--amount", "20", "--limit-price", "250000000", "--act"])
        self.assertEqual((code, posted), (2, []))
        self.assertIn("needs the signing key", text)

    # ------------------------------------------------------------ what the scripts sign is what the engine signed
    def test_the_taker_signs_the_engines_take_and_prints_the_vectors_numbers(self):
        world = vector_world()
        world.accounts[6]["nonce"] = 2  # the vector's take is the buyer's third action
        events = [lambda: None, lambda: world.pay(1, 5000)]  # at the second pause of the watch, the payment is proven
        code, text, posted = self.run_script(buy_taker, world, ["--account", "6", "--amount", "20", "--limit-price", "250000000", "--interval", "1", "--act"], seed=BUYER, sleep=lambda seconds: events.pop(0)() if events else None)
        self.assertEqual(code, 0, text)
        self.assertEqual([action.hex() for action in posted], [VECTOR["take"]["signed_hex"]], "byte for byte what the engine signed and accepted")
        sats = VECTOR["take"]["payload"]["sats"]
        self.assertEqual(sats, "5000")
        self.assertIn(f"PAY {sats} satoshis (0.00005000 BTC) to {ADDRESS[ORDER_SCRIPTS[0]]}", text)
        self.assertIn(f'bitcoin-cli -regtest sendtoaddress "{ADDRESS[ORDER_SCRIPTS[0]]}" 0.00005000', text)
        self.assertIn(f"fee 0.001 s ({VECTOR['take']['fee_micros']} microseconds)", text)
        self.assertIn("A deposit of 1 s is locked", text)
        self.assertIn("by Bitcoin height 11 at the latest", text)  # start 5 + 6 blocks to pay + 1 confirmation - 1
        self.assertIn("Fill 1 has ended: paid", text)
        self.assertIn("prove.mjs CONFIG --fill 1", text)
        self.assertEqual(world.accounts[6]["balance"], 94_999_000 - 1000 + 20_000_000, "the seconds came, the deposit came back, one fee was paid")

    def test_a_fill_paid_in_part_is_read_again_and_the_rest_is_the_vectors(self):
        world = vector_world()
        world.apply(bytes.fromhex(VECTOR["take_for_another"]["signed_hex"]))  # account 6 takes 40 seconds for account 8
        said = VECTOR["proof_of_a_part"]["fill"]
        self.assertEqual({name: world.fills[1][name] for name in said["before"]}, said["before"])
        world.pay(1, int(said["paid_sats"]))
        self.assertEqual({name: world.fills[1][name] for name in said["after"]}, said["after"])
        code, text, posted = self.run_script(buy_taker, world, ["--account", "6", "--fill", "1", "--interval", "1", "--watch-seconds", "2"])
        self.assertEqual((code, posted), (4, []), text)
        self.assertIn(f"PAY {said['after']['sats']} satoshis (0.00006000 BTC) to {ADDRESS[ORDER_SCRIPTS[0]]}", text)
        self.assertIn("24 s for account 8", text)
        self.assertIn("IF YOU HAVE PAID ALREADY, DO NOT PAY AGAIN", text)
        self.assertIn("still open", text)
        # With --fill the script never pays, and it watches only a fill this account pays.
        code, text, _ = self.run_script(buy_taker, world, ["--account", "6", "--fill", "1", "--pay-with-bitcoin-rpc", "http://127.0.0.1:1/", "--bitcoin-cookie-file", "nowhere"])
        self.assertEqual(code, 2)
        self.assertIn("never pays", text)
        code, text, _ = self.run_script(buy_taker, world, ["--account", "8", "--fill", "1"])
        self.assertEqual(code, 2)
        self.assertIn("not paid by this account", text)
        # The fill expires unpaid: the watch says so, and that a payment now buys nothing.
        world.expirable.add(1)
        world.apply(signed(world, SELLER, 5, 55, actions.expire(fill=1)))
        code, text, _ = self.run_script(buy_taker, world, ["--account", "6", "--fill", "1"])
        self.assertEqual(code, 1, "the fill is gone: there is nothing to read")
        self.assertIn("fill_not_found", text)

    def test_the_maker_signs_the_engines_order_its_new_scripts_and_its_cancellation(self):
        world = World()
        world.add_account(5, SELLER, 400_000_000)
        world.add_account(6, BUYER, 100_000_000)
        file = self.addresses(ORDER_SCRIPTS + VECTOR["new_scripts"]["payload"]["scripts"] + SPARE[:1])
        terms = ["--account", "5", "--address-file", file, "--amount", "100", "--price", "250000000", "--confirmations", "1", "--pay-blocks", "6", "--min-sats", "1000", "--deposit-ppm", "50000", "--min-deposit", "0.25", "--rounds", "1", "--act"]
        code, text, posted = self.run_script(sell_maker, world, terms + ["--scripts", "3"], seed=SELLER)
        self.assertEqual(code, 0, text)
        self.assertEqual([action.hex() for action in posted], [VECTOR["sell_order"]["signed_hex"]])
        self.assertIn(f"fee 0.004 s ({VECTOR['sell_order']['fee_micros']} microseconds)", text)
        self.assertIn("25000 satoshis in all", text)
        self.assertIn("The order is number 1.", text)
        lines = Path(file).read_text(encoding="utf-8").splitlines()
        self.assertEqual([line.split()[1:2] for line in lines[1:]], [["used"]] * 3 + [[]] * 3, "the three listed addresses are marked, the others are not")
        # The same command again finds the order and does nothing: one order is kept, not one a round.
        code, text, posted = self.run_script(sell_maker, world, terms + ["--scripts", "3"], seed=SELLER)
        self.assertEqual((code, posted), (0, []), text)
        self.assertIn("Order 1: 100 s on offer, 0 open fills, 3 free addresses.", text)
        # Takers use all three addresses. The maker then gives the order the next two of the file, never an old one.
        for _ in range(3):
            world.apply(signed(world, BUYER, 6, 52, actions.take(order=1, amount_micros=20_000_000, price=250_000_000, to=6)))
        code, text, posted = self.run_script(sell_maker, world, terms + ["--scripts", "5"], seed=SELLER)
        self.assertEqual(code, 0, text)
        self.assertEqual([action.hex() for action in posted], [VECTOR["new_scripts"]["signed_hex"]])
        self.assertIn(f"fee 0.003 s ({VECTOR['new_scripts']['fee_micros']} microseconds)", text)
        self.assertIn("this counts 100 s against the daily limit", text)
        self.assertEqual(sum("used" in line for line in Path(file).read_text(encoding="utf-8").splitlines()), 5)
        # A fill whose time has passed is ended only when asked, and only when the chain allows it.
        world.expirable.add(2)
        code, text, posted = self.run_script(sell_maker, world, terms + ["--scripts", "5"], seed=SELLER)
        self.assertEqual(posted, [])
        code, text, posted = self.run_script(sell_maker, world, terms + ["--scripts", "5", "--expire-unpaid"], seed=SELLER)
        self.assertEqual([wire.decode_action(action)["payload"] for action in posted], [{"fill": "2"}], text)
        self.assertEqual(wire.decode_action(posted[0])["kind"], 55)
        # Stopping with --cancel-on-exit takes the order back: the engine's cancellation, byte for byte.
        world.accounts[5]["nonce"] = 4  # the vector's cancellation is the seller's fifth action
        world.security[5]["allowance_micros"] = "600000000"
        code, text, posted = self.run_script(sell_maker, world, terms + ["--scripts", "5", "--cancel-on-exit"], seed=SELLER)
        self.assertEqual([action.hex() for action in posted], [VECTOR["cancel"]["signed_hex"]], text)
        self.assertIn("Taking order 1 back", text)
        # The order is gone when its last fills end; a maker that had one stops, and a new run makes a new one from new addresses.
        self.assertFalse(world.orders[1]["open"])

    def test_the_stop_loss_signs_the_engines_sale_only_when_the_book_holds_the_trigger(self):
        world = vector_world()
        world.add_account(9, OTHER, 100_000_000)
        world.accounts[5]["nonce"] = 2  # the vector's sale is the seller's third action
        file = self.addresses([SPARE[0], VECTOR["sell"]["payload"]["script"]])  # a p2pkh address the buyer cannot pay to, then a p2wsh one
        offer = lambda amount, script: world.apply(signed(world, OTHER, 9, 50, actions.sell_order(amount_micros=amount, price=240_000_000, scripts=[script], confirmations=1, pay_blocks=6, min_sats=1000, deposit_ppm=0, min_deposit_micros=0)))
        height = lambda: setattr(world, "height", world.height + 1)
        # Pauses: a small offer under the stop appears (too small to decide), then a real one, then two more blocks.
        events = [lambda: offer(5_000_000, SPARE[1]), lambda: offer(30_000_000, SPARE[2]), height, height]
        arguments = ["--account", "5", "--address-file", file, "--amount", "20", "--stop-price", "245000000", "--limit-price", "245000000", "--size-floor", "20", "--confirmations", "2", "--confirm-rounds", "2", "--interval", "1", "--act"]
        code, text, posted = self.run_script(stop_loss, world, arguments, seed=SELLER, sleep=lambda seconds: events.pop(0)() if events else None)
        self.assertEqual(code, 0, text)
        self.assertEqual([action.hex() for action in posted], [VECTOR["sell"]["signed_hex"]], "byte for byte what the engine signed and accepted")
        readings = [line for line in text.splitlines() if line.startswith("As of height")]
        self.assertEqual(["holds" in line and "does not hold" not in line for line in readings], [False, False, True, True])
        self.assertIn("the book offers less than 20 s from others", readings[0])
        self.assertIn("20 s can be had from other people's sell orders at 240 satoshis a second or less", readings[2])
        self.assertIn("(1 of 2 readings in a row)", readings[2])
        self.assertIn(f"selling 20 s into it for {VECTOR['sell']['payload']['sats']} satoshis (0.00005000 BTC)", text)
        self.assertIn(f"to be paid to {ADDRESS[VECTOR['sell']['payload']['script']]} with 2 confirmations", text)
        self.assertIn("The sale is fill 1: 5000 satoshis are to arrive at that address by Bitcoin height 12.", text)
        lines = Path(file).read_text(encoding="utf-8").splitlines()
        self.assertEqual(["used" in line for line in lines[1:]], [False, True], "the address the buyer could not pay to was left for later")

    def test_the_stop_loss_offers_at_the_limit_when_no_buyer_pays_it_and_one_reading_is_not_enough(self):
        world = vector_world()
        world.add_account(9, OTHER, 100_000_000)
        world.apply(signed(world, OTHER, 9, 50, actions.sell_order(amount_micros=30_000_000, price=240_000_000, scripts=[SPARE[2]], confirmations=1, pay_blocks=6, min_sats=1000, deposit_ppm=0, min_deposit_micros=0)))
        file = self.addresses(SPARE[:2] + [VECTOR["sell"]["payload"]["script"]])
        arguments = ["--account", "5", "--address-file", file, "--amount", "20", "--stop-price", "245000000", "--size-floor", "20", "--scripts", "2", "--interval", "1", "--act"]
        # Met at the first reading: refused, because that is nearly always a wrong unit.
        code, text, posted = self.run_script(stop_loss, world, arguments + ["--limit-price", "245000000"], seed=SELLER)
        self.assertEqual((code, posted), (2, []), text)
        self.assertIn("The trigger is met at the first reading", text)
        # Allowed, the same reading again and again is one reading: the index has not moved, and nothing is sold.
        code, text, posted = self.run_script(stop_loss, world, arguments + ["--limit-price", "245000000", "--allow-immediate", "--rounds", "5"], seed=SELLER)
        self.assertEqual((code, posted), (0, []), text)
        self.assertEqual(text.count("(1 of 3 readings in a row)"), 5)
        # With three heights it sells. The buy order pays 250, under this limit of 255: the seconds are offered at the limit.
        world.accounts[5]["balance"] = 299_996_000
        height = lambda seconds: setattr(world, "height", world.height + 1)
        code, text, posted = self.run_script(stop_loss, world, ["--account", "5", "--address-file", file, "--amount", "20", "--stop-price", "260000000", "--limit-price", "255000000", "--size-floor", "20", "--scripts", "2", "--interval", "1", "--act", "--allow-immediate"], seed=SELLER, sleep=height)
        self.assertEqual(code, 0, text)
        self.assertEqual([(wire.decode_action(action)["kind"], wire.decode_action(action)["payload"]["price"], wire.decode_action(action)["payload"]["amount_micros"]) for action in posted], [(50, "255000000", "20000000")])
        self.assertIn("No buy order of somebody else is at or above your limit.", text)
        self.assertIn("5100 satoshis in all", text)
        # A limit above the stop is not a limit.
        code, text, posted = self.run_script(stop_loss, world, arguments + ["--limit-price", "245000001"], seed=SELLER)
        self.assertEqual((code, posted), (2, []))

    def test_the_maker_stops_when_its_order_is_gone_and_makes_a_new_one_only_when_asked(self):
        def gone(more):
            """A run of two rounds; between them the owner cancels the order from a wallet (with the same key, here)."""
            world = World()
            world.add_account(5, SELLER, 400_000_000)
            file = self.addresses(SPARE[:6])
            events = [lambda: world.apply(signed(world, SELLER, 5, 51, actions.cancel(order=1)))]
            arguments = ["--account", "5", "--address-file", file, "--amount", "20", "--price", "260000000", "--scripts", "2", "--rounds", "2", "--interval", "1", "--act", *more]
            return world, file, self.run_script(sell_maker, world, arguments, seed=SELLER, sleep=lambda seconds: events.pop(0)() if events else None)

        # Without --renew the script says that the order is gone, and stops.
        world, file, (code, text, posted) = gone([])
        self.assertEqual((code, len(posted), len(world.orders)), (0, 1, 0), text)
        self.assertIn("The order is gone", text)
        # With it, it would make a new one. But the cancellation used a nonce this run did not use: somebody else signs
        # with the key, so the run stops instead, and the two addresses it had taken for the new order are spent, not kept.
        world, file, (code, text, posted) = gone(["--renew"])
        self.assertEqual((code, len(posted), len(world.orders)), (2, 1, 0), text)
        self.assertIn("The nonce of this account moved without this script", text)
        self.assertEqual(bot.AddressFile(file, "regtest").free(), 2)
        # A new run makes the order, from addresses no order was ever offered.
        code, text, posted = self.run_script(sell_maker, world, ["--account", "5", "--address-file", file, "--amount", "20", "--price", "260000000", "--scripts", "2", "--rounds", "1", "--act"], seed=SELLER)
        self.assertEqual(code, 0, text)
        self.assertEqual(wire.decode_action(posted[0])["payload"]["scripts"], SPARE[4:6])

    def test_the_stop_loss_judged_on_trades_wants_size_and_several_fills(self):
        world = vector_world()
        world.add_account(9, OTHER, 100_000_000)
        world.accounts[6]["balance"] = 80_000_000
        world.apply(signed(world, OTHER, 9, 50, actions.sell_order(amount_micros=30_000_000, price=240_000_000, scripts=SPARE[1:4], confirmations=1, pay_blocks=6, min_sats=1000, deposit_ppm=0, min_deposit_micros=0)))
        file = self.addresses([VECTOR["sell"]["payload"]["script"]] + SPARE[4:6])
        arguments = ["--account", "5", "--address-file", file, "--amount", "20", "--stop-price", "245000000", "--limit-price", "245000000", "--size-floor", "20", "--trigger", "trades", "--confirmations", "2", "--confirm-rounds", "1", "--allow-immediate", "--rounds", "1", "--act"]
        world.accounts[5]["nonce"] = 2
        for number in (1, 2):  # two fills of 10 seconds, paid at 240: enough seconds, too few fills
            world.apply(signed(world, BUYER, 6, 52, actions.take(order=3, amount_micros=10_000_000, price=240_000_000, to=6)))
            world.pay(number, 2400)
        code, text, posted = self.run_script(stop_loss, world, arguments, seed=SELLER)
        self.assertEqual((code, posted), (0, []), text)
        self.assertIn("the newest trades add up to 20 s from 2 fills: too little to decide on", text)
        world.apply(signed(world, BUYER, 6, 52, actions.take(order=3, amount_micros=10_000_000, price=240_000_000, to=6)))
        world.pay(3, 2400)
        code, text, posted = self.run_script(stop_loss, world, arguments, seed=SELLER)
        self.assertEqual(code, 0, text)
        self.assertIn("the newest 3 trades (30 s, 3 fills) were at 240 satoshis a second to 240 satoshis a second. The trigger holds", text)
        self.assertEqual([action.hex() for action in posted], [VECTOR["sell"]["signed_hex"]])
        # One of the three at a price above the stop, and the trigger does not hold.
        world.trades[-1]["price"] = "246000000"
        code, text, posted = self.run_script(stop_loss, world, arguments, seed=SELLER)
        self.assertEqual((code, posted), (0, []), text)
        self.assertIn("The trigger does not hold.", text)

    def test_one_small_trade_does_not_fire_the_stop_loss(self):
        world = vector_world()
        world.accounts[6]["balance"] = 50_000_000
        file = self.addresses(SPARE[:4])
        # Somebody takes the smallest trade the order allows (1,000 satoshis: 4 seconds) and pays it. The last recorded price is now 250.
        world.apply(signed(world, BUYER, 6, 52, actions.take(order=1, amount_micros=4_000_000, price=250_000_000, to=6)))
        world.pay(1, 1000)
        self.assertEqual(world.trades[-1]["price"], "250000000")
        for trigger in ("book", "trades"):
            arguments = ["--account", "8", "--address-file", file, "--amount", "20", "--stop-price", "250000000", "--limit-price", "240000000", "--size-floor", "20", "--trigger", trigger, "--rounds", "4", "--interval", "1", "--act", "--allow-immediate"]
            # Account 8 holds 50 seconds and judges on the book of others, or on trades that add up to its floor from three fills.
            if trigger == "book":
                world.orders[1]["owner"] = "8"  # the only sell order is its own: other people offer nothing
            code, text, posted = self.run_script(stop_loss, world, arguments, seed=OTHER, sleep=lambda seconds: setattr(world, "height", world.height + 1))
            self.assertEqual((code, posted), (0, []), text)
            self.assertEqual(text.count("The trigger does not hold."), 4)
            self.assertIn("nothing is decided" if trigger == "book" else "too little to decide on", text)

    # ------------------------------------------------------------ the refusals before anything is signed
    def acting(self, world: World, file: str):
        """The three scripts that sign, each with a command that would send something in this world."""
        return (
            (buy_taker, ["--account", "6", "--amount", "20", "--limit-price", "250000000", "--act"], BUYER),
            (sell_maker, ["--account", "5", "--address-file", file, "--amount", "100", "--price", "260000000", "--scripts", "2", "--rounds", "1", "--act"], SELLER),
            (stop_loss, ["--account", "5", "--address-file", file, "--amount", "20", "--stop-price", "250000000", "--limit-price", "240000000", "--size-floor", "20", "--allow-immediate", "--confirm-rounds", "1", "--act"], SELLER),
        )

    def world_with_offers(self) -> World:
        world = vector_world()
        world.add_account(9, OTHER, 100_000_000)
        world.apply(signed(world, OTHER, 9, 50, actions.sell_order(amount_micros=30_000_000, price=240_000_000, scripts=[SPARE[3]], confirmations=1, pay_blocks=6, min_sats=1000, deposit_ppm=0, min_deposit_micros=0)))
        return world

    def test_every_acting_script_refuses_an_account_that_is_not_fit_and_an_index_that_is_not_clean(self):
        def no_rules(world): world.security[5] = world.security[6] = None
        def limit(world): world.security[5]["policy"]["daily_limit_micros"] = world.security[6]["policy"]["daily_limit_micros"] = "600000001"
        def raise_waiting(world): world.security[5]["pending_limit"] = world.security[6]["pending_limit"] = {"daily_limit_micros": "900000000", "id": "1", "ready_elapsed_micros": "99999999999999"}
        def balance(world): world.accounts[5]["balance"] = world.accounts[6]["balance"] = 3_000_000_001
        def frozen(world): world.security[5]["frozen_until_elapsed_micros"] = world.security[6]["frozen_until_elapsed_micros"] = str(world.now + 1)
        def flag(name, value): return lambda world: world.index.__setitem__(name, value)
        def another_network(world): world.bitcoin["network"] = "testnet3"
        def halted(world): world.bitcoin["halted"] = True
        cases = (
            (no_rules, "has not adopted the account security rules"), (limit, "The daily limit of this account is 600.000001 s, more than the 600 s you allow"), (raise_waiting, "A raise of this account's daily limit to 900 s is waiting"),
            (balance, "This account holds 3000.000001 s, more than the 3000 s you allow"), (frozen, "This account is frozen"),
            (flag("consistent", False), "not to be relied on now (consistent)"), (flag("tape_reconciled", False), "not to be relied on now (tape_reconciled)"), (flag("ready", False), "not to be relied on now (ready)"),
            (flag("last_error", {"code": "read_failed", "at": "2026-11-26T00:00:00.000Z"}), "last_error read_failed"), (flag("waiting_for_indexer", True), "waiting_for_indexer"),
            (another_network, "The network follows Bitcoin testnet3, and you named regtest"), (halted, "header chain is halted"),
        )
        for change, words in cases:
            world, file = self.world_with_offers(), self.addresses(SPARE[:3])
            before = Path(file).read_text(encoding="utf-8")
            change(world)
            for module, arguments, seed in self.acting(world, file):
                code, text, posted = self.run_script(module, world, arguments, seed=seed)
                self.assertEqual((code, posted), (2, []), f"{module.__name__}: {words}\n{text}")
                self.assertIn("REFUSED: ", text)
                self.assertIn(words, text, module.__name__)
            self.assertEqual(Path(file).read_text(encoding="utf-8"), before, "no address was marked for an action that was never sent")
        # Unchanged, the same three commands do act: the refusals above are not refusals of the commands.
        world, file = self.world_with_offers(), self.addresses(SPARE[:3])
        for module, arguments, seed in self.acting(world, file)[1:]:
            code, text, posted = self.run_script(module, world, arguments, seed=seed)
            self.assertEqual((code, len(posted)), (0, 1), text)

    def test_a_key_that_is_not_the_accounts_spending_key_signs_nothing(self):
        for change, words in (
            (lambda world: None, "is not a key of this account"),
            (lambda world: world.accounts[6]["devices"].__setitem__(0, {"can_manage": False, "can_spend": False, "public_key": wire.public_key(OTHER)}), "cannot spend"),
            (lambda world: world.accounts[6]["devices"].__setitem__(0, {"can_manage": True, "can_spend": True, "public_key": wire.public_key(OTHER)}), "can also manage the account"),
        ):
            world = vector_world()
            change(world)
            code, text, posted = self.run_script(buy_taker, world, ["--account", "6", "--amount", "20", "--limit-price", "250000000", "--act"], seed=OTHER)
            self.assertEqual((code, posted), (2, []), text)
            self.assertIn(words, text)
        # A variable that is not set, or that holds something else, stops the script with words that do not repeat it.
        world = vector_world()
        code, text, posted = self.run_script(buy_taker, world, ["--account", "6", "--amount", "20", "--limit-price", "250000000", "--act", "--key-env", "TIME_EXAMPLE_NOT_SET"])
        self.assertEqual((code, posted), (1, []))
        self.assertIn("The environment variable TIME_EXAMPLE_NOT_SET is not set", text)
        with mock.patch.dict(os.environ, {"TIME_EXAMPLE_WRONG": "correct horse battery staple"}):
            code, text, posted = self.run_script(buy_taker, world, ["--account", "6", "--amount", "20", "--limit-price", "250000000", "--act", "--key-env", "TIME_EXAMPLE_WRONG"])
        self.assertEqual((code, posted), (1, []))
        self.assertNotIn("horse", text)

    def test_the_taker_refuses_a_price_above_its_limit_and_an_order_that_changed_between_list_and_act(self):
        arguments = ["--account", "6", "--amount", "20", "--act"]
        world = vector_world()
        code, text, posted = self.run_script(buy_taker, world, arguments + ["--limit-price", "249999999"], seed=BUYER)
        self.assertEqual((code, posted), (2, []), text)
        self.assertIn("The best sell order asks 250 satoshis a second, above your limit of 249.999999 satoshis a second: nothing is taken", text)
        # The row says another price than the list did (a stale list, or a lying one).
        for change, words in (
            (lambda world: world.orders[1].__setitem__("price", "250000001"), "is not what the list said"),
            (lambda world: world.orders[1].__setitem__("owner", "8"), "is not what the list said"),
            (lambda world: world.orders[1].__setitem__("open", False), "takes no fill now"),
            (lambda world: world.accounts[5]["devices"].clear(), "its owner does not stand"),
            (lambda world: world.orders.pop(1), "order_not_found"),
        ):
            world = vector_world()
            world.on_request = lambda method, path, world=world, change=change: change(world) if path == "/v1/market/orders/1" and 1 in world.orders else None
            code, text, posted = self.run_script(buy_taker, world, arguments + ["--limit-price", "250000000"], seed=BUYER)
            self.assertEqual(posted, [], text)
            self.assertIn(code, (1, 2))
            self.assertIn(words, text)
        # Terms outside the taker's own: too many confirmations, too little time, too large a deposit, too small a rest.
        for change, more, words in (
            (lambda world: world.orders[1].__setitem__("confirmations", "7"), [], "outside what you allow"),
            (lambda world: world.orders[1].__setitem__("pay_blocks", "2"), [], "outside what you allow"),
            (lambda world: world.orders[1].__setitem__("deposit_ppm", "200000"), [], "asks a deposit of 4 s, more than you allow"),
            (lambda world: world.orders[1].__setitem__("amount_micros", "23000000"), [], "What would stay on offer (3 s) costs less than the order's smallest trade"),
            (lambda world: None, ["--max-deposit", "0.5"], "asks a deposit of 1 s, more than you allow"),
        ):
            world = vector_world()
            change(world)
            code, text, posted = self.run_script(buy_taker, world, arguments + ["--limit-price", "250000000"] + more, seed=BUYER)
            self.assertEqual((code, posted), (2, []), text)
            self.assertIn(words, text)
        # Its own order is never the one it takes, and an order that takes no fill is passed over.
        world = vector_world()
        world.orders[1]["owner"] = "6"
        code, text, posted = self.run_script(buy_taker, world, arguments + ["--limit-price", "250000000"], seed=BUYER)
        self.assertEqual((code, posted), (2, []))
        self.assertIn("No sell order of somebody else takes a fill now", text)

    def test_a_fill_that_is_not_what_the_take_made_is_never_paid(self):
        class Wallet(BaseHTTPRequestHandler):
            calls = []

            def log_message(self, *arguments):
                pass

            def do_POST(self):
                Wallet.calls.append((self.headers.get("Authorization"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                status, body = Wallet.answer
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Wallet)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        cookie = os.path.join(self.folder.name, "cookie")
        Path(cookie).write_text("__cookie__:not-a-real-password-0123456789\n", encoding="utf-8")
        node = f"http://127.0.0.1:{server.server_address[1]}/wallet/trading"
        arguments = ["--account", "6", "--amount", "20", "--limit-price", "250000000", "--interval", "1", "--act", "--pay-with-bitcoin-rpc", node, "--bitcoin-cookie-file", cookie]

        def world_and_watch(change, at):
            """A world in which `change` happens when the fill is read for the `at`-th time."""
            world, reads = vector_world(), []
            world.accounts[6]["nonce"] = 2

            def seen(method, path):
                if path == "/v1/market/fills/1":
                    reads.append(path)
                    if len(reads) == at:
                        change(world)
            world.on_request = seen
            return world

        # The honest case: the fill is read twice, the node wallet is asked once, with the amount as a decimal text.
        Wallet.calls, Wallet.answer = [], (200, {"result": "ab" * 32, "error": None, "id": "buy_taker"})
        world = world_and_watch(lambda world: world.pay(1, 5000), 3)
        code, text, posted = self.run_script(buy_taker, world, arguments, seed=BUYER)
        self.assertEqual((code, len(posted)), (0, 1), text)
        self.assertEqual(Wallet.calls, [("Basic " + base64.b64encode(b"__cookie__:not-a-real-password-0123456789").decode(), {"jsonrpc": "1.0", "id": "buy_taker", "method": "sendtoaddress", "params": [ADDRESS[ORDER_SCRIPTS[0]], "0.00005000"]})])
        self.assertIsInstance(Wallet.calls[0][1]["params"][1], str)
        self.assertIn("The node wallet sent 0.00005000 BTC in transaction " + "ab" * 32, text)
        self.assertNotIn("not-a-real-password", text)
        # The fill names another address than the order showed: nothing is paid, by anyone.
        for change, at, words in (
            (lambda world: world.fills[1].__setitem__("script", SPARE[0]), 1, "PAY NOTHING"),
            (lambda world: world.fills[1].__setitem__("to", "8"), 1, "PAY NOTHING"),
            (lambda world: world.fills[1].__setitem__("payer", "8"), 1, "is not paid by this account"),
            (lambda world: world.fills[1].__setitem__("script", SPARE[0]), 2, "PAY NOTHING"),          # between the two reads
            (lambda world: world.pay(1, 2000), 2, "changed while it was being read: nothing was paid"),   # somebody paid a part meanwhile
        ):
            Wallet.calls = []
            world = world_and_watch(change, at)
            code, text, posted = self.run_script(buy_taker, world, arguments, seed=BUYER)
            self.assertEqual(len(posted), 1, "the take was made")
            self.assertIn(code, (2, 3), text)
            self.assertIn(words, text)
            self.assertEqual(Wallet.calls, [], "the node wallet was never asked")
        # The node wallet says no: nothing was paid, and the script says so. No answer: it may have been sent, and nothing is sent again.
        for answer, code_wanted, words in (((500, {"result": None, "error": {"code": -6, "message": "Insufficient funds"}}), 2, "refused the payment, and nothing was paid: Insufficient funds"), ((401, {}), 2, "refused the cookie"), ((500, {"result": None}), 3, "the payment may have been sent"), ((200, {"result": 5}), 3, "the payment may have been sent")):
            Wallet.calls, Wallet.answer = [], answer
            world = world_and_watch(lambda world: None, 99)
            code, text, posted = self.run_script(buy_taker, world, arguments, seed=BUYER)
            self.assertEqual((code, len(Wallet.calls)), (code_wanted, 1), text)
            self.assertIn(words, text)
        # A node on another machine over plain http is refused before anything is sent to it; the take is not made either way round.
        Wallet.calls = []
        world = world_and_watch(lambda world: None, 99)
        code, text, posted = self.run_script(buy_taker, world, arguments[:-4] + ["--pay-with-bitcoin-rpc", "http://node.example:18443/", "--bitcoin-cookie-file", cookie], seed=BUYER)
        self.assertEqual((code, Wallet.calls), (2, []), text)
        self.assertIn("http:// on this machine or https://", text)

    def test_an_address_is_listed_once_and_a_file_that_ran_out_stops_the_script(self):
        world = vector_world()
        maker = lambda file, price, more=(): ["--account", "5", "--address-file", file, "--amount", "20", "--price", price, "--scripts", "2", "--rounds", "1", "--act", *more]
        # Fewer free addresses than the order needs: nothing is sent, nothing is marked.
        file = self.addresses(SPARE[:1])
        code, text, posted = self.run_script(sell_maker, world, maker(file, "260000000"), seed=SELLER)
        self.assertEqual((code, posted), (2, []), text)
        self.assertIn("The address file has run out: 2 free addresses are needed and 1 are left", text)
        self.assertNotIn("used", Path(file).read_text(encoding="utf-8"))
        # The same address on two lines: refused with both line numbers, before anything is read from the network.
        file = self.addresses([SPARE[0], SPARE[1], SPARE[0]])
        code, text, posted = self.run_script(sell_maker, world, maker(file, "260000000"), seed=SELLER)
        self.assertEqual((code, posted), (2, []), text)
        self.assertIn("Line 4 of the address file repeats the address of line 2", text)
        # Not an address of this network, or of a form the market does not take: refused with its line.
        Path(file).write_text(ADDRESS[SPARE[0]] + "\nbc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\n", encoding="utf-8")
        code, text, posted = self.run_script(sell_maker, world, maker(file, "260000000"), seed=SELLER)
        self.assertEqual((code, posted), (2, []), text)
        self.assertIn("Line 2 of the address file is not an address this market can list on regtest", text)
        # Two orders, one after the other: the second never lists an address of the first, and what the chain already knows is passed over.
        file = self.addresses([ORDER_SCRIPTS[0]] + SPARE[:4])  # the first line is an address order 1 lists already
        code, text, first = self.run_script(sell_maker, world, maker(file, "260000000"), seed=SELLER)
        code, text, second = self.run_script(sell_maker, world, maker(file, "270000000"), seed=SELLER)
        listed = [wire.decode_action(action)["payload"]["scripts"] for action in first + second]
        self.assertEqual(listed, [SPARE[:2], SPARE[2:4]])
        lines = Path(file).read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[1], ADDRESS[ORDER_SCRIPTS[0]] + " used the chain already knows it")
        self.assertTrue(all(" used sell order of account 5" in line for line in lines[2:6]))
        # Now the file is used up: a third order is refused, and no address is taken twice to make it.
        code, text, posted = self.run_script(sell_maker, world, maker(file, "280000000"), seed=SELLER)
        self.assertEqual((code, posted), (2, []), text)
        self.assertIn("The address file has run out", text)
        # An address marked in the file is not handed out by a second object either, and a chain's refusal wastes it rather than reusing it.
        world.security[5]["allowance_micros"] = "0"
        file = self.addresses(SPARE[4:6])
        code, text, posted = self.run_script(sell_maker, world, maker(file, "290000000"), seed=SELLER)
        self.assertEqual(code, 2, text)
        self.assertIn("left of it now", text)
        self.assertEqual(bot.AddressFile(file, "regtest").free(), 2, "refused before the addresses were taken")

    # ------------------------------------------------------------ sending: once, the same bytes, and never a second signature
    def test_a_lost_answer_sends_the_same_bytes_again_and_an_action_in_no_block_stops_the_script(self):
        file = self.addresses(SPARE[:4])
        maker = ["--account", "5", "--address-file", file, "--amount", "20", "--price", "260000000", "--scripts", "2", "--rounds", "1", "--act"]
        # The node took the action and the answer was lost (502), twice: the same bytes go three times, and one order exists.
        world = vector_world()
        world.submit_failures = [(502, "node_unavailable"), (503, "busy")]
        code, text, posted = self.run_script(sell_maker, world, maker, seed=SELLER)
        self.assertEqual(code, 0, text)
        self.assertEqual(len(posted), 3)
        self.assertEqual(len(set(posted)), 1, "the same bytes, never a new signature")
        self.assertEqual(len(world.orders), 3)
        # The chain refuses (the daily limit is used up): nothing happened, and the script says the chain's reason.
        world = vector_world()
        world.security[5]["allowance_micros"] = "1000"
        world.security[5]["allowance_elapsed_micros"] = str(world.now)
        code, text, posted = self.run_script(sell_maker, world, maker[:-1], seed=SELLER)  # a dry run does not know what is left of the limit better than the API says
        self.assertEqual((code, posted), (2, []), text)
        self.assertIn("counts 20 s against the daily limit, and 0.001 s is left of it now", text)
        world.accounts[5]["balance"] = 20_000_000  # enough for the order, not for the order and its fee
        world.security[5]["allowance_micros"] = "600000000"
        code, text, posted = self.run_script(sell_maker, world, maker, seed=SELLER)
        self.assertEqual((code, len(posted)), (2, 1), text)
        self.assertIn("Refused, and nothing happened: The node refused the action: insufficient balance", text)
        self.assertEqual(len(world.orders), 2)
        self.assertEqual(bot.AddressFile(file, "regtest").free(), 0, "the two addresses of the refused order are spent, not used again")
        # In no block when the wait is over: the script stops and says the hash. It signs nothing else.
        world = vector_world()
        world.lookups_before_block = 10**6
        maker[maker.index("--address-file") + 1] = self.addresses(SPARE[4:6], "more.txt")
        code, text, posted = self.run_script(sell_maker, world, maker + ["--wait-seconds", "6", "--cancel-on-exit"], seed=SELLER)
        self.assertEqual((code, len(posted)), (3, 1), text)
        self.assertIn("NOT KNOWN: The action " + wire.transaction_hash(posted[0]) + " was sent and is in no checked block after 6 seconds", text)

    # ------------------------------------------------------------ the read-only script
    def test_the_watcher_shows_the_book_and_the_flags_and_writes_csv(self):
        world = vector_world()
        world.apply(bytes.fromhex(VECTOR["take_for_another"]["signed_hex"]))
        world.pay(1, 4000)
        folder = os.path.join(self.folder.name, "csv")
        code, text, posted = self.run_script(watch_market, world, ["--csv-dir", folder, "--candles", "1m"])
        self.assertEqual((code, posted), (0, []), text)
        self.assertIn("The index is clean, as of height", text)
        self.assertIn("consistent: True, tape_reconciled: True", text)
        self.assertIn("Last recorded price: 250 satoshis a second (a record of one fill, not what a second is worth)", text)
        read = lambda name: Path(folder, name).read_text(encoding="utf-8").splitlines()
        self.assertEqual(read("book-sell.csv"), ["order,owner,price,amount_micros,sats,min_sats,confirmations,pay_blocks,deposit_ppm,takes_fill", "1,5,250000000,60000000,15000,1000,1,6,50000,yes"])
        self.assertEqual(read("book-buy.csv")[1], "2,6,250000000,50000000,12500,1000,3,6,100000,yes")
        self.assertEqual(read("depth.csv")[1:], ["sell,250000000,60000000,60000000,15000,1", "buy,250000000,50000000,50000000,12500,1"])
        self.assertEqual(read("trades.csv")[1].split(",")[1:6], ["1", "250000000", "4000", "16000000", "no"])
        self.assertEqual(read("candles.csv")[1].split(",")[2:], ["250000000", "250000000", "250000000", "250000000", "4000", "16000000", "1", "computed"])
        self.assertTrue(all(method == "GET" for method, path in world.requests))
        code, text, _ = self.run_script(watch_market, world, ["--every", "1", "--rounds", "2"])
        self.assertEqual((code, text.count("Sell orders, cheapest first")), (0, 2))
        # An index that is not clean: the numbers are shown, marked, and the exit code says so.
        world.index["tape_reconciled"] = False
        code, text, _ = self.run_script(watch_market, world, [])
        self.assertEqual(code, 2)
        self.assertIn("NOT CLEAN: The API says its index of the market is not to be relied on now (tape_reconciled)", text)
        self.assertIn("Sell orders, cheapest first", text)


class Bot(unittest.TestCase):
    def test_amounts_as_text(self):
        for text, value in (("0", 0), ("300", 300_000_000), ("2.5", 2_500_000), ("0.000001", 1), ("0.25", 250_000), ("12.000000", 12_000_000)):
            self.assertEqual(bot.micros(text), value)
        for bad in ("", "-1", "1.", ".5", "1.0000001", "01", "1e3", "1,5", " 1", 5, 2.5, None):
            with self.assertRaises(ValueError):
                bot.micros(bad)
        self.assertEqual([bot.seconds(value) for value in (0, 1, 2_500_000, 20_000_000)], ["0 s", "0.000001 s", "2.5 s", "20 s"])
        self.assertEqual(bot.price_words(250_000_000), "250 satoshis a second")
        self.assertEqual(bot.price_words(1), "0.000001 satoshis a second")
        self.assertEqual([bot.bitcoin_amount(value) for value in (1, 5000, 10_000, 100_000_000, 2_100_000_000_000_000)], ["0.00000001", "0.00005000", "0.00010000", "1.00000000", "21000000.00000000"])
        for bad in (0, -1, 2.0, "5000", True, 2_100_000_000_000_001):
            with self.assertRaises(ValueError):
                bot.bitcoin_amount(bad)

    def test_the_allowance_is_the_engines_rule(self):
        # v5/src/security.rs, the_daily_limit_refills_evenly_and_never_exceeds_one_day: a limit of 86,400 microseconds, all of it spent at 0.
        def state(now, allowance="0", since="0", limit="86400", waiting=None):
            return {"security": {"policy": {"daily_limit_micros": limit}, "allowance_micros": allowance, "allowance_elapsed_micros": since, "pending_limit": waiting}, "security_clock": {"now_elapsed_micros": str(now)}}
        day = bot.DAY_MICROS
        self.assertEqual([bot.allowance(state(now)) for now in (0, 10**6, day // 2, day, 10 * day)], [0, 1, 43_200, 86_400, 86_400])
        self.assertEqual(bot.allowance(state(day, allowance="0", since=str(day // 2))), 43_200)
        # A raise that has become due: the old limit fills until then, the new one after.
        self.assertEqual(bot.allowance(state(day, waiting={"daily_limit_micros": "172800", "ready_elapsed_micros": str(day // 2)})), 43_200 + 86_400)
        self.assertEqual(bot.allowance(state(day // 4, waiting={"daily_limit_micros": "172800", "ready_elapsed_micros": str(day // 2)})), 21_600)
        self.assertIsNone(bot.allowance({"security": None, "security_clock": {"now_elapsed_micros": "5"}}))
        self.assertIsNone(bot.allowance(state(5) | {"security_clock": None}))

    def test_the_package_still_signs_in_one_place(self):
        # The new module and the examples call wire.sign_action and nothing else that signs.
        import re

        root = Path(bot.__file__).resolve().parents[1]
        for path in [root / "timemarket" / "bot.py", *sorted((root / "examples").glob("*.py"))]:
            self.assertIsNone(re.search(r"\.sign\(|SigningKey|Ed25519PrivateKey|\.reveal\(|seed_from_file|getpass|input\(", path.read_text(encoding="utf-8")), path.name)
        # No example has a default for the account, the API, a ceiling or the key's place.
        for module in (buy_taker, sell_maker, stop_loss):
            parser = module.arguments()
            defaults = {action.dest: action.default for action in parser._actions}
            self.assertEqual([defaults[name] for name in ("api", "account", "max_daily_limit", "max_balance", "bitcoin_network", "key_store", "key_env")], [None] * 7, module.__name__)
            self.assertFalse(defaults["act"])


# ---------------------------------------------------------------- docs/trading.md, held to what it shows
GUIDE = Path(__file__).resolve().parents[3] / "docs" / "trading.md"
SDK_EXAMPLE = Path(__file__).resolve().parents[3] / "client-v4" / "examples" / "market-take.mjs"
# The file of receiving addresses the guide's commands name (addresses.txt): the test vectors' scripts of one repeated byte.
GUIDE_ADDRESSES = ["0014" + "02" * 20, "0014" + "03" * 20, "0014" + "04" * 20, VECTOR["sell"]["payload"]["script"]]
NOT_RUN = ("bitcoin-cli ", "node deploy/market-prover/prove.mjs ")


def guide_blocks(text: str) -> list[dict]:
    """The fenced blocks of the guide, each with its language, its body and, when a ```text block follows it at once, what it says is printed."""
    found = list(re.finditer(r"^```(\w+)\n(.*?)^```$", text, flags=re.S | re.M))
    blocks = []
    for at, block in enumerate(found):
        after = found[at + 1] if at + 1 < len(found) else None
        printed = after.group(2) if after is not None and after.group(1) == "text" and not text[block.end():after.start()].strip() else None
        blocks.append({"language": block.group(1), "body": block.group(2), "printed": printed})
    return blocks


def run_guide(base: str, world: World, address_file: str, blocks: list[dict]) -> list[dict]:
    """Runs every block of the guide that is a command or a script, and returns the blocks with what each really printed (``actual``)."""
    names, modules = {}, {"buy_taker": buy_taker, "sell_maker": sell_maker, "stop_loss": stop_loss, "watch_market": watch_market}
    for block in blocks:
        out = io.StringIO()
        if block["language"] == "python":
            with contextlib.redirect_stdout(out):
                exec(compile(block["body"].replace('"http://127.0.0.1:8930"', repr(base)), "docs/trading.md", "exec"), names)
            block["actual"] = out.getvalue()
        elif block["language"] == "sh":
            if "# not run" in block["body"]:
                commands = [line for line in block["body"].splitlines() if line.strip() and not line.startswith("#")]
                assert commands and all(line.startswith(NOT_RUN) for line in commands), f"a command that is marked as not run, and is not one of those the guide may leave so: {commands}"
                continue
            for line in block["body"].splitlines():
                command, _, comment = line.partition("#")
                words = shlex.split(command)
                if not words or (len(words) == 1 and words[0].startswith("API=")):
                    continue
                if words[:2] == ["curl", "-s"] and len(words) == 3:
                    with urllib.request.urlopen(words[2].replace("$API", base), timeout=10) as answer:
                        assert answer.status == 200 and isinstance(json.loads(answer.read()), dict), line
                elif words[:2] == ["python", "-m"] and words[2].startswith("examples."):
                    arguments = [base if word == "$API" else address_file if word == "addresses.txt" else word for word in words[3:]]
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                        code = modules[words[2].removeprefix("examples.")].main(arguments, sleep=lambda seconds: None)
                    wanted = int(comment.split("exit code")[1]) if "exit code" in comment else 0
                    assert code == wanted, f"{line}\nended with {code}, and the guide says {wanted}:\n{out.getvalue()}"
                else:
                    raise AssertionError(f"The guide has a command this test does not know how to run, and it is not marked as not run: {line}")
            block["actual"] = out.getvalue()
    assert not [method for method, path in world.requests if method != "GET"], "the guide's commands only read"
    return blocks


class Guide(unittest.TestCase):
    def test_every_command_and_every_script_line_of_the_guide_runs_and_prints_what_the_guide_shows(self):
        text = GUIDE.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as folder, FakeApi(guide_world()) as api:
            file = os.path.join(folder, "addresses.txt")
            Path(file).write_text("".join(script_to_address(script, "regtest") + "\n" for script in GUIDE_ADDRESSES), encoding="utf-8")
            blocks = run_guide(api.base, api.world, file, guide_blocks(text))
        ran = [block for block in blocks if "actual" in block]
        self.assertGreaterEqual(len(ran), 20, "the guide lost its commands")
        for block in ran:
            if block["printed"] is not None:
                self.assertEqual(block["actual"], block["printed"], block["body"])
            elif block["language"] == "sh":
                self.assertEqual(block["actual"], "", "what a script command of the guide prints is shown under it:\n" + block["body"])
        self.assertGreaterEqual(sum(block["printed"] is not None for block in ran), 12)
        # The addresses the guide writes out are those of its address file, and the lines of JavaScript it shows are the example's own.
        for script in GUIDE_ADDRESSES:
            self.assertIn(script_to_address(script, "regtest"), text)
        example = SDK_EXAMPLE.read_text(encoding="utf-8")
        shown = [line.split("//")[0].strip() for block in blocks if block["language"] == "js" for line in block["body"].splitlines()]
        self.assertGreaterEqual(len(shown), 3)
        for line in shown:
            self.assertIn(line, example)

    def test_the_numbers_of_the_guide_are_the_packages_and_the_vectors(self):
        from timemarket import amounts

        text, price = GUIDE.read_text(encoding="utf-8"), 250_000_000
        said = lambda sentence: self.assertIn(sentence, text)
        # Section 2: what an amount costs, and what a sum buys.
        for seconds, costs, bitcoin in ((20_000_000, "5,000", "0.00005000"), (40_000_000, "10,000", "0.00010000"), (100_000_000, "25,000", "0.00025000")):
            sats = amounts.sats(seconds, price)
            self.assertEqual((f"{sats:,}", bot.bitcoin_amount(sats)), (costs, bitcoin))
            said(f"| {seconds // 10**6} | 250 satoshis a second | {costs} satoshis | {bitcoin} |")
        self.assertEqual((amounts.sats(999_999, price), amounts.sats(1, 1), bot.bitcoin_amount(250)), (250, 1, "0.00000250"))
        said("| 0.999999 | 250 satoshis a second | 250 satoshis: the same as a whole second | 0.00000250 |")
        self.assertEqual((amounts.bought(10_000, price), amounts.bought(9_999, price)), (40_000_000, 39_996_000))
        said("10,000 satoshis buy 40 seconds at 250 satoshis a second, and 9,999 buy 39.996")
        self.assertEqual((amounts.sats(4_000_000, price), amounts.sats(2_000_000, 500_000_000)), (1000, 1000))
        said("At 250 satoshis a second, 1,000 satoshis are 4 seconds.")
        said("at 250 satoshis a second that is 4 seconds, and at 500 it is 2")
        # The deposit and the bond.
        deposit = lambda amount: max(-(-amount * 50_000 // 10**6), 250_000)
        self.assertEqual([deposit(amount) for amount in (40_000_000, 20_000_000, 4_000_000)], [2_000_000, 1_000_000, 250_000])
        said("a take of 40 seconds locks 2 seconds, a take of 20 locks 1, and a take of 4 locks 0.25")
        self.assertEqual((-(-50_000_000 * 100_000 // 10**6), 5_000_000 * 20_000_000 // 50_000_000), (5_000_000, 2_000_000))
        said("A buy order for 50 seconds at 10% locks 5 seconds. When a seller sells 20 of the 50 into it, 2 seconds of the bond move into that fill")
        # The fees are those the engine took.
        self.assertEqual([VECTOR[name]["fee_micros"] for name in ("sell_order", "new_scripts", "proof_of_a_part", "proof", "buy_order", "take", "sell", "cancel", "expire", "release", "settle")], ["4000", "3000", "4000", "23000"] + ["1000"] * 7)
        self.assertEqual((len(VECTOR["sell_order"]["payload"]["scripts"]), len(VECTOR["new_scripts"]["payload"]["scripts"])), (3, 2))
        self.assertEqual(len(transaction_outputs(VECTOR["proof"]["payload"]["transaction"])), 82, "the payment of the larger proof")
        for sentence in ("3 addresses: 4,000 microseconds", "2 addresses: 3,000 microseconds", "the smallest proof the engine's tests made: 4,000 microseconds; a payment in a transaction with 82 outputs: 23,000"):
            said(sentence)
        self.assertEqual(actions.action_fee(50, actions.sell_order(amount_micros=2_000_000, price=500_000_000, scripts=[SPARE[1]], confirmations=3, pay_blocks=3, min_sats=1000, deposit_ppm=0, min_deposit_micros=0), 1000) + 1000 + 4000, 7000)
        said("The cost is the fees of an order, a take and a proof: 7,000 microseconds with the smallest proof of section 2.")
        # A payment of a part: the engine's own fill before and after.
        part = VECTOR["proof_of_a_part"]["fill"]
        after = amounts.fill_after_payment(int(part["before"]["amount_micros"]), int(part["before"]["sats"]), int(part["before"]["deposit_micros"]), int(part["paid_sats"]))
        self.assertEqual((after["seconds"], after["deposit_back"], {name: str(after[name]) for name in part["after"]}), (16_000_000, 800_000, part["after"]))
        said("A payment of 4,000 satoshis bought 16 seconds and returned 0.8 second of the deposit. The fill then held 24 seconds, 6,000 satoshis to pay and a deposit of 1.2 seconds.")
        self.assertEqual([amounts.part_counts(6000, paid, 1000) for paid in (3000, 1000, 999)] + [amounts.part_counts(1500, paid, 1000) for paid in (750, 749)], [True, True, False, True, False])
        said("With 6,000 satoshis to pay and a smallest trade of 1,000: 3,000 count, 1,000 count, 999 do not. With 1,500 to pay: 750 count (half), 749 do not.")
        # The times, with the numbers of spec/market.md, 2.1 (production: a block of 10 minutes, 16 spare blocks, a grace of 30 minutes).
        earliest = lambda pay_blocks, confirmations: (pay_blocks + 2 * confirmations + 16) * 10 + 30
        self.assertEqual((earliest(3, 3), earliest(6, 3), 6 + 3 - 1), (280, 310, 8))
        said("With 3 blocks to pay and 3 confirmations that is 280 minutes; with 6 and 3, 310 minutes.")
        said("With 6 blocks to pay and 3 confirmations it is 8 above the start.")
        # The take as bytes.
        take = VECTOR["take"]
        self.assertEqual((len(take["signed_hex"]) // 2, len(take["payload_json"]), 19 + 32 + 1 + 24 + 32 + 4 + 63 + 64), (239, 63, 239))
        said("The take of section 3.1 is the entry `take`: 239 bytes, of which 63 are the payload.")


if __name__ == "__main__":
    unittest.main()
