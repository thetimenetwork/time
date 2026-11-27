"""Takes the best sell order at or under your limit price, says exactly what to pay and where, and waits for the fill to be paid.

    python -m examples.buy_taker --api http://127.0.0.1:8930 --account 6 --bitcoin-network regtest \\
        --max-daily-limit 600 --max-balance 3000 --amount 20 --limit-price 250000000 --key-env TIME_BOT_KEY --act

IT HOLDS NO BITCOIN KEY. Paying is your own step: the script prints the address and the amount, read
again from the fill, and the ``bitcoin-cli sendtoaddress`` line for a node wallet you run. With
``--pay-with-bitcoin-rpc URL --bitcoin-cookie-file FILE`` it asks that node wallet to send the
payment itself, once, with the amount as an exact decimal text. Keep little in that wallet.

What it does:

1. Reads its account and refuses to go on unless the account has the security rules, a daily limit
   and a balance under your two ceilings.
2. Reads the sell side of the book (the index's word; refused unless the index is clean) and picks
   the first order of somebody else that takes a fill. If its price is above ``--limit-price`` it stops.
3. Reads that order by itself and refuses if it is not what the list said, if its owner does not
   stand, or if its terms are outside yours (confirmations, time to pay, deposit).
4. Takes it (kind 52): you promise the bitcoin and lock the deposit. The satoshis are computed from
   the order's price and signed; the chain refuses the take if they are not the price of the amount.
5. Finds the fill, READS IT AGAIN, checks that it is yours and that its address is one the order
   showed, and prints what to pay. Then it asks the fill again every ``--interval`` seconds until
   it has ended, and says how.

SOMEBODY HAS TO PROVE THE PAYMENT. The chain hands the seconds over when it is shown a proof of the
payment (kind 54), and this script sends none. A prover service does (deploy/market-prover/README.md),
or you do, with a Bitcoin node of your own: ``node deploy/market-prover/prove.mjs CONFIG --fill N``.
A payment that is not proven before the fill ends has bought nothing.

WHAT THE API COULD DO TO THIS SCRIPT. It cannot verify a proof. An API that lies can name an address
of its own for the fill, and the bitcoin you pay there is gone. Call an API you run yourself.

``--fill N`` watches a fill you already have, without taking anything. It never pays: if you have
paid already, a second payment buys nothing.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from timemarket import TimeApi, actions, amounts, bot, script_to_address
from timemarket.api import ApiError


def arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="buy_taker", description="Takes the best sell order at or under a limit price and says what to pay. Dry run unless --act.")
    bot.common_arguments(parser)
    parser.add_argument("--amount", type=bot.micros, metavar="SECONDS", help="how many seconds to buy")
    parser.add_argument("--limit-price", type=int, metavar="P", help="the most you pay, in millionths of a satoshi for one second (250 satoshis a second is 250000000)")
    parser.add_argument("--to", type=int, metavar="NUMBER", help="the account the seconds go to (default: --account)")
    parser.add_argument("--max-confirmations", type=int, default=6, help="pass over an order that asks more Bitcoin confirmations than this (default 6)")
    parser.add_argument("--min-pay-blocks", type=int, default=3, help="pass over an order that gives fewer Bitcoin blocks to pay than this (default 3)")
    parser.add_argument("--max-deposit", type=bot.micros, metavar="SECONDS", help="the largest deposit you lock (default: a tenth of the amount)")
    parser.add_argument("--fill", type=int, metavar="N", help="watch this fill of yours and take nothing")
    parser.add_argument("--pay-with-bitcoin-rpc", metavar="URL", help="ask the wallet of a Bitcoin Core node you run to send the payment (http:// on this machine, or https://)")
    parser.add_argument("--bitcoin-cookie-file", metavar="FILE", help="the .cookie file of that node, read when the payment is sent")
    parser.add_argument("--interval", type=int, default=30, metavar="SECONDS", help="how often the fill is read while it is open (default 30)")
    parser.add_argument("--watch-seconds", type=int, default=0, metavar="N", help="stop watching after this long (default: until the fill ends)")
    return parser


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def send_bitcoin(url: str, cookie_file: str, address: str, amount: str) -> str:
    """Asks a Bitcoin Core wallet to pay ``amount`` bitcoin (a decimal text, never a float) to ``address``. Returns the transaction id.

    One request, never repeated. ``bot.Refusal``: the node said no and nothing was paid.
    ``bot.NotKnown``: no usable answer, so the payment may have been sent: look in the wallet before
    paying again. Nothing of the cookie is printed or put in a message.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.username or parts.password or not (parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"))):
        raise bot.Refusal("The Bitcoin node's RPC is http:// on this machine or https://, without a user name in the address: its password would cross the network in the clear")
    with open(cookie_file, "r", encoding="utf-8") as file:
        cookie = file.read().strip()
    body = json.dumps({"jsonrpc": "1.0", "id": "buy_taker", "method": "sendtoaddress", "params": [address, amount]}).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json", "Authorization": "Basic " + base64.b64encode(cookie.encode("utf-8")).decode("ascii")})
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=30) as answer:
            said = json.loads(answer.read(1_000_000).decode("utf-8"))
    except urllib.error.HTTPError as error:
        with error:
            raw = error.read(1_000_000)
        if error.code in (401, 403):
            raise bot.Refusal("The Bitcoin node refused the cookie: nothing was paid") from None
        try:
            message = str(json.loads(raw.decode("utf-8"))["error"]["message"])[:120]
        except (ValueError, KeyError, TypeError):
            raise bot.NotKnown(f"The Bitcoin node answered {error.code} without saying why: the payment may have been sent. Look in the wallet (listtransactions) before you pay again") from None
        raise bot.Refusal(f"The Bitcoin wallet refused the payment, and nothing was paid: {message}") from None
    except (urllib.error.URLError, OSError, ValueError):
        raise bot.NotKnown("No usable answer from the Bitcoin node: the payment may have been sent. Look in the wallet (listtransactions) before you pay again") from None
    txid = said.get("result") if isinstance(said, dict) else None
    if not isinstance(txid, str) or len(txid) != 64:
        raise bot.NotKnown("The Bitcoin node's answer is not a transaction id: the payment may have been sent. Look in the wallet before you pay again")
    return txid


def read_fill(api, number, *, me: str, to: str | None = None, order: str | None = None, price: str | None = None, scripts=None) -> dict:
    """The fill as the current state holds it, read now, and refused unless it is the fill this script means."""
    answer = api.market_fill(number)
    fill = answer["fill"]
    if fill["payer"] != me:
        raise bot.Refusal(f"Fill {number} is not paid by this account: nothing is paid to it")
    wrong = [name for name, wanted in (("to", to), ("order", order), ("price", price)) if wanted is not None and fill[name] != wanted]
    if scripts is not None and fill["script"] not in scripts:
        wrong.append("script")
    if wrong:
        raise bot.NotKnown(f"Fill {number} is not what this script made ({', '.join(wrong)} differ): PAY NOTHING. Read the fill and the order from an API you trust")
    return answer


def say_what_to_pay(answer: dict, network: str) -> tuple[str, int]:
    fill = answer["fill"]
    address, sats = script_to_address(fill["script"], network), int(fill["sats"])
    known = (answer.get("bitcoin") or {}).get("best_height")
    print(f"Fill {fill['id']}: {bot.seconds(int(fill['amount_micros']))} for account {fill['to']}, at {bot.price_words(int(fill['price']))}.")
    print(f"  PAY {sats} satoshis ({bot.bitcoin_amount(sats)} BTC) to {address}")
    print(f"  Confirmations asked: {fill['confirmations']}, reached by Bitcoin height {answer['last_height']} at the latest" + (f"; the chain knows height {known} now" if known is not None else "") + ". Pay now, with a fee that confirms in the next block.")
    print(f"  With a node wallet of yours:  bitcoin-cli -{'regtest' if network == 'regtest' else 'testnet'} sendtoaddress \"{address}\" {bot.bitcoin_amount(sats)}")
    print("  Pay from a wallet whose transaction you control. A withdrawal from an exchange can come late, short, or in a transaction too large to prove.")
    print(f"  Then the payment must be proven to the chain: a prover service does it, or you do (node deploy/market-prover/prove.mjs CONFIG --fill {fill['id']}).")
    return address, sats


def watch(api, number: int, me: str, args, sleep) -> int:
    last, rounds, done = None, (max(1, args.watch_seconds // max(1, args.interval)) if args.watch_seconds else 0), 0  # 0: until the fill ends
    while True:
        try:
            fill = read_fill(api, number, me=me)["fill"]
        except ApiError as error:
            if error.status in (None, 429, 502, 503):  # no answer now: the fill is asked again
                print(f"The API did not answer ({error}); asking again.")
                sleep(args.interval)
                continue
            if error.code != "fill_not_found":
                raise
            how = (((error.body or {}).get("indexed") or {}).get("ended") or {}).get("how")
            if how in ("paid", "settled"):
                print(f"Fill {number} has ended: {how}. The seconds are in the account they were bought for; the deposit is back.")
                return 0
            print(f"Fill {number} has ended without being paid in full ({how or 'the API does not say how'}). What it still held went back to the seller, with what was left of the deposit. A payment that confirms now buys nothing.")
            return 4
        if fill["sats"] != last:
            print(f"Fill {number} is open: {fill['sats']} satoshis are still to pay for {bot.seconds(int(fill['amount_micros']))}." + ("" if last is None else " A part was paid and counted."))
            last = fill["sats"]
        done += 1
        if rounds and done >= rounds:
            print(f"Fill {number} is still open, and this script stops watching. Run it again with --fill {number} to go on; that never pays.")
            return 4
        sleep(args.interval)


def run(args, sleep) -> int:
    if args.fill is None and (args.amount is None or args.limit_price is None):
        raise bot.Refusal("Give --amount and --limit-price to take an order, or --fill to watch a fill you have")
    if bool(args.pay_with_bitcoin_rpc) != bool(args.bitcoin_cookie_file):
        raise bot.Refusal("--pay-with-bitcoin-rpc and --bitcoin-cookie-file go together")
    if args.pay_with_bitcoin_rpc and args.fill is not None:
        raise bot.Refusal("With --fill the script never pays: it cannot know whether you have paid already, and a second payment buys nothing")
    api, me = TimeApi(args.api), str(args.account)
    to = str(args.account if args.to is None else args.to)
    seed = bot.key_from(args)  # only from the key store or the environment, under the names you gave
    print(f"buy_taker: account {me}; {'ACTING' if args.act else 'DRY RUN'}")

    # 1. The account, read now.
    state = api.account_state(args.account)
    facts = bot.check_account(state, most_daily_limit_micros=args.max_daily_limit, most_balance_micros=args.max_balance)
    if seed is not None:
        bot.check_key(state, seed)
    market = api.market()
    bot.check_index(market)
    bot.check_bitcoin(market, args.bitcoin_network, new_fill=args.fill is None)

    if args.fill is not None:
        say_what_to_pay(read_fill(api, args.fill, me=me), args.bitcoin_network)
        print("  IF YOU HAVE PAID ALREADY, DO NOT PAY AGAIN: what is paid above what the fill needs buys nothing.")
        return watch(api, args.fill, me, args, sleep)

    # 2. The book: the index's word. The best order of somebody else that takes a fill.
    book = api.market_orders("sell", limit=50)
    bot.check_index(book)
    listed = next((order for order in book["items"] if order["owner"] != me and order["takes_fill"]), None)
    if listed is None:
        raise bot.Refusal("No sell order of somebody else takes a fill now")
    if int(listed["price"]) > args.limit_price:
        raise bot.Refusal(f"The best sell order asks {bot.price_words(int(listed['price']))}, above your limit of {bot.price_words(args.limit_price)}: nothing is taken")

    # 3. The order itself, from the current state, just before acting.
    read = api.market_order(listed["id"])
    order = read["order"]
    if any(order[name] != listed[name] for name in ("id", "side", "owner", "price")) or order["side"] != "sell":
        raise bot.Refusal(f"Order {listed['id']} is not what the list said (it changed between the list and its own row, or the list is wrong): nothing is taken")
    if not order["open"] or read["takes_fill"] is not True or read["owner_stands"]["stands"] is False:
        raise bot.Refusal(f"Order {order['id']} takes no fill now: it is closed, has no free address, or its owner does not stand")
    price, amount = int(order["price"]), min(args.amount, int(order["amount_micros"]))
    if amount < args.amount:
        print(f"Order {order['id']} offers {bot.seconds(amount)}, less than the {bot.seconds(args.amount)} you asked: taking what it offers.")
    sats, rest = amounts.sats(amount, price), int(order["amount_micros"]) - amount
    if sats < int(order["min_sats"]) and not (rest == 0 and sats >= int(market["rules"]["minSats"])):
        raise bot.Refusal(f"{bot.seconds(amount)} cost {sats} satoshis, less than the order's smallest trade ({order['min_sats']})")
    if rest and amounts.sats(rest, price) < int(order["min_sats"]):
        raise bot.Refusal(f"What would stay on offer ({bot.seconds(rest)}) costs less than the order's smallest trade: take all {bot.seconds(int(order['amount_micros']))}, or less")
    deposit = max(-(-amount * int(order["deposit_ppm"]) // 10**6), int(order["min_deposit_micros"]))
    if int(order["confirmations"]) > args.max_confirmations or int(order["pay_blocks"]) < args.min_pay_blocks:
        raise bot.Refusal(f"Order {order['id']} asks {order['confirmations']} confirmations and gives {order['pay_blocks']} Bitcoin blocks to pay: outside what you allow")
    if deposit > (amount // 10 if args.max_deposit is None else args.max_deposit):
        raise bot.Refusal(f"Order {order['id']} asks a deposit of {bot.seconds(deposit)}, more than you allow (--max-deposit): you would lose it if the payment came late")
    if deposit > facts["balance"] or (facts["allowance"] is not None and deposit > facts["allowance"]):
        raise bot.Refusal(f"The deposit of {bot.seconds(deposit)} is more than the account holds, or more than is left of its daily limit now")
    free = [entry["script"] for entry in order["scripts"] if "fill" not in entry and not entry.get("used")]

    # 4. The take. `sats` is computed from the order's price by actions.take and signed.
    payload = actions.take(order=order["id"], amount_micros=amount, price=price, to=to)
    print(f"Order {order['id']} of account {order['owner']}: {bot.seconds(amount)} at {bot.price_words(price)} cost {sats} satoshis ({bot.bitcoin_amount(sats)} BTC).")
    print(f"  A deposit of {bot.seconds(deposit)} is locked. It comes back as the fill is paid, and goes to the seller for what is not paid in time.")
    print(f"  Confirmations the seller asks: {order['confirmations']}. Time to pay: {order['pay_blocks']} Bitcoin blocks from the take.")
    answer = bot.Sender(api, account=args.account, seed=seed, act=args.act, sleep=sleep, wait_seconds=args.wait_seconds).send(52, payload, f"a take of {bot.seconds(amount)} from order {order['id']}, for account {to}")
    if answer is None:
        print(f"  The fill would get the order's first free address: {script_to_address(free[0], args.bitcoin_network)}. It is read from the fill before anything is paid.")
        return 0

    # 5. The fill, read from the current state: what to pay is what the fill says now, never what was computed before.
    number = int(bot.fill_made(api, args.account, order=order["id"], height=answer["action"]["height"], role="payer", sleep=sleep)["id"])
    mine = dict(me=me, to=to, order=order["id"], price=order["price"], scripts=free)
    address, owed = say_what_to_pay(read_fill(api, number, **mine), args.bitcoin_network)
    if args.pay_with_bitcoin_rpc:
        again = read_fill(api, number, **mine)["fill"]  # once more, at the moment of paying
        if script_to_address(again["script"], args.bitcoin_network) != address or int(again["sats"]) != owed:
            raise bot.NotKnown(f"Fill {number} changed while it was being read: nothing was paid. Run again with --fill {number} and pay by hand")
        txid = send_bitcoin(args.pay_with_bitcoin_rpc, args.bitcoin_cookie_file, address, bot.bitcoin_amount(owed))
        print(f"  The node wallet sent {bot.bitcoin_amount(owed)} BTC in transaction {txid}. This script will not pay this fill again.")
    return watch(api, number, me, args, sleep)


def main(argv=None, *, sleep=time.sleep) -> int:
    args = arguments().parse_args(argv)
    return bot.outcome(lambda: run(args, sleep))


if __name__ == "__main__":
    sys.exit(main())
