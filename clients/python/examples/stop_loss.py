"""A stop loss that one small trade cannot fire: it watches the book, and sells with a limit price when the trigger holds.

    python -m examples.stop_loss --api http://127.0.0.1:8930 --account 5 --bitcoin-network regtest \\
        --max-daily-limit 600 --max-balance 3000 --address-file addresses.txt \\
        --amount 20 --stop-price 250000000 --limit-price 240000000 --size-floor 20 --key-env TIME_BOT_KEY --act

THE CHAIN HAS NO STOP ORDER, and will not have one (spec/market.md, section 11): it would have to read
its own last price, which costs nothing to move. So the trigger runs here, in your script, and it is
only as good as what it reads.

WHAT IT READS, and why. The last price is what one fill was paid at. Two accounts of one person can
write any price there for a fee, with a trade as small as the market allows. A trigger on it sells
your seconds whenever somebody wants them cheap. This script judges differently:

- ``--trigger book`` (the default): other people's sell orders that take a fill offer at least
  ``--size-floor`` seconds at or under ``--stop-price``. Whoever wants to fire this trigger must put
  that many seconds on the book at that price, where anyone can take them, and leave them there.
- The trigger must hold in ``--confirm-rounds`` readings in a row (default 3), each at a newer height
  of the index. One reading is one block's word.
- ``--trigger trades``: the newest recorded trades that add up to ``--size-floor`` seconds are all at
  or under the stop, and come from at least ``--min-trades`` different fills. Weaker: trades between
  two accounts of one person cost fees only, whatever their size. The floor raises the seconds
  somebody must hold to fake it; it does not make it impossible.
- A trigger that is already met at the first reading is refused (``--allow-immediate`` lifts that):
  it is nearly always a wrong unit or a wrong price.

WHAT IT SENDS, always with a limit. ``--limit-price`` is the least you accept, and the chain never
gives you less: every action names its price.

- If the best buy order of somebody else is at or above the limit, it sells into it (kind 53), to a
  fresh address from your file. The buyer then has to pay; if they do not, the seconds come back
  with their bond's part.
- What is left is offered as a sell order at the limit (kind 50), with fresh addresses.

A false trigger therefore costs at most the difference between what a second is worth to you and
your limit. Nothing else bounds it: choose the limit as if the trigger could be made to fire.

IT NEEDS NO BITCOIN KEY: addresses come from a file, as for the selling bot (see sell_maker.py).
A dry run (the default) does one reading, says what it sees, and sends nothing.
"""
from __future__ import annotations

import argparse
import sys
import time

from timemarket import TimeApi, actions, amounts, bot, script_form
from timemarket.api import ApiError


def arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="stop_loss", description="Sells with a limit price when the book has fallen to a stop price for real size. Dry run unless --act.")
    bot.common_arguments(parser)
    parser.add_argument("--address-file", required=True, metavar="FILE", help="receiving addresses from your own Bitcoin wallet, one on a line; the script marks the ones it used")
    parser.add_argument("--amount", required=True, type=bot.micros, metavar="SECONDS", help="how many seconds to sell when the trigger holds")
    parser.add_argument("--stop-price", required=True, type=int, metavar="P", help="the trigger, in millionths of a satoshi for one second")
    parser.add_argument("--limit-price", required=True, type=int, metavar="P", help="the least you accept, at or under the stop price")
    parser.add_argument("--size-floor", required=True, type=bot.micros, metavar="SECONDS", help="the size the trigger is judged on: less than this on the book, or in trades, decides nothing")
    parser.add_argument("--trigger", choices=("book", "trades"), default="book", help="what is read (default: book)")
    parser.add_argument("--min-trades", type=int, default=3, help="with --trigger trades: the fewest different fills the trades come from (default 3)")
    parser.add_argument("--confirm-rounds", type=int, default=3, metavar="N", help="readings in a row, each at a newer height, in which the trigger must hold (default 3)")
    parser.add_argument("--allow-immediate", action="store_true", help="act even if the trigger is met at the very first reading")
    parser.add_argument("--confirmations", type=int, default=3, help="Bitcoin confirmations you ask of a payment (default 3)")
    parser.add_argument("--pay-blocks", type=int, default=6, help="for the sell order: the time a taker has to pay, in Bitcoin blocks (default 6)")
    parser.add_argument("--min-sats", type=int, default=1000, help="for the sell order: the smallest trade, in satoshis (default 1000)")
    parser.add_argument("--deposit-ppm", type=int, default=50_000, help="for the sell order: the deposit a taker locks, in millionths (default 50000)")
    parser.add_argument("--min-deposit", type=bot.micros, default=bot.micros("1"), metavar="SECONDS", help="for the sell order: the least deposit of a fill (default 1)")
    parser.add_argument("--scripts", type=int, default=4, metavar="N", help="for the sell order: how many addresses it lists, 1 to 16 (default 4)")
    parser.add_argument("--interval", type=int, default=30, metavar="SECONDS", help="the pause between two readings (default 30)")
    parser.add_argument("--rounds", type=int, default=0, metavar="N", help="stop after N readings (default: until the trigger; a dry run does one)")
    return parser


def price_for(orders: list[dict], me: str, floor: int) -> int | None:
    """The price at which ``floor`` microseconds can be had from other people's orders that take a fill, best first; ``None`` when the book holds less."""
    reached = 0
    for order in orders:
        if order["owner"] == me or not order["takes_fill"]:
            continue
        reached += int(order["amount_micros"])
        if reached >= floor:
            return int(order["price"])
    return None


def reading(api, args, me: str) -> tuple[str, bool, str]:
    """One look at the market: (the height it is as of, whether the trigger holds there, a line for the operator)."""
    if args.trigger == "book":
        asks = api.market_orders("sell", limit=200)
        height = bot.check_index(asks)
        price = price_for(asks["items"], me, args.size_floor)
        if price is None:
            return height, False, f"the book offers less than {bot.seconds(args.size_floor)} from others: no price for that size, and nothing is decided"
        return height, price <= args.stop_price, f"{bot.seconds(args.size_floor)} can be had from other people's sell orders at {bot.price_words(price)} or less"
    trades = api.market_trades(limit=200)
    height = bot.check_index(trades)
    seen, fills, prices = 0, set(), []
    for trade in trades["items"]:  # newest first
        if trade["seconds_micros"] is None or trade["price"] is None:
            continue  # an entry the index could not value says nothing
        seen += int(trade["seconds_micros"])
        fills.add(trade["fill"])
        prices.append(int(trade["price"]))
        if seen >= args.size_floor and len(fills) >= args.min_trades:
            break
    if seen < args.size_floor or len(fills) < args.min_trades:
        return height, False, f"the newest trades add up to {bot.seconds(seen)} from {len(fills)} fills: too little to decide on"
    return height, max(prices) <= args.stop_price, f"the newest {len(prices)} trades ({bot.seconds(seen)}, {len(fills)} fills) were at {bot.price_words(min(prices))} to {bot.price_words(max(prices))}"


def sell(api, sender, addresses, args, me: str, facts: dict, market: dict, sleep) -> int:
    """The trigger holds: sell into the best buy order at or above the limit, and offer what is left at the limit."""
    left = args.amount
    if left > facts["balance"]:
        raise bot.Refusal(f"The account holds {bot.seconds(facts['balance'])}, less than the {bot.seconds(left)} to sell")
    if facts["allowance"] is not None and left > facts["allowance"]:
        raise bot.Refusal(f"Selling {bot.seconds(left)} counts that much against the daily limit, and {bot.seconds(facts['allowance'])} is left of it now")
    is_free = lambda script: api.market_script(script)["status"] == "free"
    bids = api.market_orders("buy", limit=50)
    bot.check_index(bids)
    listed = next((order for order in bids["items"] if order["owner"] != me and order["takes_fill"]), None)
    if listed is not None and int(listed["price"]) >= args.limit_price:
        read = api.market_order(listed["id"])  # the order itself, from the current state, just before acting
        order = read["order"]
        if any(order[name] != listed[name] for name in ("id", "side", "owner", "price")) or order["side"] != "buy":
            raise bot.Refusal(f"Order {listed['id']} is not what the list said (it changed between the list and its own row, or the list is wrong): nothing is sold into it")
        price, amount = int(order["price"]), min(left, int(order["amount_micros"]))
        cost, rest = amounts.sats(amount, price), int(order["amount_micros"]) - amount
        can_pay = lambda script: script_form(script) in order["forms"]  # the forms of address this buyer can pay to
        fits = (order["open"] and read["takes_fill"] is True and read["owner_stands"]["stands"] is not False and int(order["confirmations"]) >= args.confirmations and bool(addresses.forms() & set(order["forms"]))
                and (cost >= int(order["min_sats"]) or (rest == 0 and cost >= int(market["rules"]["minSats"]))) and (rest == 0 or amounts.sats(rest, price) >= int(order["min_sats"])))
        if fits:
            bot.check_bitcoin(market, args.bitcoin_network)  # a new fill needs a header chain that is not stale
            taken = addresses.take(1, f"a sale to buy order {order['id']}", write=args.act, is_free=is_free, only=can_pay)[0]
            print(f"Buy order {order['id']} of account {order['owner']} pays {bot.price_words(price)}, at or above your limit: selling {bot.seconds(amount)} into it for {cost} satoshis ({bot.bitcoin_amount(cost)} BTC),")
            print(f"  to be paid to {taken['address']} with {args.confirmations} confirmations. The seconds leave the balance now; if the buyer does not pay, they come back with the buyer's bond for them.")
            answer = sender.send(53, actions.sell(order=order["id"], amount_micros=amount, price=price, confirmations=args.confirmations, script=taken["script"]), f"a sale of {bot.seconds(amount)} to buy order {order['id']}")
            if answer is not None:
                fill = bot.fill_made(api, args.account, order=order["id"], height=answer["action"]["height"], role="owner", sleep=sleep)
                print(f"  The sale is fill {fill['id']}: {fill['sats']} satoshis are to arrive at that address by Bitcoin height {fill['last_height']}.")
            left -= amount
        else:
            print(f"Buy order {order['id']} pays enough, and does not fit (it waits for fewer confirmations than you ask, it cannot pay to any form of address your file holds, the amount is against its smallest trade, or it takes no fill now): nothing is sold into it.")
    else:
        print("No buy order of somebody else is at or above your limit.")
    if left:
        cost = amounts.sats(left, args.limit_price)
        if cost < args.min_sats:
            print(f"{bot.seconds(left)} are left, worth {cost} satoshis at the limit: less than the smallest trade of an order, so nothing more is offered.")
            return 0
        taken = addresses.take(args.scripts, "a sell order at the limit", write=args.act, is_free=is_free)
        print(f"Offering {bot.seconds(left)} at your limit, {bot.price_words(args.limit_price)} ({cost} satoshis in all), paid to:")
        for entry in taken:
            print(f"  {entry['address']}")
        sender.send(50, actions.sell_order(amount_micros=left, price=args.limit_price, scripts=[entry["script"] for entry in taken], confirmations=args.confirmations, pay_blocks=args.pay_blocks, min_sats=args.min_sats,
                                           deposit_ppm=args.deposit_ppm, min_deposit_micros=args.min_deposit), f"a sell order of {bot.seconds(left)} at {bot.price_words(args.limit_price)}")
    return 0


def run(args, sleep) -> int:
    if not 1 <= args.limit_price <= args.stop_price:
        raise bot.Refusal("--limit-price is the least you accept: it is at or under --stop-price, and at least 1")
    if args.confirm_rounds < 1 or not 1 <= args.scripts <= 16 or args.size_floor < 1:
        raise bot.Refusal("--confirm-rounds is at least 1, --scripts from 1 to 16, --size-floor above nothing")
    api, me = TimeApi(args.api), str(args.account)
    seed = bot.key_from(args)  # only from the key store or the environment, under the names you gave
    sender = bot.Sender(api, account=args.account, seed=seed, act=args.act, sleep=sleep, wait_seconds=args.wait_seconds)
    addresses = bot.AddressFile(args.address_file, args.bitcoin_network)
    rounds = args.rounds or (0 if args.act else 1)  # a dry run does one reading
    print(f"stop_loss: account {me}, {bot.seconds(args.amount)}; stop {bot.price_words(args.stop_price)}, limit {bot.price_words(args.limit_price)}; judged on the {args.trigger} for {bot.seconds(args.size_floor)}; {'ACTING' if args.act else 'DRY RUN'}")
    held, last_height, done = 0, None, 0
    try:
        while True:
            state = api.account_state(args.account)
            facts = bot.check_account(state, most_daily_limit_micros=args.max_daily_limit, most_balance_micros=args.max_balance)
            if seed is not None:
                bot.check_key(state, seed)
            market = api.market()
            bot.check_index(market)
            bot.check_bitcoin(market, args.bitcoin_network, new_fill=False)
            try:
                height, met, line = reading(api, args, me)
            except ApiError as error:
                if error.status not in (None, 429, 502, 503):
                    raise
                height, met, line = last_height, False, f"the API did not answer ({error}): a reading that is missing decides nothing"
            if met and done == 0 and not args.allow_immediate:
                raise bot.Refusal(f"The trigger is met at the first reading ({line}; your stop is {bot.price_words(args.stop_price)}). That is nearly always a wrong unit or a wrong price: nothing is sold. If you mean it, run again with --allow-immediate")
            # A reading counts once for each height of the index: the same answer twice is one reading.
            held = 0 if not met else held + 1 if height != last_height else max(held, 1)
            last_height, done = height, done + 1
            print(f"As of height {height}: {line}. The trigger {'holds' if met else 'does not hold'}" + (f" ({held} of {args.confirm_rounds} readings in a row)." if met else "."))
            if held >= args.confirm_rounds:
                return sell(api, sender, addresses, args, me, facts, market, sleep)
            if rounds and done >= rounds:
                return 0
            sleep(args.interval)
    except KeyboardInterrupt:
        print("Stopped. Nothing is on the book for this script: a stop loss that is not running does not fire.")
        return 0


def main(argv=None, *, sleep=time.sleep) -> int:
    args = arguments().parse_args(argv)
    return bot.outcome(lambda: run(args, sleep))


if __name__ == "__main__":
    sys.exit(main())
