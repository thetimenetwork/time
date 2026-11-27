"""Keeps one sell order at a price you give, and feeds it receiving addresses from a file you made.

    python -m examples.sell_maker --api http://127.0.0.1:8930 --account 5 --bitcoin-network regtest \\
        --max-daily-limit 600 --max-balance 3000 --address-file addresses.txt \\
        --amount 100 --price 250000000 --scripts 3 --key-env TIME_BOT_KEY --act

IT NEEDS NO BITCOIN KEY. The addresses come from your own Bitcoin wallet, on another machine: one on a
line, each receiving nothing else, each listed once, ever. The script marks an address in the file
before it lists it, and stops asking for more when the file runs out. Buyers pay those addresses; the
script never sees the bitcoin and cannot spend it.

What it does each round:

1. Reads its account and refuses to go on unless the account has the security rules, a daily limit
   and a balance under your two ceilings, and the key is a spending key of it.
2. Reads the market and refuses to go on unless the API says its index is clean.
3. Finds its open sell order at ``--price`` (the list is the index's word), and reads the order itself.
   With none, it makes one of ``--amount`` seconds with ``--scripts`` addresses.
4. With ``--expire-unpaid``, ends fills of the order whose time has passed (kind 55): the seconds
   return to the order and the taker's deposit comes to you.
5. When fewer than ``--min-free`` addresses of the order are free, gives it new ones (kind 58).

THE DAILY LIMIT COUNTS EVERY ONE OF THESE (spec/market.md, section 7): a new order counts its seconds,
and new addresses count the order's seconds AGAIN. With a limit of 600 seconds you offer at most 600
seconds a day. So list enough addresses when the order is made (``--scripts``, at most 16), and ask a
least deposit (``--min-deposit``) that makes it costly for others to use them up.

A dry run (the default) does one round, prints what it would send and sends nothing.
"""
from __future__ import annotations

import argparse
import sys
import time

from timemarket import TimeApi, actions, amounts, bot
from timemarket.api import ApiError


def arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sell_maker", description="Keeps one sell order at a price you give, fed with receiving addresses from a file. Dry run unless --act.")
    bot.common_arguments(parser)
    parser.add_argument("--address-file", required=True, metavar="FILE", help="receiving addresses from your own Bitcoin wallet, one on a line; the script marks the ones it used")
    parser.add_argument("--price", required=True, type=int, metavar="P", help="the limit price, in millionths of a satoshi for one second (250 satoshis a second is 250000000)")
    parser.add_argument("--amount", required=True, type=bot.micros, metavar="SECONDS", help="what the order offers when the script makes it")
    parser.add_argument("--scripts", type=int, default=8, metavar="N", help="addresses the order lists, 1 to 16 (default 8): one for each fill it can have")
    parser.add_argument("--min-free", type=int, default=1, metavar="N", help="give the order new addresses when fewer than this are free (default 1)")
    parser.add_argument("--confirmations", type=int, default=3, help="Bitcoin confirmations you ask of every payment (default 3)")
    parser.add_argument("--pay-blocks", type=int, default=6, help="the time a taker has to pay, in Bitcoin blocks (default 6)")
    parser.add_argument("--min-sats", type=int, default=1000, help="the smallest trade, in satoshis (default 1000)")
    parser.add_argument("--deposit-ppm", type=int, default=50_000, help="the deposit a taker locks, in millionths of what they take (default 50000, 5%%)")
    parser.add_argument("--min-deposit", type=bot.micros, default=bot.micros("1"), metavar="SECONDS", help="the least deposit of a fill (default 1)")
    parser.add_argument("--expire-unpaid", action="store_true", help="end fills of the order whose time has passed, as the chain allows it")
    parser.add_argument("--renew", action="store_true", help="make a new order when the old one is sold (default: stop)")
    parser.add_argument("--cancel-on-exit", action="store_true", help="take the order back when the script stops")
    parser.add_argument("--interval", type=int, default=30, metavar="SECONDS", help="the pause between two rounds (default 30)")
    parser.add_argument("--rounds", type=int, default=0, metavar="N", help="stop after N rounds (default: until stopped; a dry run does one)")
    return parser


def within_limit(facts: dict, counted: int, what: str) -> None:
    """Refuses what the chain would refuse: more than the account holds, or more than is left of the day's limit."""
    if counted > facts["daily_limit"]:
        raise bot.Refusal(f"{what} counts {bot.seconds(counted)} against the daily limit, which is {bot.seconds(facts['daily_limit'])}: it can never pass. Make the order smaller")
    if facts["allowance"] is not None and counted > facts["allowance"]:
        raise bot.Refusal(f"{what} counts {bot.seconds(counted)} against the daily limit, and {bot.seconds(facts['allowance'])} is left of it now: wait for it to refill (it refills evenly over 24 hours)")


def run(args, sleep) -> int:
    if not 1 <= args.scripts <= 16 or not 1 <= args.min_free <= args.scripts:
        raise bot.Refusal("--scripts is from 1 to 16, and --min-free from 1 to --scripts")
    api = TimeApi(args.api)
    seed = bot.key_from(args)  # only from the key store or the environment, under the names you gave
    sender = bot.Sender(api, account=args.account, seed=seed, act=args.act, sleep=sleep, wait_seconds=args.wait_seconds)
    addresses = bot.AddressFile(args.address_file, args.bitcoin_network)
    me, known, had_order, done = str(args.account), None, False, 0
    rounds = args.rounds or (0 if args.act else 1)  # a dry run does one round
    is_free = lambda script: api.market_script(script)["status"] == "free"
    print(f"sell_maker: account {me}, one sell order at {bot.price_words(args.price)}; {addresses.free()} free addresses in the file; {'ACTING' if args.act else 'DRY RUN'}")
    try:
        while True:
            # 1. The account, read now: its rules, its limit, its balance, its key.
            state = api.account_state(args.account)
            facts = bot.check_account(state, most_daily_limit_micros=args.max_daily_limit, most_balance_micros=args.max_balance)
            if seed is not None:
                bot.check_key(state, seed)
            # 2. The market: the index must be clean, the Bitcoin network yours, the header chain not halted.
            market = api.market()
            bot.check_index(market)
            bot.check_bitcoin(market, args.bitcoin_network, new_fill=False)
            # 3. My order at this price. The list is the index's word: the order itself is read before anything is done.
            mine = api.account_market(args.account)
            bot.check_index(mine)
            listed = [order for order in mine["orders"] if order["side"] == "sell" and order["open"] and order["price"] == str(args.price)]
            if len(listed) > 1:
                raise bot.Refusal(f"The account has {len(listed)} open sell orders at this price: this script keeps one. Cancel the others first")
            if not listed:
                if had_order and not args.renew:
                    print("The order is gone: all of it is sold, or it was cancelled. The script stops (--renew makes a new one).")
                    known = None
                    return 0
                cost = amounts.sats(args.amount, args.price)
                if cost < args.min_sats:
                    raise bot.Refusal(f"The order would cost {cost} satoshis, less than its own smallest trade ({args.min_sats})")
                if args.amount > facts["balance"]:
                    raise bot.Refusal(f"The account holds {bot.seconds(facts['balance'])}, less than the {bot.seconds(args.amount)} the order would offer")
                within_limit(facts, args.amount, "A new order")
                taken = addresses.take(args.scripts, f"sell order of account {me}", write=args.act, is_free=is_free)
                payload = actions.sell_order(amount_micros=args.amount, price=args.price, scripts=[entry["script"] for entry in taken], confirmations=args.confirmations, pay_blocks=args.pay_blocks,
                                             min_sats=args.min_sats, deposit_ppm=args.deposit_ppm, min_deposit_micros=args.min_deposit)
                print(f"No open sell order at this price. A new one: {bot.seconds(args.amount)} at {bot.price_words(args.price)}, {cost} satoshis in all, paid to:")
                for entry in taken:
                    print(f"  {entry['address']}")
                answer = sender.send(50, payload, f"a sell order of {bot.seconds(args.amount)} at {bot.price_words(args.price)}")
                if answer is not None:  # sent, and in a block: the chain gave the order its number
                    had_order = True
                    known = bot.order_made(api, args.account, side="sell", price=args.price, height=answer["action"]["height"], sleep=sleep)["id"]
                    print(f"The order is number {known}.")
            else:
                had_order, known = True, listed[0]["id"]
                row = api.market_order(known)["order"]  # the row itself, from the current state
                if row["owner"] != me or row["side"] != "sell" or row["price"] != str(args.price):
                    raise bot.Refusal(f"Order {known} changed between the list and its own row: nothing is done on it")
                in_use = [entry for entry in row["scripts"] if "fill" in entry]
                free = [entry for entry in row["scripts"] if "fill" not in entry and not entry.get("used")]
                print(f"Order {known}: {bot.seconds(int(row['amount_micros']))} on offer, {len(in_use)} open fills, {len(free)} free addresses.")
                # 4. Fills whose time has passed, if asked: each fill is read by itself just before.
                for entry in in_use if args.expire_unpaid else ():
                    try:
                        fill = api.market_fill(entry["fill"])
                    except ApiError as error:
                        if error.code != "fill_not_found":
                            raise
                        continue
                    if fill["fill"]["order"] == known and (fill.get("expiry") or {}).get("possible") is True:
                        print(f"Fill {entry['fill']} was not paid in its time: {bot.seconds(int(fill['fill']['amount_micros']))} return to the order, and the deposit of {bot.seconds(int(fill['fill']['deposit_micros']))} comes to this account.")
                        sender.send(55, actions.expire(fill=entry["fill"]), f"the end of fill {entry['fill']}, which was not paid")
                # 5. New addresses, when too few are free. They count the order's seconds against the daily limit again.
                if row["open"] and int(row["amount_micros"]) > 0 and len(free) < args.min_free:
                    wanted = min(args.scripts, 16) - len(in_use) - len(free)
                    if wanted > 0:
                        held = int(row["amount_micros"])
                        for entry in in_use:
                            try:
                                held += int(api.market_fill(entry["fill"])["fill"]["amount_micros"])
                            except ApiError as error:
                                if error.code != "fill_not_found":
                                    raise
                        within_limit(facts, held, "New addresses for the order")
                        taken = addresses.take(wanted, f"sell order {known}", write=args.act, is_free=is_free)
                        print(f"The order has {len(free)} free addresses. {len(taken)} new ones (this counts {bot.seconds(held)} against the daily limit):")
                        for entry in taken:
                            print(f"  {entry['address']}")
                        sender.send(58, actions.new_scripts(order=known, scripts=[entry["script"] for entry in taken]), f"{len(taken)} new receiving addresses for order {known}")
            done += 1
            if rounds and done >= rounds:
                return 0
            sleep(args.interval)
    except KeyboardInterrupt:
        print("Stopped.")
        return 0
    finally:
        # The order is firm while it stands: a taker can still take it after the script has stopped.
        if args.cancel_on_exit and known is not None and sys.exc_info()[0] not in (bot.NotKnown,):
            try:
                row = api.market_order(known)["order"]
                if row["owner"] == me and row["open"]:
                    print(f"Taking order {known} back: {bot.seconds(int(row['amount_micros']))} return to the balance. Its open fills go on.")
                    sender.send(51, actions.cancel(order=known), f"the cancellation of order {known}")
            except ApiError as error:
                print(f"Order {known} was not cancelled: {error}")


def main(argv=None, *, sleep=time.sleep) -> int:
    args = arguments().parse_args(argv)
    return bot.outcome(lambda: run(args, sleep))


if __name__ == "__main__":
    sys.exit(main())
