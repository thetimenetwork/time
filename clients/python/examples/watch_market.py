"""Reads the market and shows it: the book, the depth, the recent trades and the candles, on the terminal and as CSV.

    python -m examples.watch_market --api http://127.0.0.1:8930
    python -m examples.watch_market --api http://127.0.0.1:8930 --csv-dir out --candles 15m --every 60

IT SIGNS NOTHING AND NEEDS NO KEY AND NO ACCOUNT. It only asks.

Everything it shows is the word of the API it asks: lists come from that server's index, and this
script cannot check a proof. The first lines say where the index stands (``market_index``). When the
index is not clean the script still shows what it was given, marks it NOT CLEAN, and exits with 2,
so that a program that reads its output does not take the numbers for good ones.

THE PRICES ARE RECORDS, NOT A VALUATION. A trade is one fill paid at its own price; a candle is the
trades of an interval. No rule of the chain reads them, and two accounts of one person can write any
price for a fee (spec/market.md, section 9). The book is firmer: a sell order is seconds somebody has
locked at that price. A buy order is a promise with a bond.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import time

from timemarket import TimeApi, bot
from timemarket.api import CANDLE_INTERVALS


def arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watch_market", description="Shows the book, the depth, the trades and the candles of the market. Read-only.")
    parser.add_argument("--api", required=True, metavar="URL", help="the API to ask, such as http://127.0.0.1:8930")
    parser.add_argument("--levels", type=int, default=10, help="prices of each side in the depth (default 10)")
    parser.add_argument("--orders", type=int, default=10, help="orders of each side in the book (default 10)")
    parser.add_argument("--trades", type=int, default=20, help="recent trades (default 20)")
    parser.add_argument("--candles", choices=CANDLE_INTERVALS, default="hour", help="the interval of the candles: hour is the chain's own (default)")
    parser.add_argument("--csv-dir", metavar="DIRECTORY", help="also write book-sell.csv, book-buy.csv, depth.csv, trades.csv and candles.csv there")
    parser.add_argument("--every", type=int, default=0, metavar="SECONDS", help="show again every so often (default: once)")
    parser.add_argument("--rounds", type=int, default=0, metavar="N", help="with --every: stop after N times")
    return parser


def table(title: str, columns: list[str], rows: list[list], csv_dir, name: str) -> None:
    print(f"\n{title}")
    if not rows:
        print("  (nothing)")
    else:
        widths = [max(len(str(cell)) for cell in [column] + [row[at] for row in rows]) for at, column in enumerate(columns)]
        for row in [columns] + rows:
            print("  " + "  ".join(str(cell).rjust(width) for cell, width in zip(row, widths)))
    if csv_dir:
        with open(os.path.join(csv_dir, name), "w", encoding="utf-8", newline="") as file:
            csv.writer(file, lineterminator="\n").writerows([columns] + rows)


def show(api, args) -> bool:
    """One reading. Returns whether the index was clean."""
    market = api.market()
    index, chain, summary = market["market_index"], market.get("bitcoin") or {}, market["summary"]
    try:
        bot.check_index(market)
        clean = True
        print(f"The index is clean, as of height {index['as_of_height']} (the state: height {market['state_height']}); {index.get('pending_rows', 0)} rows are being read again.")
    except bot.Refusal as refusal:
        clean = False
        print(f"NOT CLEAN: {refusal}")
    print("  " + ", ".join(f"{name}: {index.get(name)}" for name in ("ready", "consistent", "tape_reconciled", "tape_complete", "tape_unvalued", "tape_faults", "unread_actions", "waiting_for_indexer")))
    print(f"Bitcoin {chain.get('network')}: the chain knows height {chain.get('best_height')}; halted: {chain.get('halted')}; fresh: {chain.get('fresh')} (the API's best guess; null is not known).")
    print(f"The chain counts: orders {summary['orders']}, open fills {summary['fills']}, proven payments {summary['trades']} ({summary['sats']} satoshis for {bot.seconds(int(summary['seconds_micros']))} in all).")
    last = market.get("last_recorded_price")
    print("Last recorded price: " + ("none yet" if last is None else f"{bot.price_words(int(last))} (a record of one fill, not what a second is worth)"))

    for side, name in (("sell", "Sell orders, cheapest first"), ("buy", "Buy orders, dearest first")):
        book = api.market_orders(side, limit=args.orders)
        rows = [[order["id"], order["owner"], order["price"], order["amount_micros"], order["sats"], order["min_sats"], order["confirmations"], order["pay_blocks"], order["deposit_ppm"], "yes" if order["takes_fill"] else "no"] for order in book["items"]]
        table(f"{name} (the index's word, as of height {book['market_index']['as_of_height']})", ["order", "owner", "price", "amount_micros", "sats", "min_sats", "confirmations", "pay_blocks", "deposit_ppm", "takes_fill"], rows, args.csv_dir, f"book-{side}.csv")
    depth = api.market_depth(args.levels)
    rows = [[side, level["price"], level["amount_micros"], level["takeable_micros"], level["sats"], level["orders"]] for side in ("sell", "buy") for level in depth[side]]
    table("Depth: each side added up by price", ["side", "price", "amount_micros", "takeable_micros", "sats", "orders"], rows, args.csv_dir, "depth.csv")
    trades = api.market_trades(limit=args.trades)
    rows = [[trade["id"], trade["fill"], trade["price"], trade["sats"], trade["seconds_micros"], "yes" if trade["full"] else "no", trade["basis"]] for trade in trades["items"]]
    table("Trades, newest first: one for every proven payment", ["id", "fill", "price", "sats", "seconds_micros", "in_full", "basis"], rows, args.csv_dir, "trades.csv")
    candles = api.market_candles(args.candles, limit=50)
    rows = [[candle["number"], candle["start_time_micros"], candle["recorded_prices"]["open"], candle["recorded_prices"]["high"], candle["recorded_prices"]["low"], candle["recorded_prices"]["close"], candle["sats"], candle["seconds_micros"], candle["trades"], candle["source"]] for candle in candles["items"]]
    table(f"Candles ({args.candles}), newest first: records of trades, not a valuation", ["number", "start_time_micros", "open", "high", "low", "close", "sats", "seconds_micros", "trades", "source"], rows, args.csv_dir, "candles.csv")
    return clean


def run(args, sleep) -> int:
    api = TimeApi(args.api)
    if args.csv_dir:
        os.makedirs(args.csv_dir, exist_ok=True)
    done, clean = 0, True
    try:
        while True:
            clean = show(api, args)
            done += 1
            if not args.every or (args.rounds and done >= args.rounds):
                break
            sleep(args.every)
            print("\n" + "-" * 60)
    except KeyboardInterrupt:
        pass
    return 0 if clean else 2


def main(argv=None, *, sleep=time.sleep) -> int:
    args = arguments().parse_args(argv)
    return bot.outcome(lambda: run(args, sleep))


if __name__ == "__main__":
    sys.exit(main())
