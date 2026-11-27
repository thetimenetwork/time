"""A stand-in for the API, with a small model of the market behind it. For the tests of the examples, and for trying them by hand.

IT IS NOT THE ENGINE AND NOT THE API. It answers the routes the Python client calls in the forms of
client-v4/api.mjs, and it follows the rules of spec/market.md as far as the example scripts go (an
order, a cancel, a take, a sale to a buy order, new scripts, an expiry, a release, a settle; a proven
payment is played by ``World.pay``, since no script here sends a proof). It checks the signature, the
key, the nonce, the balance and the daily limit of what is submitted, so that a script which signs
something wrong fails here too. What the engine does is in v5/src/market.rs; what a real network
answers, no test of this package has seen.

By hand, from clients/python:

    python -m tests.fake_api --port 8930

serves the market that docs/trading.md uses for its commands (``guide_world``), on 127.0.0.1 only.
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from timemarket import actions, address, amounts, wire

from . import ENGINE

GENESIS = 1_800_000_000_000_000
LABORATORY = {"profile": "laboratory", "kMin": "1", "nMin": "1", "blockMicros": "1000000", "graceMicros": "20000000", "bondMinPpm": "0", "minSats": "1", "hourMicros": "60000000",
              "priceMax": "1000000000000000", "satsMax": "2100000000000000", "kMax": "100", "nMax": "144", "spareBlocks": "16", "orders": 64, "payerFills": 64, "scripts": 16, "buyFills": 16, "heightEntries": 256}
RECOVERY_KEY = "cc" * 32


class Reject(Exception):
    """The node refuses an action: it is in no block and nothing changed."""


class World:
    """One network with the market, as the stand-in holds it. Tests change its fields between requests."""

    def __init__(self, *, bitcoin_network: str = "regtest"):
        self.network_id, self.fee = ENGINE["network_id"], 1000
        self.height, self.now = 345, 20_405_000_000  # the chain's height, and the clock of the waits
        self.accounts, self.security, self.orders, self.fills, self.scripts = {}, {}, {}, {}, {}
        self.ended, self.trades, self.expirable = {}, [], set()
        self.next_order = self.next_fill = 1
        self.index = {"as_of_height": None, "ready": True, "consistent": True, "pending_rows": 0, "reading_every_row": False, "tape_reconciled": True, "tape_from_height": "1", "tape_complete": True,
                      "tape_trades": 0, "tape_unvalued": 0, "tape_faults": 0, "unread_actions": 0, "waiting_for_indexer": False, "last_error": None}
        self.bitcoin = {"network": bitcoin_network, "best_height": "5", "best_tip": "6d8e2823981bb076e74b8947380d71309422d4014dbd7c0f654d7f676ac4d691", "halted": False, "halt": None, "fresh": True, "best_header_time": "1800020405", "max_tip_age_secs": 7200}
        self.posted, self.included, self.requests = [], {}, []
        self.lookups_before_block = 0  # how many lookups of a new action answer 404 before it is in a block
        self.submit_failures = []      # (status, code) answered, in turn, to the next submissions although they are taken
        self.on_request = None         # called with (method, path) before each request is answered
        self.lock = threading.RLock()

    # ------------------------------------------------------------ setting it up
    def add_account(self, number: int, seed_hex: str | None, balance: int, *, nonce: int = 0, secured: bool = True, daily_limit: int = 600_000_000, can_manage: bool = False) -> None:
        devices = [] if seed_hex is None else [{"can_manage": can_manage or not secured, "can_spend": True, "public_key": wire.public_key(seed_hex)}]
        self.accounts[number] = {"id": str(number), "name": f"account{number}", "balance": balance, "nonce": nonce, "auth_epoch": 0, "devices": devices + ([{"can_manage": True, "can_spend": False, "public_key": RECOVERY_KEY}] if secured else [])}
        self.security[number] = None if not secured else {
            "allowance_elapsed_micros": str(self.now), "allowance_micros": str(daily_limit), "freezes": "0", "frozen_until_elapsed_micros": "0", "next_id": "1", "pending_limit": None, "pending_payments": [], "pending_root": None,
            "policy": {"daily_limit_micros": str(daily_limit), "delay_seconds": "86400", "freeze_seconds": "86400", "threshold": "2"}, "version": "1"}

    # ------------------------------------------------------------ the rules, as far as the examples go
    def _moment(self) -> dict:
        return {"height": str(self.height), "time_micros": str(GENESIS + self.now)}

    def _charge(self, sender: int, out: int, counted: int) -> None:
        """Takes ``out`` from the sender's balance and counts ``counted`` against its daily limit, or refuses."""
        account, security = self.accounts[sender], self.security[sender]
        if account["balance"] < out:
            raise Reject("insufficient balance")
        if security is not None:
            if self.now < int(security["frozen_until_elapsed_micros"]) or security["pending_root"]:
                raise Reject("account is frozen")
            if counted > int(security["allowance_micros"]):
                raise Reject("over the daily limit of this account: use a payment that waits, or a second proof")
            security["allowance_micros"], security["allowance_elapsed_micros"] = str(int(security["allowance_micros"]) - counted), str(self.now)
        account["balance"] -= out

    def _new_scripts(self, scripts: list[str]) -> None:
        if any(script in self.scripts for script in scripts):
            raise Reject("a receiving script is listed already, or has served a fill")

    def _size(self, order: dict, amount: int, sats: int) -> None:
        offered, price, least = int(order["amount_micros"]), int(order["price"]), int(order["min_sats"])
        if not 1 <= amount <= offered:
            raise Reject("the order does not offer this amount")
        if sats != amounts.sats(amount, price):
            raise Reject("sats is not the price of the amount at the order's price")
        if not (sats >= least or (amount == offered and sats >= int(LABORATORY["minSats"]))):
            raise Reject("the fill is smaller than the order's smallest trade")
        if amount < offered and amounts.sats(offered - amount, price) < least:
            raise Reject("what would stay on offer is smaller than the order's smallest trade")

    def _stands(self, order: dict) -> bool:
        owner, security = self.accounts[int(order["owner"])], self.security[int(order["owner"])]
        frozen = security is not None and (self.now < int(security["frozen_until_elapsed_micros"]) or bool(security["pending_root"]))
        return not frozen and any(device["can_spend"] and device["public_key"] == order["key"] for device in owner["devices"])

    def _fresh(self) -> None:
        if self.bitcoin["network"] == "mainnet":
            raise Reject("the market is closed on Bitcoin mainnet")
        if self.bitcoin["halted"] or self.bitcoin["fresh"] is False:
            raise Reject("the Bitcoin header chain is not fresh")

    def _fill(self, order: dict, *, amount: int, sats: int, confirmations: str, deposit: int, owner: str, payer: str, to: str, script: str) -> dict:
        number = self.next_fill
        self.next_fill += 1
        self.fills[number] = {"amount_micros": str(amount), "confirmations": confirmations, "created": self._moment(), "deposit_micros": str(deposit), "id": str(number), "opened_micros": str(self.now), "order": order["id"], "owner": owner,
                              "pay_blocks": order["pay_blocks"], "payer": payer, "price": order["price"], "sats": str(sats), "script": script, "side": order["side"], "start_hash": self.bitcoin["best_tip"], "start_height": self.bitcoin["best_height"], "to": to}
        return self.fills[number]

    def _order_goes(self, order: dict) -> None:
        number, open_fills = int(order["id"]), [fill for fill in self.fills.values() if fill["order"] == order["id"]]
        if open_fills or (order["open"] and order["amount_micros"] != "0"):
            return
        self.accounts[int(order["owner"])]["balance"] += int(order["bond_micros"])
        for entry in order.get("scripts", ()):
            if not entry.get("used"):
                self.scripts.pop(entry["script"], None)
        del self.orders[number]

    def _end(self, fill: dict, how: str, *, back: bool) -> None:
        """A fill ends. ``back``: its seconds return to the seller and the deposit goes to the seller (an expiry, a release)."""
        number, order = int(fill["id"]), self.orders[int(fill["order"])]
        held, deposit = int(fill["amount_micros"]), int(fill["deposit_micros"])
        if back:
            if order["side"] == "sell" and order["open"]:
                order["amount_micros"] = str(int(order["amount_micros"]) + held)
            else:
                self.accounts[int(fill["owner"])]["balance"] += held
            self.accounts[int(fill["owner"])]["balance"] += deposit
        else:
            self.accounts[int(fill["to"])]["balance"] += held
            self.accounts[int(fill["payer"])]["balance"] += deposit
        self.scripts[fill["script"]] = ("used",)
        if order["side"] == "sell":
            for entry in order["scripts"]:
                if entry.get("fill") == fill["id"]:
                    del entry["fill"]
                    entry["used"] = True
        else:
            order["fills"] = str(int(order["fills"]) - 1)
        self.ended[number] = {"id": f"{self.height}.0", "source": "index", "proven": False, "hash": None, "height": str(self.height), "index": 0, "time": None, "type": "fill_ended", "fill": fill["id"], "order": fill["order"], "side": fill["side"],
                              "owner": fill["owner"], "payer": fill["payer"], "to": fill["to"], "price": fill["price"], "how": how, "unpaid_micros": fill["amount_micros"] if back else "0", "unpaid_sats": fill["sats"] if back else "0"}
        del self.fills[number]
        self._order_goes(order)

    def pay(self, fill_number: int, sats: int) -> None:
        """A payment of ``sats`` satoshis to the fill's address is proven (kind 54, sent by somebody)."""
        with self.lock:
            self.height += 1
            fill = self.fills[fill_number]
            after = amounts.fill_after_payment(int(fill["amount_micros"]), int(fill["sats"]), int(fill["deposit_micros"]), sats)
            self.accounts[int(fill["to"])]["balance"] += after["seconds"]
            self.accounts[int(fill["payer"])]["balance"] += after["deposit_back"]
            self.trades.append({"id": f"{self.height}.0", "source": "index", "proven": False, "hash": "AB" * 32, "height": str(self.height), "index": 0, "time": None, "type": "payment", "fill": fill["id"], "order": fill["order"], "side": fill["side"],
                                "owner": fill["owner"], "payer": fill["payer"], "to": fill["to"], "price": fill["price"], "sats": str(min(sats, int(fill["sats"]))), "seconds_micros": str(after["seconds"]), "paid_sats": str(sats), "full": after["ends"],
                                "bitcoin_txid": "cd" * 32, "vout": "0", "bitcoin_block_hash": "ef" * 32, "basis": "proven_row", "time_micros": GENESIS + self.now})
            self.index["tape_trades"] += 1
            if after["ends"]:
                fill["amount_micros"] = fill["deposit_micros"] = "0"
                self._end(fill, "paid", back=False)
            else:
                fill["amount_micros"], fill["sats"], fill["deposit_micros"] = str(after["amount_micros"]), str(after["sats"]), str(after["deposit_micros"])

    def apply(self, raw: bytes) -> None:
        """Executes a signed action, or refuses it (``Reject``) and changes nothing."""
        action = wire.verify_action(raw)
        sender, kind, p = int(action["sender"]), action["kind"], action["payload"]
        account = self.accounts.get(sender)
        if account is None or not any(device["can_spend"] and device["public_key"] == action["public_key"] for device in account["devices"]):
            raise Reject("the key is not a spending key of the account")
        if int(action["auth_epoch"]) != account["auth_epoch"]:
            raise Reject("stale authority epoch")
        if int(action["nonce"]) != account["nonce"] + 1:
            raise Reject("incorrect nonce or nonce exhausted")
        fee, me = actions.action_fee(kind, p, self.fee), str(sender)
        if kind == 50:
            amount = int(p["amount_micros"])
            if p["side"] == "sell":
                self._new_scripts(p["scripts"])
                self._charge(sender, amount + fee, amount + fee)
                order = {"amount_micros": p["amount_micros"], "bond_micros": "0", "min_deposit_micros": p["min_deposit_micros"], "scripts": [{"script": script} for script in p["scripts"]]}
            else:
                bond = -(-amount * int(p["deposit_ppm"]) // 10**6)
                self._charge(sender, bond + fee, bond + fee)
                order = {"amount_micros": p["amount_micros"], "bond_micros": str(bond), "min_deposit_micros": "0", "fills": "0", "forms": p["forms"]}
            order.update({"confirmations": p["confirmations"], "created": self._moment(), "deposit_ppm": p["deposit_ppm"], "id": str(self.next_order), "key": action["public_key"], "min_sats": p["min_sats"], "open": True, "owner": me, "pay_blocks": p["pay_blocks"], "price": p["price"], "side": p["side"]})
            for script in p.get("scripts", ()):
                self.scripts[script] = ("order", order["id"])
            self.orders[self.next_order] = order
            self.next_order += 1
        elif kind in (51, 58):
            order = self.orders.get(int(p["order"]))
            if order is None or order["owner"] != me or not order["open"]:
                raise Reject("no such open order of the sender")
            if kind == 51:
                self._charge(sender, fee, fee)
                account["balance"] += int(order["amount_micros"]) + int(order["bond_micros"])
                order["amount_micros"], order["bond_micros"], order["open"] = "0", "0", False
                self._order_goes(order)
            else:
                if order["side"] != "sell":
                    raise Reject("new scripts are for a sell order")
                self._new_scripts(p["scripts"])
                kept = [entry for entry in order["scripts"] if not entry.get("used")]
                if len(kept) + len(p["scripts"]) > 16:
                    raise Reject("an order has at most 16 receiving scripts that have not served")
                counted = int(order["amount_micros"]) + sum(int(fill["amount_micros"]) for fill in self.fills.values() if fill["order"] == order["id"])
                self._charge(sender, fee, counted + fee)
                order["scripts"], order["key"] = kept + [{"script": script} for script in p["scripts"]], action["public_key"]
                for script in p["scripts"]:
                    self.scripts[script] = ("order", order["id"])
        elif kind in (52, 53):
            order, amount, sats = self.orders.get(int(p["order"])), int(p["amount_micros"]), int(p["sats"])
            self._fresh()
            if order is None or not order["open"] or order["side"] != ("sell" if kind == 52 else "buy"):
                raise Reject("no such open order of that side")
            if not self._stands(order):
                raise Reject("the owner of the order does not stand")
            self._size(order, amount, sats)
            if kind == 52:
                entry = next((entry for entry in order["scripts"] if "fill" not in entry and not entry.get("used")), None)
                if entry is None or int(p["to"]) not in self.accounts:
                    raise Reject("the order has no free receiving script, or the account the seconds go to does not exist")
                deposit = max(-(-amount * int(order["deposit_ppm"]) // 10**6), int(order["min_deposit_micros"]))
                self._charge(sender, deposit + fee, deposit + fee)
                fill = self._fill(order, amount=amount, sats=sats, confirmations=order["confirmations"], deposit=deposit, owner=order["owner"], payer=me, to=p["to"], script=entry["script"])
                entry["fill"] = fill["id"]
            else:
                if not 1 <= int(p["confirmations"]) <= int(order["confirmations"]) or address.script_form(p["script"]) not in order["forms"]:
                    raise Reject("the buyer does not wait for that many confirmations, or cannot pay to that form of address")
                self._new_scripts([p["script"]])
                offered, bond = int(order["amount_micros"]), int(order["bond_micros"])
                deposit = bond if amount == offered else bond * amount // offered
                self._charge(sender, amount + fee, amount + fee)
                self._fill(order, amount=amount, sats=sats, confirmations=p["confirmations"], deposit=deposit, owner=me, payer=order["owner"], to=order["owner"], script=p["script"])
                order["bond_micros"], order["fills"] = str(bond - deposit), str(int(order["fills"]) + 1)
                self.scripts[p["script"]] = ("fill", str(self.next_fill - 1))
            order["amount_micros"] = str(int(order["amount_micros"]) - amount)
        elif kind in (55, 56, 57):
            fill = self.fills.get(int(p["fill"]))
            if fill is None:
                raise Reject("no such fill")
            if kind == 55 and int(p["fill"]) not in self.expirable:
                raise Reject("the fill cannot end yet")
            if (kind == 56 and fill["to"] != me) or (kind == 57 and fill["owner"] != me):
                raise Reject("the sender may not end this fill")
            counted = int(fill["amount_micros"]) if kind in (56, 57) else 0
            self._charge(sender, fee, counted + fee)
            self._end(fill, {55: "expired", 56: "released", 57: "settled"}[kind], back=kind != 57)
        else:
            raise Reject("a proof of payment is not modelled here: World.pay plays it")
        account["nonce"] += 1

    # ------------------------------------------------------------ the answers, in the forms of client-v4/api.mjs
    def _index(self) -> dict:
        return {**self.index, "as_of_height": self.index["as_of_height"] or str(self.height)}

    def _proven(self) -> dict:
        return {"source": "state_proof", "checked_by": "this server, with its own trust anchor", "state_height": str(self.height), "state_time_micros": str(GENESIS + self.now), "indexed_height": str(self.height),
                "proof": {"query": {}, "view_proof": None, "how": "A stand-in gives no proof."}}

    def _listed(self, body: dict) -> dict:
        return {"source": "index", "proven": False, **body, "market_index": self._index(), "index": {"network_id": self.network_id, "start_height": "1", "indexed_height": str(self.height), "seconds_behind": 0}}

    @staticmethod
    def takes_fill(order: dict) -> bool:
        if not order["open"] or order["amount_micros"] == "0":
            return False
        return any("fill" not in entry and not entry.get("used") for entry in order["scripts"]) if order["side"] == "sell" else int(order["fills"]) < 16

    def _order_view(self, order: dict) -> dict:
        sell = order["side"] == "sell"
        return {"id": order["id"], "side": order["side"], "owner": order["owner"], "price": order["price"], "amount_micros": order["amount_micros"], "sats": str(amounts.sats(int(order["amount_micros"]), int(order["price"]))), "min_sats": order["min_sats"],
                "confirmations": order["confirmations"], "pay_blocks": order["pay_blocks"], "deposit_ppm": order["deposit_ppm"], "min_deposit_micros": order["min_deposit_micros"], "bond_micros": order["bond_micros"], "open": order["open"], "takes_fill": self.takes_fill(order),
                "open_fills": sum(1 for entry in order["scripts"] if "fill" in entry) if sell else int(order["fills"]), "free_scripts": sum(1 for entry in order["scripts"] if "fill" not in entry and not entry.get("used")) if sell else None,
                "forms": None if sell else order["forms"], "key": order["key"], "created": order["created"], "proven_at_height": str(self.height)}

    @staticmethod
    def last_height(fill: dict) -> str:
        return str(int(fill["start_height"]) + int(fill["pay_blocks"]) + int(fill["confirmations"]) - 1)

    def _book(self, side: str) -> list[dict]:
        rows = [order for order in self.orders.values() if order["side"] == side and order["open"] and order["amount_micros"] != "0"]
        return sorted(rows, key=lambda order: (int(order["price"]) if side == "sell" else -int(order["price"]), int(order["id"])))

    def _depth(self, side: str, levels: int) -> list[dict]:
        out = []
        for order in self._book(side):
            if not out or out[-1]["price"] != order["price"]:
                if len(out) == levels:
                    break
                out.append({"price": order["price"], "amount": 0, "takeable": 0, "orders": 0})
            out[-1]["amount"] += int(order["amount_micros"])
            out[-1]["takeable"] += int(order["amount_micros"]) if self.takes_fill(order) else 0
            out[-1]["orders"] += 1
        return [{"price": level["price"], "amount_micros": str(level["amount"]), "takeable_micros": str(level["takeable"]), "sats": str(amounts.sats(level["amount"], int(level["price"]))), "orders": level["orders"]} for level in out]

    def _roles(self, fill: dict, account: str) -> list[str]:
        return [role for role in ("payer", "owner", "to") if fill[role] == account]

    def get(self, path: str, query: dict) -> tuple[int, dict]:
        """(status, body) for a GET."""
        parts = path.strip("/").split("/")
        missing = lambda code, message, more=None: (404, {"error": {"code": code, "message": message}, **(more or {})})
        if path == "/v1/status":
            return 200, {"api": "v1", "network": {"network_id": self.network_id, "chain_id": "stand-in", "protocol_version": "4", "fee_micros": str(self.fee), "fee_source": "state_proof"}, "indexer": {"start_height": "1", "indexed_height": str(self.height), "seconds_behind": 0}}
        if path == "/v1/health":
            return 200, {"ok": True, "reasons": [], "market": self._index()}
        if len(parts) == 4 and parts[:2] == ["v1", "accounts"] and parts[3] in ("state", "market"):
            number = int(parts[2])
            if parts[3] == "state":
                if number not in self.accounts:
                    return missing("account_not_found", "No such account in the verified state", self._proven())
                account = self.accounts[number]
                return 200, {**self._proven(), "account": {**account, "balance": str(account["balance"]), "nonce": str(account["nonce"]), "auth_epoch": str(account["auth_epoch"])}, "security": self.security[number], "recovery_cases": [], "stake": None, "validator": None,
                             "genesis_time_micros": str(GENESIS), "security_clock": {"waits_survive_stops": True, "stopped_micros": "0", "now_elapsed_micros": str(self.now)}}
            me = str(number)
            return 200, self._listed({"account": me, "orders": [{**self._order_view(order), "roles": ["owner"]} for order in self.orders.values() if order["owner"] == me],
                                      "fills": [{**fill, "last_height": self.last_height(fill), "proven_at_height": str(self.height), "roles": self._roles(fill, me)} for fill in sorted(self.fills.values(), key=lambda fill: -int(fill["id"])) if self._roles(fill, me)], "fills_truncated": False,
                                      "ended": {"has_more": False, "next_cursor": None, "items": [{**ended, "roles": self._roles(ended, me)} for ended in self.ended.values() if self._roles(ended, me)]}})
        if len(parts) == 3 and parts[:2] == ["v1", "actions"]:
            found = self.included.get(parts[2])
            if found is None or found["lookups"] < self.lookups_before_block:
                if found is not None:
                    found["lookups"] += 1
                return missing("not_found", "No action with this hash is in the index: it may be waiting for a block, refused, or above the indexed height")
            action = wire.decode_action(found["raw"])
            return 200, {"source": "index", "proven": False, "action": {"hash": parts[2], "height": str(found["height"]), "index": 0, "kind": action["kind"], "sender": action["sender"], "nonce": action["nonce"], "results_checked": True, "payload": action["payload"]}, "verify": {"height": str(found["height"])}}
        if path == "/v1/market":
            summary = {"fills": str(len(self.fills)), "next_fill": str(self.next_fill), "next_order": str(self.next_order), "orders": str(len(self.orders)), "sats": str(sum(int(trade["sats"]) for trade in self.trades)),
                       "seconds_micros": str(sum(int(trade["seconds_micros"]) for trade in self.trades)), "trades": str(len(self.trades)), **({"last_price": self.trades[-1]["price"]} if self.trades else {})}
            return 200, {**self._proven(), "market": True, "rules": LABORATORY, "summary": summary, "last_recorded_price": summary.get("last_price"), "held_micros": "0", "heights": {"entries": [{"at": "0", "height": "0"}]},
                         "clock": {"genesis_time_micros": str(GENESIS), "now_elapsed_micros": str(self.now), "hour": str(self.now // 60_000_000)}, "bitcoin": dict(self.bitcoin), "market_index": self._index()}
        if path == "/v1/market/orders":
            rows = self._book(query["side"])[: int(query.get("limit", 50))]
            return 200, self._listed({"side": query["side"], "has_more": False, "next_cursor": f"{rows[-1]['price']}.{rows[-1]['id']}" if rows else None, "items": [self._order_view(order) for order in rows]})
        if path == "/v1/market/depth":
            levels = int(query.get("levels", 20))
            return 200, self._listed({"levels": levels, "sell": self._depth("sell", levels), "buy": self._depth("buy", levels), "truncated": False, "last_recorded_price": self.trades[-1]["price"] if self.trades else None})
        if path == "/v1/market/trades":
            rows = self.trades if query.get("order") == "asc" else self.trades[::-1]
            if "cursor" in query:
                height, place = (int(part) for part in query["cursor"].split("."))
                rows = [trade for trade in rows if (int(trade["height"]), trade["index"]) > (height, place)] if query.get("order") == "asc" else [trade for trade in rows if (int(trade["height"]), trade["index"]) < (height, place)]
            rows = rows[: int(query.get("limit", 50))]
            return 200, self._listed({"order": query.get("order", "desc"), "has_more": False, "next_cursor": rows[-1]["id"] if rows else query.get("cursor"), "items": [{key: value for key, value in trade.items() if key != "time_micros"} for trade in rows]})
        if path == "/v1/market/candles":
            width, chain, buckets = {"hour": 60_000_000, "1m": 60_000_000, "5m": 300_000_000, "15m": 900_000_000, "1d": 86_400_000_000}[query["interval"]], query["interval"] == "hour", {}
            for trade in self.trades:
                buckets.setdefault((trade["time_micros"] - (GENESIS if chain else 0)) // width, []).append(trade)
            items = []
            for number in sorted(buckets, reverse=True)[: int(query.get("limit", 50))]:
                prices, start = [int(trade["price"]) for trade in buckets[number]], (GENESIS if chain else 0) + number * width
                items.append({"number": str(number), "start_time_micros": str(start), "start_time": None, "recorded_prices": {"open": str(prices[0]), "high": str(max(prices)), "low": str(min(prices)), "close": str(prices[-1])},
                              "sats": str(sum(int(trade["sats"]) for trade in buckets[number])), "seconds_micros": str(sum(int(trade["seconds_micros"]) for trade in buckets[number])), "trades": str(len(prices)),
                              **({"source": "state_row", "proven_at_height": str(self.height), "matches_tape": True} if chain else {"source": "computed"})})
            return 200, self._listed({"interval": query["interval"], "interval_micros": str(width), "begins": "with the chain" if chain else "on whole multiples of the interval since 1970 (UTC)", "has_more": False, "next_to": None, "items": items})
        if len(parts) == 4 and parts[:3] == ["v1", "market", "orders"]:
            order = self.orders.get(int(parts[3]))
            if order is None:
                return missing("order_not_found", "No such order in the verified state: it was never made, or it is gone (cancelled, or all of it sold and paid)", {**self._proven(), "order": None})
            stands = self._stands(order)
            return 200, {**self._proven(), "order": json.loads(json.dumps(order)), "sats": str(amounts.sats(int(order["amount_micros"]), int(order["price"]))), "takes_fill": self.takes_fill(order), "owner_stands": {"stands": stands, "key_can_spend": stands, "frozen": False}}
        if len(parts) == 4 and parts[:3] == ["v1", "market", "fills"]:
            number, fill = int(parts[3]), self.fills.get(int(parts[3]))
            indexed = self._listed({"ended": self.ended.get(number), "payments": [trade for trade in self.trades if trade["fill"] == parts[3]]})
            if fill is None:
                return missing("fill_not_found", "No such fill in the verified state: it was never made, or it has ended (paid in full, expired, released or settled). A payment to its address now is for nothing", {**self._proven(), "fill": None, "indexed": indexed})
            possible = number in self.expirable
            # spec/market.md, 5.5 point 4, with the laboratory profile's numbers: a block of 1 second, 16 spare blocks, a grace of 20 seconds.
            earliest = str(int(fill["opened_micros"]) + (int(fill["pay_blocks"]) + 2 * int(fill["confirmations"]) + 16) * 1_000_000 + 20_000_000)
            return 200, {**self._proven(), "fill": dict(fill), "order": json.loads(json.dumps(self.orders[int(fill["order"])])), "last_height": self.last_height(fill), "earliest_end_micros": earliest, "now_elapsed_micros": str(self.now),
                         "expiry": {"possible": possible, "reason": None if possible else "height", "lastHeight": self.last_height(fill), "knownMicros": None, "earliestEndMicros": earliest, "notBeforeMicros": earliest},
                         "bitcoin": dict(self.bitcoin), "indexed": indexed}
        if len(parts) == 4 and parts[:3] == ["v1", "market", "scripts"]:
            row = self.scripts.get(parts[3])
            said = {"status": "free"} if row is None else {"status": "used"} if row[0] == "used" else {"status": "listed", "order": row[1]} if row[0] == "order" else {"status": "in_use", "fill": row[1]}
            return 200, {**self._proven(), "script": parts[3], "form": address.script_form(parts[3]), **said}
        return missing("unknown_route", "No such route")

    def post(self, path: str, raw: bytes) -> tuple[int, dict]:
        """(status, body) for a POST: only /v1/transactions."""
        if path != "/v1/transactions":
            return 404, {"error": {"code": "unknown_route", "message": "No such route"}}
        signed = base64.b64decode(json.loads(raw)["tx"])
        name = wire.transaction_hash(signed)
        self.posted.append(signed)
        if name not in self.included:
            self.height += 1  # the block the action is in
            try:
                self.apply(signed)
            except (Reject, ValueError) as error:
                self.height -= 1
                return 422, {"error": {"code": "rejected", "message": f"The node refused the action: {error}."}, "hash": name}
            self.included[name] = {"raw": signed, "height": self.height, "lookups": 0}
            answer = 202, {"hash": name, "status": "submitted", "kind": signed[19 + 32], "note": "Submitted is not included."}
        else:
            answer = 200, {"hash": name, "status": "already_included", "height": str(self.included[name]["height"])}
        if self.submit_failures:  # the action was taken, and the caller does not learn it
            status, code = self.submit_failures.pop(0)
            return status, {"error": {"code": code, "message": "The node did not answer"}}
        return answer


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *arguments):
        pass

    def _answer(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _serve(self, method: str) -> None:
        world, url = self.server.world, urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))) if method == "POST" else None
        with world.lock:
            world.requests.append((method, self.path))
            if world.on_request is not None:
                world.on_request(method, self.path)
            try:
                status, answer = world.get(url.path, {name: values[0] for name, values in parse_qs(url.query).items()}) if method == "GET" else world.post(url.path, body)
            except (KeyError, ValueError, IndexError):
                status, answer = 400, {"error": {"code": "invalid_request", "message": "The stand-in does not take this request"}}
        self._answer(status, answer)

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")


class FakeApi(ThreadingHTTPServer):
    """The stand-in on 127.0.0.1, at a port the system gives (or ``port``). ``with FakeApi(world) as api: api.base``."""

    daemon_threads = True

    def __init__(self, world: World, port: int = 0):
        super().__init__(("127.0.0.1", port), _Handler)
        self.world, self.base = world, f"http://127.0.0.1:{self.server_address[1]}"
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)

    def handle_error(self, request, client_address):
        pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exception):
        self.shutdown()
        self.server_close()


def seed_of(name: str) -> str:
    """The test key of the account that signed the action ``name`` of spec/market-vectors.json."""
    return next(entry for entry in ENGINE["actions"] if entry["name"] == name)["seed_hex"]


def vector_world() -> World:
    """The accounts of the engine's vectors, with the sell order and the buy order the engine accepted (orders 1 and 2)."""
    world = World()
    world.add_account(5, seed_of("sell_order"), 400_000_000)  # the seller of the vectors
    world.add_account(6, seed_of("buy_order"), 100_000_000)   # the buyer of the vectors
    world.add_account(8, seed_of("sell_the_rest"), 50_000_000)
    for name in ("sell_order", "buy_order"):
        world.apply(bytes.fromhex(next(entry for entry in ENGINE["actions"] if entry["name"] == name)["signed_hex"]))
    world.height += 2
    return world


def guide_world() -> World:
    """The market docs/trading.md shows: ``vector_world``, then the vectors' take of 40 seconds for account 8, of which 4,000 satoshis are paid."""
    world = vector_world()
    world.apply(bytes.fromhex(next(entry for entry in ENGINE["actions"] if entry["name"] == "take_for_another")["signed_hex"]))
    world.height += 1
    world.pay(1, 4000)
    world.height += 1
    return world


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="A stand-in for the API with a small model of the market: for trying the examples by hand. Not the engine, not the API.")
    parser.add_argument("--port", type=int, default=8930)
    chosen = parser.parse_args()
    with FakeApi(guide_world(), chosen.port) as served:
        print(f"The stand-in answers at {served.base} (127.0.0.1 only). Stop it with Ctrl-C.", flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
