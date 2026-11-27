"""The payloads of the market's actions: kinds 50 to 58 (spec/market.md, section 6).

A payload has exactly the fields of its kind, each in its one form, and is checked here before it is
signed. The builders (``sell_order`` … ``new_scripts``) take arguments by name and return the payload,
so that no caller writes a field name; ``wire.sign_action`` takes such a payload under its kind.

    50 sell  {"amount_micros":D,"confirmations":D,"deposit_ppm":D,"min_deposit_micros":D,"min_sats":D,"pay_blocks":D,"price":D,"scripts":[X,…],"side":"sell"}
    50 buy   {"amount_micros":D,"confirmations":D,"deposit_ppm":D,"forms":[F,…],"min_sats":D,"pay_blocks":D,"price":D,"side":"buy"}
    51       {"order":D}                                             cancel
    52       {"amount_micros":D,"order":D,"sats":D,"to":D}           take a sell order
    53       {"amount_micros":D,"confirmations":D,"order":D,"sats":D,"script":X}   sell to a buy order
    54       {"block_hash":H,"coinbase":X,"fill":D,"merkle_proof":X,"transaction":X,"vout":D}   proof of payment
    55, 56, 57   {"fill":D}                                          expire, release, settle
    58       {"order":D,"scripts":[X,…]}                             new receiving scripts

D is a decimal string without leading zeros, X lowercase hexadecimal, H 64 lowercase hexadecimal
characters, F one of ``FORMS``.

Checked here: the field set of the kind and the side; a price from 1 to 10^15; an amount of at least a
microsecond; what an order costs at most 2.1 × 10^15 satoshis and at least its ``min_sats``;
``deposit_ppm`` at most 1,000,000; a least deposit at most the amount; 1 to 16 scripts, each of a
standard form, none twice; forms from the five names, ascending, each once; a list is a list, never
``None``; a proof's block hash, its payment (65 to 100,000 bytes) and its coinbase (at most 150,000
bytes), both serialized without witness data, and its Merkle proof (86 to 4,096 bytes); ids of orders
and fills from 1.

NOT checked here, because it depends on the network's profile (spec/market.md, 2.1) or on its state,
and the engine refuses it: ``confirmations`` and ``pay_blocks`` are held to the outer bounds 1 to 100
and 1 to 144 only (a production network asks at least 3 of each); ``min_sats`` to at least 1
(production: 1,000); a buy order's ``deposit_ppm`` to no least value (production: 30,000); ``sats`` of
a fill to what any price allows, not to the order's price (``take`` and ``sell`` compute it); whether
an order, a fill or an account exists, whether a script has served, whether the sender may send the
action, and everything of a proof beyond its form. Bitcoin mainnet is closed to kinds 52 to 54.

The same rules as the SDK (client-v4/time-sdk.js, ``marketActionPayload`` and its builders), and the
same vectors (spec/market-vectors.json). Every refusal is a ``ValueError`` that says why.
"""
from __future__ import annotations

import json
import re
from types import MappingProxyType

from .address import FORMS, script_form
from .amounts import MICROS_MAX, PRICE_MAX, SATS_MAX, sats as _cost

KINDS = MappingProxyType(
    {"order": 50, "cancel": 51, "take": 52, "sell": 53, "proof": 54, "expire": 55, "release": 56, "settle": 57, "scripts": 58}
)
"""The kinds of the market's actions, by name."""
LIMITS = MappingProxyType(
    {
        "price_max": PRICE_MAX,
        "sats_max": SATS_MAX,
        "deposit_ppm_max": 1_000_000,
        "confirmations_min": 1,
        "confirmations_max": 100,
        "pay_blocks_min": 1,
        "pay_blocks_max": 144,
        "scripts_max": 16,
        "transaction_bytes_min": 65,
        "transaction_bytes_max": 100_000,
        "coinbase_bytes_min": 1,
        "coinbase_bytes_max": 150_000,
        "merkle_proof_bytes_min": 86,
        "merkle_proof_bytes_max": 4096,
        "proof_bytes_per_fee": 256,
        "payload_bytes_max": 512 * 1024,
    }
)
"""The bounds checked here. Those of ``confirmations``, ``pay_blocks`` are the outer ones: a network asks more."""

_FIELDS = {
    "sell": ("amount_micros", "confirmations", "deposit_ppm", "min_deposit_micros", "min_sats", "pay_blocks", "price", "scripts", "side"),
    "buy": ("amount_micros", "confirmations", "deposit_ppm", "forms", "min_sats", "pay_blocks", "price", "side"),
    51: ("order",),
    52: ("amount_micros", "order", "sats", "to"),
    53: ("amount_micros", "confirmations", "order", "sats", "script"),
    54: ("block_hash", "coinbase", "fill", "merkle_proof", "transaction", "vout"),
    55: ("fill",),
    56: ("fill",),
    57: ("fill",),
    58: ("order", "scripts"),
}
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,19}")
_HEX = re.compile(r"[0-9a-f]*")


def _whole(value, field: str, least: int, most: int) -> int:
    if not isinstance(value, str) or not _DECIMAL.fullmatch(value) or int(value) > MICROS_MAX:
        raise ValueError(f"{field} is a whole number as a decimal string without leading zeros")
    number = int(value)
    if number < least or number > most:
        raise ValueError(f"{field} is from {least} to {most}")
    return number


def _hex(value, field: str, least: int, most: int) -> None:
    if not isinstance(value, str) or len(value) % 2 or not 2 * least <= len(value) <= 2 * most or not _HEX.fullmatch(value):
        if least == most:
            raise ValueError(f"{field} is {2 * least} lowercase hexadecimal characters")
        raise ValueError(f"{field} is lowercase hexadecimal of {least} to {most} bytes")


def _transaction(value, field: str) -> None:
    """A transaction as a proof carries it: without witness data.

    A serialization with witness data has the marker 00 where one without has its number of inputs,
    which is never zero. (``bitcoin.strip_witness`` removes the witness data; ``bitcoin.proof_payload``
    puts a proof together from what a Bitcoin node gives.)
    """
    _hex(value, field, LIMITS[f"{field}_bytes_min"], LIMITS[f"{field}_bytes_max"])
    if value[8:10] == "00":
        raise ValueError(f"{field} is serialized without witness data: this one carries its witness data, or has no input")


def _scripts(value) -> None:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= LIMITS["scripts_max"]:
        raise ValueError("scripts is a list of 1 to 16 receiving scripts")
    for script in value:
        script_form(script)
    if len(set(value)) != len(value):
        raise ValueError("A receiving script is listed once")


def _forms(value) -> None:
    good = isinstance(value, (list, tuple)) and len(value) >= 1 and all(isinstance(form, str) and form in FORMS for form in value)
    if not good or any(value[index - 1] >= value[index] for index in range(1, len(value))):
        raise ValueError("forms is a list of at least one of p2pkh, p2sh, p2tr, p2wpkh, p2wsh, in this order, each once")


def _side(value) -> None:
    if not isinstance(value, str) or value not in ("sell", "buy"):
        raise ValueError('The side of an order is "sell" or "buy"')


_CHECKS = {
    "amount_micros": lambda v: _whole(v, "amount_micros", 1, MICROS_MAX),
    "confirmations": lambda v: _whole(v, "confirmations", LIMITS["confirmations_min"], LIMITS["confirmations_max"]),
    "deposit_ppm": lambda v: _whole(v, "deposit_ppm", 0, LIMITS["deposit_ppm_max"]),
    "min_deposit_micros": lambda v: _whole(v, "min_deposit_micros", 0, MICROS_MAX),
    "min_sats": lambda v: _whole(v, "min_sats", 1, SATS_MAX),
    "pay_blocks": lambda v: _whole(v, "pay_blocks", LIMITS["pay_blocks_min"], LIMITS["pay_blocks_max"]),
    "price": lambda v: _whole(v, "price", 1, PRICE_MAX),
    "sats": lambda v: _whole(v, "sats", 1, SATS_MAX),
    "order": lambda v: _whole(v, "order", 1, MICROS_MAX),
    "fill": lambda v: _whole(v, "fill", 1, MICROS_MAX),
    "to": lambda v: _whole(v, "to", 0, MICROS_MAX),
    "vout": lambda v: _whole(v, "vout", 0, 0xFFFFFFFF),
    "side": _side,
    "scripts": _scripts,
    "script": script_form,
    "forms": _forms,
    "block_hash": lambda v: _hex(v, "block_hash", 32, 32),
    "transaction": lambda v: _transaction(v, "transaction"),
    "coinbase": lambda v: _transaction(v, "coinbase"),
    "merkle_proof": lambda v: _hex(v, "merkle_proof", LIMITS["merkle_proof_bytes_min"], LIMITS["merkle_proof_bytes_max"]),
}


def action_payload(kind: int, payload: dict) -> dict:
    """A payload of kind 50 to 58, checked: a new ``dict`` with the fields in the order they are signed.

    Raises ``ValueError`` for anything else. ``wire.canonical_payload`` writes exactly this.
    """
    if not isinstance(kind, int) or isinstance(kind, bool) or not 50 <= kind <= 58:
        raise ValueError("The kinds of the market are 50 to 58")
    if type(payload) is not dict or not all(isinstance(key, str) for key in payload):
        raise ValueError("A market payload is a plain dict")
    if kind == 50:
        _side(payload.get("side"))
    fields = _FIELDS[payload["side"] if kind == 50 else kind]
    if len(payload) != len(fields) or any(field not in payload for field in fields):
        side = f" ({payload['side']})" if kind == 50 else ""
        raise ValueError(f"A payload of kind {kind}{side} has exactly the fields {', '.join(fields)}")
    read, canonical = {}, {}
    for field in fields:
        value = payload[field]
        read[field] = _CHECKS[field](value)
        canonical[field] = list(value) if isinstance(value, (list, tuple)) else value
    if kind == 50:
        try:
            worth = _cost(read["amount_micros"], read["price"])
        except ValueError as error:
            raise ValueError(str(error)) from None
        if worth < read["min_sats"]:
            raise ValueError("An order is worth at least its smallest trade: amount_micros at price costs less than min_sats")
        if payload["side"] == "sell" and read["min_deposit_micros"] > read["amount_micros"]:
            raise ValueError("The least deposit of a fill is at most what the order offers")
    # The satoshis of a fill are the price of its amount. The price is the order's, which is not in the
    # payload: here they are held to what the lowest and the highest price make of the amount.
    if kind in (52, 53) and not -(-read["amount_micros"] // 10**12) <= read["sats"] <= read["amount_micros"] * 1000:
        raise ValueError("sats is the price of amount_micros at the price of the order: ceil(amount_micros × price / 10^12)")
    return canonical


def _decimal(value, name: str) -> str:
    """A whole number given to a builder: an ``int`` or a decimal string without leading zeros."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not _DECIMAL.fullmatch(value) or int(value) > MICROS_MAX:
        raise ValueError(f"{name} is a whole number from 0 to 2^64-1: an int, or a decimal string without leading zeros")
    return value


def _list(value, name: str) -> list:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} is a list")
    return list(value)


# ---------------------------------------------------------------- the builders
# Every argument is given by name, and all of them are needed.
def sell_order(*, amount_micros, price, scripts, confirmations, pay_blocks, min_sats, deposit_ppm, min_deposit_micros) -> dict:
    """Kind 50, a sell order: ``amount_micros`` on offer at ``price``, paid to one of ``scripts``.

    ``price`` is in millionths of a satoshi for one second. ``scripts`` are receiving scripts of the
    seller, one for each fill the order can have. ``confirmations`` is what the seller asks of every
    payment, ``pay_blocks`` the time to pay in Bitcoin blocks, ``min_sats`` the smallest trade. A taker
    locks a deposit of ``deposit_ppm`` millionths of what they take, or ``min_deposit_micros``,
    whichever is more.
    """
    return action_payload(
        50,
        {
            "amount_micros": _decimal(amount_micros, "amount_micros"),
            "confirmations": _decimal(confirmations, "confirmations"),
            "deposit_ppm": _decimal(deposit_ppm, "deposit_ppm"),
            "min_deposit_micros": _decimal(min_deposit_micros, "min_deposit_micros"),
            "min_sats": _decimal(min_sats, "min_sats"),
            "pay_blocks": _decimal(pay_blocks, "pay_blocks"),
            "price": _decimal(price, "price"),
            "scripts": _list(scripts, "scripts"),
            "side": "sell",
        },
    )


def buy_order(*, amount_micros, price, forms, confirmations, pay_blocks, min_sats, deposit_ppm) -> dict:
    """Kind 50, a buy order: a promise to pay for ``amount_micros`` at ``price``, with a bond.

    The bond is ``deposit_ppm`` millionths of the amount. ``forms`` are the forms of receiving script
    the buyer can pay to, in any order. ``confirmations`` is the most the buyer will wait for.
    """
    return action_payload(
        50,
        {
            "amount_micros": _decimal(amount_micros, "amount_micros"),
            "confirmations": _decimal(confirmations, "confirmations"),
            "deposit_ppm": _decimal(deposit_ppm, "deposit_ppm"),
            "forms": sorted(_list(forms, "forms"), key=str),
            "min_sats": _decimal(min_sats, "min_sats"),
            "pay_blocks": _decimal(pay_blocks, "pay_blocks"),
            "price": _decimal(price, "price"),
            "side": "buy",
        },
    )


def cancel(*, order) -> dict:
    """Kind 51: the owner takes back what an order still offers."""
    return action_payload(51, {"order": _decimal(order, "order")})


def take(*, order, amount_micros, price, to) -> dict:
    """Kind 52: take ``amount_micros`` of sell order ``order``, whose price is ``price``, for account ``to``.

    The sender promises the bitcoin and locks the deposit. ``price`` is the order's, read from the
    chain; ``sats`` is computed here.
    """
    amount = _decimal(amount_micros, "amount_micros")
    return action_payload(
        52,
        {
            "amount_micros": amount,
            "order": _decimal(order, "order"),
            "sats": str(_cost(int(amount), int(_decimal(price, "price")))),
            "to": _decimal(to, "to"),
        },
    )


def sell(*, order, amount_micros, price, confirmations, script) -> dict:
    """Kind 53: sell ``amount_micros`` to buy order ``order``, whose price is ``price``, to be paid to ``script``.

    ``confirmations`` is what the seller asks of the payment (at most what the buyer waits for).
    ``sats`` is computed here.
    """
    amount = _decimal(amount_micros, "amount_micros")
    return action_payload(
        53,
        {
            "amount_micros": amount,
            "confirmations": _decimal(confirmations, "confirmations"),
            "order": _decimal(order, "order"),
            "sats": str(_cost(int(amount), int(_decimal(price, "price")))),
            "script": script,
        },
    )


def proof(*, fill, block_hash, transaction, coinbase, vout, merkle_proof) -> dict:
    """Kind 54: the proof that output ``vout`` of ``transaction``, in the block ``block_hash``, paid for ``fill``.

    ``coinbase`` is the first transaction of that block; both are serialized without witness data.
    ``merkle_proof`` is what Bitcoin Core's gettxoutproof returns for the two transaction ids. Anyone
    may send it, for a payment in full or of a part; a part counts if it is at least the order's
    ``min_sats`` or half of what is still to pay (``amounts.part_counts``), and leaves the fill open
    for the rest. ``bitcoin.proof_payload`` makes this payload from what a
    Bitcoin node gives, and checks more.
    """
    return action_payload(
        54,
        {
            "block_hash": block_hash,
            "coinbase": coinbase,
            "fill": _decimal(fill, "fill"),
            "merkle_proof": merkle_proof,
            "transaction": transaction,
            "vout": _decimal(vout, "vout"),
        },
    )


def expire(*, fill) -> dict:
    """Kind 55: a fill that was not paid in time ends. Anyone may send it."""
    return action_payload(55, {"fill": _decimal(fill, "fill")})


def release(*, fill) -> dict:
    """Kind 56: the account the seconds of a fill would go to gives it up; the deposit is lost."""
    return action_payload(56, {"fill": _decimal(fill, "fill")})


def settle(*, fill) -> dict:
    """Kind 57: the owner of a fill's seconds hands them over without a proof."""
    return action_payload(57, {"fill": _decimal(fill, "fill")})


def new_scripts(*, order, scripts) -> dict:
    """Kind 58: new receiving scripts for an open sell order of the sender."""
    return action_payload(58, {"order": _decimal(order, "order"), "scripts": _list(scripts, "scripts")})


def payload_bytes(kind: int, payload: dict) -> bytes:
    """The bytes of a market payload as they are signed: checked, fields ascending, no spaces."""
    body = json.dumps(action_payload(kind, payload), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > LIMITS["payload_bytes_max"]:
        raise ValueError("The payload of an action is at most 512 KiB")
    return body


def action_fee(kind: int, payload: dict, network_fee_micros) -> int:
    """What an action of the market costs its sender in fees, in microseconds.

    ``network_fee_micros`` is the network's fee (``network.fee_micros`` of the API's status). The fee,
    and for kinds 50 and 58 once more for each script listed, for kind 54 once more for every 256
    bytes of the payload as it is signed: a proof of an ordinary payment costs about a dozen fees, and
    the chain refuses a proof whose sender cannot pay that with what it holds and what the proof
    brings it. Beside its fees an action locks what it locks (the seconds of a sell order, a bond, a
    deposit, the seconds sold).
    """
    fee = int(_decimal(network_fee_micros, "network_fee_micros"))
    checked = action_payload(kind, payload)
    if kind == 54:
        more = len(json.dumps(checked, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) // LIMITS["proof_bytes_per_fee"]
    else:
        more = len(checked.get("scripts", ()))
    cost = fee * (1 + more)
    if cost > MICROS_MAX:
        raise ValueError("The fee of this action is more than a balance can hold")
    return cost
