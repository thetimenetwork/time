"""Amounts and prices of the market (spec/market.md, section 3), in whole numbers.

Seconds are counted in microseconds and bitcoin in satoshis. A price is a whole number from 1 to
10^15: millionths of a satoshi for one second. So a price of 250,000,000 is 250 satoshis a second.
Python's integers have no size, so nothing here rounds or overflows; never use ``float`` for these.
"""
from __future__ import annotations

PRICE_MAX = 10**15
"""The highest price: 10^15 millionths of a satoshi for one second."""
SATS_MAX = 2_100_000_000_000_000
"""All the satoshis there will ever be: no trade costs more."""
MICROS_MAX = 2**64 - 1
"""The largest number a row of the chain holds."""
_SCALE = 10**12


def _whole(value, name: str, least: int, most: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} is a whole number (int), not {type(value).__name__}")
    if value < least or value > most:
        raise ValueError(f"{name} is from {least} to {most}")
    return value


def sats(amount_micros: int, price: int) -> int:
    """What ``amount_micros`` microseconds cost at ``price``, in satoshis: ceil(amount × price / 10^12).

    Every rule of the market uses this one formula. Raises ``ValueError`` for a price outside 1 to
    10^15, and when the result would pass 2.1 × 10^15 satoshis, as the engine refuses both.
    """
    _whole(amount_micros, "amount_micros", 0, MICROS_MAX)
    if not isinstance(price, int) or isinstance(price, bool):
        raise TypeError(f"price is a whole number (int), not {type(price).__name__}")
    if price < 1 or price > PRICE_MAX:
        raise ValueError("A price is from 1 to 10^15 millionths of a satoshi for one second")
    cost = -(-amount_micros * price // _SCALE)
    if cost > SATS_MAX:
        raise ValueError("This amount at this price costs more satoshis than exist")
    return cost


def bought(paid_sats: int, price: int) -> int:
    """The microseconds ``paid_sats`` satoshis buy at ``price``: floor(sats × 10^12 / price).

    Paying the price always buys the amount: ``bought(sats(a, p), p) >= a``. Like the engine, the
    result stops at the largest number a row holds (2^64 − 1); a fill never gives more than it holds
    anyway.
    """
    _whole(paid_sats, "paid_sats", 0, MICROS_MAX)
    _whole(price, "price", 1, PRICE_MAX)
    return min(paid_sats * _SCALE // price, MICROS_MAX)


def part_seconds(amount_micros: int, sats: int, paid: int) -> int:
    """What a payment of a part buys of a fill: floor(amount × paid / sats) microseconds.

    ``amount_micros`` is what the fill still holds and ``sats`` what is still to pay for it (both read
    from the fill's row); ``paid`` is the value of the payment, less than ``sats``. A payment of
    ``sats`` or more is a payment in full and buys all the fill holds: see ``fill_after_payment``.
    Whether the chain takes a part at all is ``part_counts``.
    """
    _whole(amount_micros, "amount_micros", 1, MICROS_MAX)
    _whole(sats, "sats", 1, SATS_MAX)
    _whole(paid, "paid", 1, MICROS_MAX)
    if paid >= sats:
        raise ValueError("A payment of all that is still to pay, or more, is a payment in full, not a part")
    return amount_micros * paid // sats


def part_counts(sats: int, paid: int, order_min_sats: int) -> bool:
    """Whether the chain counts a payment of ``paid`` satoshis for a fill that still needs ``sats``.

    It counts if it is at least the smallest trade of the fill's order (``order_min_sats``, the
    order's ``min_sats``), or at least half of what the fill still needs (2 × paid ≥ sats), or all of
    it (spec/market.md, 5.2 point 3 and 6.5). So a seller is not paid in outputs too small to spend,
    and a payment that came a little short, and its top-up, are never lost. A payment that does not
    count stays with the seller and buys nothing: do not send one.
    """
    _whole(sats, "sats", 1, SATS_MAX)
    _whole(paid, "paid", 1, MICROS_MAX)
    _whole(order_min_sats, "order_min_sats", 1, SATS_MAX)
    return paid >= order_min_sats or 2 * paid >= sats


def fill_after_payment(amount_micros: int, sats: int, deposit_micros: int, paid: int) -> dict:
    """What a proven payment of ``paid`` satoshis does to a fill (spec/market.md, 6.5).

    Returns ``{"seconds", "deposit_back", "amount_micros", "sats", "deposit_micros", "ends"}``:
    ``seconds`` go to the account the fill is for and ``deposit_back`` returns to the payer; the three
    fields named as in a fill's row are what the fill holds afterwards, and ``ends`` says whether it
    is over.

    - ``paid >= sats``: paid in full. All the seconds are delivered, the whole deposit returns, the
      fill ends. Satoshis above ``sats`` buy nothing more.
    - otherwise a part: it buys ``part_seconds``, returns floor(deposit × seconds / amount) of the
      deposit, and what is still to pay falls by exactly what was paid. So a buyer pays, in all,
      exactly the satoshis agreed, in as many payments as they like.

    This says what a payment does if the chain counts it; ``part_counts`` says whether it does.
    """
    _whole(deposit_micros, "deposit_micros", 0, MICROS_MAX)
    _whole(amount_micros, "amount_micros", 1, MICROS_MAX)
    _whole(sats, "sats", 1, SATS_MAX)
    _whole(paid, "paid", 1, MICROS_MAX)
    if paid >= sats:
        return {"seconds": amount_micros, "deposit_back": deposit_micros, "amount_micros": 0, "sats": 0, "deposit_micros": 0, "ends": True}
    seconds = part_seconds(amount_micros, sats, paid)
    if seconds < 1:
        raise ValueError("This payment buys less than a microsecond: the chain refuses it")
    back = deposit_micros * seconds // amount_micros
    return {"seconds": seconds, "deposit_back": back, "amount_micros": amount_micros - seconds, "sats": sats - paid, "deposit_micros": deposit_micros - back, "ends": False}
