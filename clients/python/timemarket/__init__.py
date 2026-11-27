"""A small client for the market of seconds against bitcoin (spec/market.md), for people who automate trading.

- ``timemarket.address``: Bitcoin addresses and receiving scripts (``address_to_script``, ``script_to_address``, ``script_form``).
- ``timemarket.bitcoin``: what a proof of payment needs (``strip_witness``, ``transaction_id``, ``transaction_outputs``,
  ``merkle_proof_matches``, ``proof_payload``).
- ``timemarket.amounts``: the price arithmetic (``sats``, ``bought``, ``part_seconds``, ``part_counts``,
  ``fill_after_payment``).
- ``timemarket.actions``: the payload of each action, checked (``sell_order``, ``buy_order``, ``cancel``, ``take``, ``sell``,
  ``proof``, ``expire``, ``release``, ``settle``, ``new_scripts``, ``action_payload``, ``action_fee``).
- ``timemarket.wire``: the envelope and its signature (``sign_action``, ``build_action``, ``decode_action``, ``verify_action``).
- ``timemarket.keys``: where a script gets its signing key, by a call you write (``seed_from_key_store``, ``seed_from_env``,
  ``seed_from_file``); nothing is looked for by itself.
- ``timemarket.api``: the public API over HTTP (``TimeApi``, ``ApiError``), with the market's routes (the book, the
  depth, one order, fill or script, the trades, the candles, an account's orders and fills).
- ``timemarket.bot``: what a script checks before it acts, and what the examples share (``check_account``,
  ``check_key``, ``check_index``, ``check_bitcoin``, ``AddressFile``, ``Sender``).

The example scripts are in ``clients/python/examples``; docs/trading.md is the guide. See README.md.
"""
from . import actions, address, amounts, api, bitcoin, bot, keys, wire
from .actions import KINDS, action_fee, action_payload
from .address import FORMS, NETWORKS, address_to_script, script_form, script_to_address
from .amounts import bought, fill_after_payment, part_counts, part_seconds, sats
from .api import ApiError, TimeApi
from .bitcoin import merkle_proof_matches, proof_payload, strip_witness, transaction_id, transaction_outputs
from .wire import build_action, decode_action, public_key, sign_action, transaction_hash, verify_action

__version__ = "0.1.0"
__all__ = [
    "actions", "address", "amounts", "api", "bitcoin", "bot", "keys", "wire",
    "KINDS", "FORMS", "NETWORKS",
    "action_fee", "action_payload", "address_to_script", "script_form", "script_to_address",
    "bought", "fill_after_payment", "part_counts", "part_seconds", "sats", "ApiError", "TimeApi",
    "merkle_proof_matches", "proof_payload", "strip_witness", "transaction_id", "transaction_outputs",
    "build_action", "decode_action", "public_key", "sign_action", "transaction_hash", "verify_action",
]
