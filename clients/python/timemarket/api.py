"""A client for the public API (client-v4/api.mjs, JSON under /v1/). Standard library only (urllib).

What this client calls: the status of the service and the network's fee, its health, the verified
state of an account (with the nonce and authority epoch an action needs), an action by its hash, the
submission of a signed action, and the market: the book of open orders, its depth, one order, fill or
receiving script, an account's orders and fills, the trades and the candles.

WHAT A SCRIPT CANNOT DO: verify a proof. The API hands out a proof with every single order, fill and
script, and with the state of an account, and says that its own server checked it. Checking it again
takes the verifier, which exists in Rust and as WebAssembly for the JavaScript SDK (client-v4/), not
in Python. So a bot that uses this client TRUSTS THE API IT CALLS, for every number it acts on: the
address it pays to, the satoshis a fill still needs, whether a fill exists at all. Call an API that
you run yourself, beside a node you run yourself (deploy/api/README.md). An API run by somebody else
can make a bot pay bitcoin to an address of theirs.

How it behaves:

- Every request has a timeout (10 seconds unless another is given).
- Nothing is retried. For a submission that matters: a submission whose answer was lost may have
  reached the chain. Sending THE SAME BYTES again is safe (the chain takes them once); signing a new
  action for the same purpose is not, until the first is known to have failed. ``submit`` therefore
  never signs and never repeats; the caller keeps the signed bytes and decides.
- A redirect is refused, not followed: a client that follows one would post a signed action to
  wherever a server points.
- An answer is JSON of at most 8 MiB, or an ``ApiError``.
- What the API says from its index is the word of that server, not a proof (its answers say which is
  which, under ``source``). This client verifies nothing; the SDK (client-v4/) does.
- The lists of the market come from the server's index. Each says the height it is as of and whether
  the index agrees with the chain (``market_index``: ``as_of_height``, ``consistent``,
  ``tape_reconciled``). Before acting on a row of a list, read the row itself (``market_order``,
  ``market_fill``, ``market_script``): that answer is the current state, not the index.
- A price of a trade or of a candle is a record of what two parties agreed. It is not what a second
  is worth, and it costs little to write (spec/market.md, section 9). Never let it decide an order.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from . import wire
from .address import script_form

MAX_ANSWER_BYTES = 8 * 1024 * 1024

# The routes of the API this client calls: name -> (method, path).
_ROUTES = {
    "status": ("GET", "/v1/status"),
    "health": ("GET", "/v1/health"),
    "account_state": ("GET", "/v1/accounts/{account}/state"),
    "account": ("GET", "/v1/accounts/{account}"),
    "action": ("GET", "/v1/actions/{hash}"),
    "submit": ("POST", "/v1/transactions"),
    # The market (client-v4/api.mjs, the routes under /v1/market).
    "market": ("GET", "/v1/market"),
    "market_orders": ("GET", "/v1/market/orders"),
    "market_depth": ("GET", "/v1/market/depth"),
    "market_order": ("GET", "/v1/market/orders/{order}"),
    "market_fill": ("GET", "/v1/market/fills/{fill}"),
    "market_script": ("GET", "/v1/market/scripts/{script}"),
    "market_trades": ("GET", "/v1/market/trades"),
    "market_candles": ("GET", "/v1/market/candles"),
    "account_market": ("GET", "/v1/accounts/{account}/market"),
}
# The intervals of candles: the chain's own, and those the API computes from its list of trades.
CANDLE_INTERVALS = ("hour", "1m", "5m", "15m", "1d")


class ApiError(Exception):
    """A request that the API refused or that did not get an answer.

    ``status`` is the HTTP status (``None`` when there was no answer: no connection, a timeout),
    ``code`` the API's own code for the refusal (such as ``rejected``, ``nonce_used``,
    ``wrong_network``, ``busy``), ``body`` the whole JSON answer when there was one, and
    ``retry_after`` the seconds the service asked the caller to wait, when it said so.
    """

    def __init__(self, message: str, *, status: int | None = None, code: str | None = None, body=None, retry_after: int | None = None):
        super().__init__(message)
        self.status, self.code, self.body, self.retry_after = status, code, body, retry_after


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


class TimeApi:
    """The public API of one network, at ``base_url`` (such as ``https://api.example.org``)."""

    def __init__(self, base_url: str, *, timeout: float = 10.0):
        parts = urllib.parse.urlsplit(base_url) if isinstance(base_url, str) else None
        if parts is None or parts.scheme not in ("http", "https") or not parts.netloc or parts.query or parts.fragment or parts.username or parts.password:
            raise ValueError("The address of the API is http:// or https://, a host, and at most a path: no query, no user name")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 300:
            raise ValueError("timeout is a number of seconds, above 0 and at most 300")
        self._base, self._timeout = base_url.rstrip("/"), float(timeout)
        # No redirects, and no proxy or handler beyond what urllib takes from the environment.
        self._opener = urllib.request.build_opener(_NoRedirect)

    # ------------------------------------------------------------ one place for every request
    def _call(self, route: str, *, body: dict | None = None, query: dict | None = None, **params: str):
        method, path = _ROUTES[route]
        url = self._base + path.format(**{name: urllib.parse.quote(value, safe="") for name, value in params.items()})
        # A parameter that was not given is left out: the API refuses a name it does not know, and has its own defaults.
        given = {name: value for name, value in (query or {}).items() if value is not None}
        if given:
            url += "?" + urllib.parse.urlencode(given)
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        if (method == "POST") != (data is not None):
            raise ValueError(f"{route} is a {method} request")
        request = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", "User-Agent": "timemarket-python"})
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(request, timeout=self._timeout) as answer:
                return self._json(answer.read(MAX_ANSWER_BYTES + 1), answer.status)
        except urllib.error.HTTPError as error:
            with error:
                raw = error.read(MAX_ANSWER_BYTES + 1)
            wait = error.headers.get("Retry-After") if error.headers else None
            retry_after = int(wait) if isinstance(wait, str) and re.fullmatch(r"[0-9]{1,6}", wait) else None
            if 300 <= error.code < 400:
                raise ApiError(f"The API answered with a redirect ({error.code}), which this client does not follow", status=error.code, retry_after=retry_after) from None
            try:
                answer = self._json(raw, error.code)
            except ApiError:
                answer = None
            said = answer.get("error") if isinstance(answer, dict) else None
            code = said.get("code") if isinstance(said, dict) and isinstance(said.get("code"), str) else None
            message = said.get("message") if isinstance(said, dict) and isinstance(said.get("message"), str) else f"The API refused the request ({error.code})"
            raise ApiError(message, status=error.code, code=code, body=answer, retry_after=retry_after) from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            reason = getattr(error, "reason", error)
            raise ApiError(f"No answer from the API: {reason}") from None

    @staticmethod
    def _json(raw: bytes, status: int):
        if len(raw) > MAX_ANSWER_BYTES:
            raise ApiError("The answer of the API is larger than 8 MiB", status=status)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError("The answer of the API is not JSON", status=status) from None

    @staticmethod
    def _account(account) -> str:
        if isinstance(account, int) and not isinstance(account, bool):
            account = str(account)
        if not isinstance(account, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", account) or int(account) >= 2**64 - 1:
            raise ValueError("An account is its number: a whole number, without leading zeros")
        return account

    # ------------------------------------------------------------ what the API serves today
    def status(self) -> dict:
        """The service and its network: ``network.network_id``, ``network.fee_micros`` (the fee of an action), the indexer's height."""
        return self._call("status")

    def health(self) -> dict:
        """Whether the service is following the chain. An unhealthy service answers 503, which is an ``ApiError`` here."""
        return self._call("health")

    def account_state(self, account) -> dict:
        """The state of an account, read with a proof by the service: ``account`` holds ``nonce``, ``auth_epoch``, ``balance``, ``devices``.

        An action is signed with nonce ``account.nonce + 1`` and authority epoch ``account.auth_epoch``.
        """
        return self._call("account_state", account=self._account(account))

    def account(self, account) -> dict:
        """An account by its number: what the service read with a proof, beside what its index holds of it.

        ``indexed.state_is_behind`` is true when the index already holds an action of the account that the proven
        state does not show yet (the state is read a block behind). A script that signs then counts its nonce
        itself and does not take ``account_state`` for the newest word (``bot.Sender`` does this).
        """
        return self._call("account", account=self._account(account))

    def action(self, action_hash: str) -> dict:
        """An action that is in a block, by its hash (``wire.transaction_hash``). 404 (``not_found``) while it is not.

        For an order (kind 50), a take (52) and a sale to a buy order (53) the answer has ``market.made``:
        ``{"order": id}`` or ``{"fill": id}``, the row the action made as the index counted it, or None while
        the index has not followed the block. Read that row (``market_order``, ``market_fill``) before acting on it.
        """
        if not isinstance(action_hash, str) or not re.fullmatch(r"[0-9A-Fa-f]{64}", action_hash):
            raise ValueError("A hash is 64 hexadecimal characters")
        return self._call("action", hash=action_hash.upper())

    def submit(self, signed_action: bytes) -> dict:
        """Hands a signed action (``wire.sign_action``) to the network. Sent once, never retried.

        The answer says ``submitted`` (the node took it; it is not in a block yet) or
        ``already_included``. Keep the bytes until ``action(hash)`` shows them in a block: after an
        error or a lost answer, send THE SAME BYTES again, and sign nothing new for the same purpose
        until you know the first did not happen.
        """
        if not isinstance(signed_action, (bytes, bytearray)) or len(signed_action) < wire.HEADER_BYTES + 64:
            raise ValueError("A signed action is bytes, as wire.sign_action returns them")
        return self._call("submit", body={"tx": base64.b64encode(bytes(signed_action)).decode("ascii")})

    # ------------------------------------------------------------ the market
    @staticmethod
    def _number(value, what: str) -> str:
        """The id of an order or of a fill: a whole number from 1."""
        if isinstance(value, int) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,15}", value):
            raise ValueError(f"{what} is its number: a whole number from 1, without leading zeros")
        return value

    @staticmethod
    def _limit(value, most: int = 200) -> str | None:
        if value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= most:
            raise ValueError(f"limit is a whole number from 1 to {most}")
        return str(value)

    @staticmethod
    def _cursor(value, pattern: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError("cursor is a next_cursor value of an earlier answer")
        return value

    @staticmethod
    def _micros(value, name: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 10**16:
            raise ValueError(f"{name} is a moment in microseconds since 1970, as a whole number")
        return str(value)

    def market(self) -> dict:
        """The market of the network: its rules, the summary row and where the server's index stands.

        ``rules`` are the numbers of the network's profile, ``summary`` the row the chain keeps (how many
        orders and fills exist, the sums of all proven payments), ``bitcoin`` the Bitcoin header chain
        the chain follows (``halted``, and ``fresh`` when the server can tell), ``market_index`` how
        far to rely on the lists. A network without the market answers 404 (``no_market``), which is an
        ``ApiError`` here.
        """
        return self._call("market")

    def market_orders(self, side: str, *, limit: int | None = None, cursor: str | None = None) -> dict:
        """One side of the book, best price first: ``"sell"`` by rising price, ``"buy"`` by falling price.

        Each item has what is left on offer (``amount_micros``), what it costs (``sats``), the smallest
        trade (``min_sats``), the confirmations and the time to pay, the deposit terms, and whether its
        row allows a new fill (``takes_fill``). ``next_cursor`` goes back in as ``cursor``. Read an
        order by itself (``market_order``) before you take it.
        """
        if side not in ("sell", "buy"):
            raise ValueError('side is "sell" or "buy"')
        return self._call("market_orders", query={"side": side, "limit": self._limit(limit), "cursor": self._cursor(cursor, r"[1-9][0-9]{0,15}\.[1-9][0-9]{0,15}")})

    def market_depth(self, levels: int | None = None) -> dict:
        """Both sides of the book added up by price: the first ``levels`` prices of each (20 unless given, at most 200)."""
        return self._call("market_depth", query={"levels": self._limit(levels)})

    def market_order(self, order) -> dict:
        """One order as the current state holds it, and whether its owner still stands (``owner_stands``).

        404 (``order_not_found``) when the state holds no such order: never made, cancelled, or all of
        it sold and paid. The answer carries a proof that this client cannot check: see the top of
        this file.
        """
        return self._call("market_order", order=self._number(order, "An order"))

    def market_fill(self, fill) -> dict:
        """One fill as the current state holds it: ``fill.script`` is where the bitcoin must arrive and ``fill.sats`` what is still to pay.

        Read it again before EVERY payment: a fill shrinks as it is paid, and a fill that has ended is
        404 (``fill_not_found``), after which a payment to its address buys nothing. ``last_height``
        is the last Bitcoin height that still counts for it, ``expiry`` whether it can be ended now,
        ``indexed`` what the server's index saw of it (the payments counted, and how it ended).
        """
        return self._call("market_fill", fill=self._number(fill, "A fill"))

    def market_script(self, script: str) -> dict:
        """What a receiving script serves in the current state: ``status`` is free, listed, in_use or used.

        A script serves one fill, ever: do not list one whose status is not ``free``, and never pay to
        one that is ``used``.
        """
        script_form(script)
        return self._call("market_script", script=script)

    def market_trades(self, *, limit: int | None = None, cursor: str | None = None, order: str | None = None) -> dict:
        """The recorded trades: one for every proven payment, newest first unless ``order`` is ``"asc"``.

        ``market_index.tape_reconciled`` says whether the list adds up to what the chain counted. A
        price here is what two parties agreed for one fill, not what a second is worth.
        """
        if order not in (None, "asc", "desc"):
            raise ValueError('order is "asc" or "desc"')
        return self._call("market_trades", query={"limit": self._limit(limit), "cursor": self._cursor(cursor, r"[1-9][0-9]{0,15}\.(0|[1-9][0-9]{0,5})"), "order": order})

    def market_candles(self, interval: str, *, from_micros: int | None = None, to_micros: int | None = None, limit: int | None = None) -> dict:
        """Candles of recorded trades, newest first: ``"hour"`` is the candle the chain keeps, the others are computed by the API.

        ``from_micros`` and ``to_micros`` bound the start of an interval, in microseconds since 1970;
        ``next_to`` of an answer goes back in as ``to_micros`` (as a whole number) for the page before.
        Records of trades, not a valuation: see the top of this file.
        """
        if interval not in CANDLE_INTERVALS:
            raise ValueError("interval is one of " + ", ".join(CANDLE_INTERVALS))
        return self._call("market_candles", query={"interval": interval, "from": self._micros(from_micros, "from_micros"), "to": self._micros(to_micros, "to_micros"), "limit": self._limit(limit)})

    def account_market(self, account, *, limit: int | None = None, cursor: str | None = None) -> dict:
        """An account's part in the market: the open ``orders`` it owns, the open ``fills`` with its ``roles`` in each, and what ``ended``.

        A role is ``payer`` (it promised the bitcoin), ``owner`` (its seconds are in the fill) or
        ``to`` (the seconds go to it). ``ended.items`` say how each fill ended (``how``: paid,
        expired, released, settled); ``limit`` and ``cursor`` page them.
        """
        return self._call("account_market", account=self._account(account), query={"limit": self._limit(limit), "cursor": self._cursor(cursor, r"[1-9][0-9]{0,15}\.(0|[1-9][0-9]{0,5})")})
