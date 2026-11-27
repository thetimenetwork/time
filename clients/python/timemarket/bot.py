"""What a script checks before it acts, and the few things the examples in ``clients/python/examples`` share.

Nothing here trades. It is the part of a bot that says no:

- ``check_account``: the bot's account has adopted the account security rules, its daily limit and its
  balance are under ceilings the operator gave, and it is not frozen. ``check_key``: the key the bot was
  given is a key of that account that can spend, and cannot manage it.
- ``check_index``: the API says its index of the market agrees with the chain. ``check_bitcoin``: the
  chain follows the Bitcoin network the operator named, it is not mainnet, and its header chain is not halted.
- ``AddressFile``: a file of receiving addresses made by the operator's own Bitcoin wallet, of which
  each is handed out once and marked in the file before it is used.
- ``Sender``: signs one action at a time through ``wire.sign_action``, sends it, sends THE SAME BYTES
  again when the answer was lost, and waits until the action is in a block before anything else is
  signed. Without ``act`` it prints what it would send and sends nothing.
- ``fill_made``, ``order_made``: the fill or the order an action of the account made, found in the API's index.
- ``micros``, ``seconds``, ``price_words``, ``bitcoin_amount``: amounts as text, in whole numbers.
- ``common_arguments``, ``key_from``, ``outcome``: the command line every example shares, the key from the place
  the operator named, and the exit code of a run.

WHAT THESE CHECKS ARE NOT. Every number they read is the word of the API the script calls: this
package cannot verify a proof (see ``api.py``). They stop an honest mistake (the wrong account, a
limit that was raised, a balance that grew, an index that is being rebuilt). They do not stop a lying
API. What bounds a lying API, and a thief who has the bot's machine, is on the chain: the daily limit
of the account and what the account holds. Run the API yourself (deploy/api/README.md).
"""
from __future__ import annotations

import os
import re
import time

from . import actions, wire
from .address import address_to_script, script_form
from .api import ApiError

DAY_MICROS = 86_400 * 10**6
_SECONDS = re.compile(r"(0|[1-9][0-9]{0,13})(?:\.([0-9]{1,6}))?")


class Refusal(Exception):
    """A reason not to act. Nothing was sent, or the chain refused what was sent and nothing happened."""


class NotKnown(Exception):
    """An action was sent and is in no block yet: it may still enter one. Sign nothing new before you know."""


# ---------------------------------------------------------------- what every example takes on its command line
def common_arguments(parser) -> None:
    """Adds to an ``argparse`` parser what every acting example asks: the API, the account, the two ceilings, the key's place, and whether to act.

    A dry run is the default: the script reads, says what it would send, and sends nothing. Nothing
    has a default that could be somebody else's account or key.
    """
    parser.add_argument("--api", required=True, metavar="URL", help="the API you run yourself, beside your own node, such as http://127.0.0.1:8930")
    parser.add_argument("--account", required=True, type=int, metavar="NUMBER", help="the script's own account: never the one that holds your savings")
    parser.add_argument("--max-daily-limit", required=True, type=micros, metavar="SECONDS", help="refuse to run if the account's daily limit is higher than this")
    parser.add_argument("--max-balance", required=True, type=micros, metavar="SECONDS", help="refuse to run if the account holds more than this")
    parser.add_argument("--bitcoin-network", required=True, choices=("regtest", "testnet3"), help="the Bitcoin network the chain follows; mainnet is closed in this version")
    key = parser.add_mutually_exclusive_group()
    key.add_argument("--key-store", nargs=2, metavar=("SERVICE", "NAME"), help="read the signing key from the system's key store, under these two names of yours")
    key.add_argument("--key-env", metavar="VARIABLE", help="read the signing key from this environment variable, set by whatever starts the script")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="say what would be sent and send nothing (the default)")
    mode.add_argument("--act", action="store_true", help="sign and send")
    parser.add_argument("--wait-seconds", type=int, default=120, metavar="N", help="how long to wait for an action to be in a block (default 120)")


def key_from(arguments):
    """The signing key from the place the operator named on the command line, or ``None`` when none was named.

    Only ``keys.seed_from_key_store`` and ``keys.seed_from_env`` are used: a key is never an argument,
    never in the script, and what comes back does not show when it is printed.
    """
    from . import keys

    if arguments.key_store:
        return keys.seed_from_key_store(*arguments.key_store)
    if arguments.key_env:
        return keys.seed_from_env(arguments.key_env)
    return None


def outcome(run) -> int:
    """Runs a script's work and turns how it ended into an exit code, with one line that says why.

    0 done; 2 refused (nothing was sent, or the chain refused it and nothing happened); 3 not known
    (something was sent and is in no block yet: look before you run anything again); 1 the API, the
    key store or a file could not be read.
    """
    try:
        return run() or 0
    except Refusal as refusal:
        print(f"REFUSED: {refusal}")
        return 2
    except NotKnown as unknown:
        print(f"NOT KNOWN: {unknown}")
        return 3
    except ApiError as error:
        print(f"THE API: {error}" + (f" ({error.code})" if error.code else ""))
        return 1
    except (OSError, RuntimeError, ValueError) as error:
        print(f"STOPPED: {error}")
        return 1


# ---------------------------------------------------------------- amounts as text
def micros(text: str) -> int:
    """Seconds written as a decimal (``"300"``, ``"2.5"``, ``"0.000001"``) in microseconds. No ``float`` is used."""
    found = _SECONDS.fullmatch(text) if isinstance(text, str) else None
    if not found:
        raise ValueError("Seconds are written as a whole number or a decimal with at most six places, such as 300 or 2.5")
    return int(found.group(1)) * 10**6 + int((found.group(2) or "").ljust(6, "0"))


def _decimal(value: int, places: int) -> str:
    whole, part = divmod(int(value), 10**places)
    return f"{whole}.{part:0{places}d}".rstrip("0").rstrip(".")


def seconds(amount_micros) -> str:
    """Microseconds as seconds, for people: ``20000000`` is ``"20 s"``."""
    return _decimal(amount_micros, 6) + " s"


def price_words(price) -> str:
    """A price (millionths of a satoshi for one second) for people: ``250000000`` is ``"250 satoshis a second"``."""
    return _decimal(price, 6) + " satoshis a second"


def bitcoin_amount(sats) -> str:
    """Satoshis as the decimal number of bitcoin a Bitcoin wallet takes, exactly: ``5000`` is ``"0.00005000"``."""
    if not isinstance(sats, int) or isinstance(sats, bool) or not 0 < sats <= 2_100_000_000_000_000:
        raise ValueError("An amount of bitcoin is a whole number of satoshis, from 1")
    return f"{sats // 10**8}.{sats % 10**8:08d}"


# ---------------------------------------------------------------- the account and its key
def allowance(state: dict) -> int | None:
    """What the account's spending keys may still move now, in microseconds, or ``None`` when the answer does not say.

    ``state`` is the answer of ``TimeApi.account_state``. The daily limit refills evenly over 24 hours
    and never holds more than one day's worth (v5/src/security.rs, ``level``).
    """
    security, clock = state.get("security"), state.get("security_clock")
    if not security or not clock or clock.get("now_elapsed_micros") is None:
        return None
    now, limit = int(clock["now_elapsed_micros"]), int(security["policy"]["daily_limit_micros"])
    level, since = int(security["allowance_micros"]), int(security["allowance_elapsed_micros"])

    def filled(start: int, end: int, cap: int, held: int) -> int:
        return min(held + min(cap * max(end - start, 0) // DAY_MICROS, cap), cap)

    waiting = security.get("pending_limit")
    if waiting and int(waiting["ready_elapsed_micros"]) <= now:
        level, since = filled(since, int(waiting["ready_elapsed_micros"]), limit, level), int(waiting["ready_elapsed_micros"])
        limit = int(waiting["daily_limit_micros"])
    return filled(since, now, limit, level)


def check_account(state: dict, *, most_daily_limit_micros: int, most_balance_micros: int) -> dict:
    """Refuses (``Refusal``) unless the account is one a bot should run on. ``state`` is ``TimeApi.account_state(...)``.

    - it has adopted the account security rules;
    - its daily limit, and a raise of the limit that is waiting, are at most ``most_daily_limit_micros``;
    - it holds at most ``most_balance_micros``;
    - it is not frozen.

    Returns ``{"balance", "daily_limit", "allowance"}`` in microseconds (``allowance`` may be ``None``).
    """
    account, security = state.get("account"), state.get("security")
    if not isinstance(account, dict):
        raise Refusal("The API gave no account")
    if not security:
        raise Refusal("This account has not adopted the account security rules: do that in your wallet first, with a daily limit")
    limit = int(security["policy"]["daily_limit_micros"])
    if limit > most_daily_limit_micros:
        raise Refusal(f"The daily limit of this account is {seconds(limit)}, more than the {seconds(most_daily_limit_micros)} you allow this script: lower the limit, or give the script another account")
    waiting = security.get("pending_limit")
    if waiting and int(waiting["daily_limit_micros"]) > most_daily_limit_micros:
        raise Refusal(f"A raise of this account's daily limit to {seconds(int(waiting['daily_limit_micros']))} is waiting, more than the {seconds(most_daily_limit_micros)} you allow this script: if you did not ask for it, freeze the account from your wallet")
    balance = int(account["balance"])
    if balance > most_balance_micros:
        raise Refusal(f"This account holds {seconds(balance)}, more than the {seconds(most_balance_micros)} you allow this script: move the rest out before the script runs")
    clock = state.get("security_clock") or {}
    now = clock.get("now_elapsed_micros")
    if now is not None and (int(now) < int(security.get("frozen_until_elapsed_micros") or 0) or security.get("pending_root")):
        raise Refusal("This account is frozen, or a replacement of its keys is waiting: it sends nothing now")
    return {"balance": balance, "daily_limit": limit, "allowance": allowance(state)}


def check_key(state: dict, seed) -> str:
    """Refuses unless ``seed`` is a key of the account that can spend and cannot manage it. Returns its public key.

    A bot holds a spending key only. A key that also manages the account can change its keys and its
    limit: it does not belong on the bot's machine.
    """
    public = wire.public_key(seed)
    for device in (state.get("account") or {}).get("devices") or ():
        if isinstance(device, dict) and device.get("public_key") == public:
            if device.get("can_spend") is not True:
                raise Refusal("The key this script was given is a key of the account that cannot spend: give it the spending key made for it")
            if device.get("can_manage") is True:
                raise Refusal("The key this script was given can also manage the account: a script is given a key that can spend and nothing else")
            return public
    raise Refusal("The key this script was given is not a key of this account")


# ---------------------------------------------------------------- what the API says of its index, and of Bitcoin
def check_index(answer: dict) -> str:
    """Refuses unless a list of the market can be acted on. Returns the height the list is as of.

    ``answer`` is any answer of the market that carries ``market_index``. Clean means: the book was
    proven whole once (``ready``), the index agrees with the chain's own counts (``consistent``), its
    list of trades adds up to what the chain counted (``tape_reconciled``), its last read did not fail
    (``last_error``) and it is not waiting for the block index (``waiting_for_indexer``).
    """
    index = answer.get("market_index") if isinstance(answer, dict) else None
    if not isinstance(index, dict):
        raise Refusal("The API's answer does not say where its index of the market stands: do not act on it")
    wrong = [name for name in ("ready", "consistent", "tape_reconciled") if index.get(name) is not True]
    if isinstance(index.get("last_error"), dict):
        wrong.append("last_error " + str(index["last_error"].get("code"))[:40])
    if index.get("waiting_for_indexer") is True:
        wrong.append("waiting_for_indexer")
    if wrong:
        raise Refusal("The API says its index of the market is not to be relied on now (" + ", ".join(wrong) + "): nothing is done on its lists. Ask again later; if it stays, the operator of the API looks at /v1/health")
    return str(index.get("as_of_height"))


def check_bitcoin(market: dict, network: str, *, new_fill: bool = True) -> None:
    """Refuses unless the market can move: ``market`` is the answer of ``TimeApi.market()``.

    The chain follows the Bitcoin network the operator named, which is not mainnet (closed in this
    version), and its header chain is not halted. With ``new_fill`` (a take, a sale to a buy order)
    it also refuses when the API says the header chain is stale. Whether it is fresh is the API's
    best guess (the time of the best header is not in the row the state proves): the chain itself
    refuses a new fill on a stale header chain, which costs a refused action and no seconds.
    """
    chain = market.get("bitcoin") if isinstance(market, dict) else None
    if not isinstance(chain, dict):
        raise Refusal("The API does not say which Bitcoin header chain the network follows")
    if chain.get("network") != network:
        raise Refusal(f"The network follows Bitcoin {chain.get('network')}, and you named {network}: an address of one is not an address of the other")
    if network == "mainnet":
        raise Refusal("Bitcoin mainnet is closed in this version of the market: nothing can be traded there")
    if chain.get("halted") is not False:
        raise Refusal("The chain's Bitcoin header chain is halted: no fill can be made, proven or expired. Orders can be cancelled, fills released or settled")
    if new_fill and chain.get("fresh") is False:
        raise Refusal("The chain's view of Bitcoin is stale (no new header for two hours): it would refuse a new fill. A header relay has to catch up first")


# ---------------------------------------------------------------- receiving addresses, each used once
class AddressFile:
    """A file of receiving addresses the operator made with their own Bitcoin wallet: one on a line, each used once.

    A line is an address, alone while it is free. This class marks an address by writing ``used`` and
    a few words after it, in the file, BEFORE the address is handed to the caller: a script that stops
    at the wrong moment wastes an address and never lists one twice. Lines that are empty or begin
    with ``#`` are kept as they are. An address that stands twice in the file, or that is not an
    address of ``network`` in one of the five forms the market takes, is refused with its line number
    before anything is done.
    """

    def __init__(self, path, network: str):
        self._path, self._network = os.fspath(path), network
        with open(self._path, "r", encoding="utf-8") as file:
            self._lines = file.read().splitlines()
        self._entries, seen = [], {}
        for number, line in enumerate(self._lines, 1):
            words = line.split(None, 1)
            if not words or words[0].startswith("#"):
                continue
            try:
                script = address_to_script(words[0], network)
            except ValueError as error:
                raise Refusal(f"Line {number} of the address file is not an address this market can list on {network}: {error}") from None
            if script in seen:
                raise Refusal(f"Line {number} of the address file repeats the address of line {seen[script]}: a receiving address serves one fill, ever, and is listed once")
            seen[script] = number
            self._entries.append({"line": number - 1, "address": words[0], "script": script, "used": len(words) > 1})

    def free(self) -> int:
        """How many addresses are not marked."""
        return sum(1 for entry in self._entries if not entry["used"])

    def take(self, count: int, what: str, *, write: bool = True, is_free=None, only=None) -> list[dict]:
        """The next ``count`` free addresses, each ``{"address", "script"}``, marked in the file as used for ``what``.

        ``is_free(script)``, when given, is asked for each (``TimeApi.market_script``): an address the
        chain already knows is marked and passed over. ``only(script)``, when given, leaves aside,
        unmarked, the addresses it is false for (a form of address a buyer cannot pay to). With
        ``write=False`` (a dry run) the file is not changed, and the addresses are still not handed
        out twice by this object. Raises ``Refusal`` when the file does not hold ``count`` such
        addresses: make new ones in your wallet and add them to the file; nothing is ever taken twice.
        """
        taken, passed = [], []
        for entry in self._entries:
            if len(taken) == count:
                break
            if entry["used"] or (only is not None and not only(entry["script"])):
                continue
            if is_free is not None and not is_free(entry["script"]):
                passed.append(entry)
                continue
            taken.append(entry)
        if len(taken) < count:
            raise Refusal(f"The address file has run out: {count} free addresses are needed and {len(taken)} are left. Make new ones in your own Bitcoin wallet and add them; no address is used twice")
        for entry, note in [(entry, "the chain already knows it") for entry in passed] + [(entry, what) for entry in taken]:
            entry["used"] = True
            self._lines[entry["line"]] = f"{entry['address']} used {re.sub(r'[^ -~]', ' ', str(note))[:80]}"
        if write:
            self._write()
        return [{"address": entry["address"], "script": entry["script"]} for entry in taken]

    def forms(self) -> set[str]:
        """The forms of address (``p2wpkh`` and so on) among the addresses that are still free."""
        return {script_form(entry["script"]) for entry in self._entries if not entry["used"]}

    def _write(self) -> None:
        temporary = self._path + ".writing"
        with open(temporary, "w", encoding="utf-8", newline="\n") as file:
            file.write("\n".join(self._lines) + "\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, self._path)


# ---------------------------------------------------------------- one action at a time
class Sender:
    """Signs, sends and waits for the actions of one account, one at a time. Without ``act`` it sends nothing.

    - ``send(kind, payload, what)`` reads the network and the account just before it signs, says what
      the action is and costs, and, with ``act``, signs it (``wire.sign_action``), submits it and waits
      until the API shows it in a block. It returns the API's answer for the action, or ``None`` in a
      dry run.
    - A lost answer, or a service that is busy, is answered by sending THE SAME BYTES again. Nothing
      new is signed for the same purpose.
    - A refusal by the chain (not enough balance, the daily limit, a frozen account, an order that is
      gone) is a ``Refusal``: nothing happened, and the nonce is not used.
    - An action that is in no block when the wait is over is ``NotKnown``: it may still enter one.
      The script that gets it stops; a person looks the hash up before anything else is signed.
    - The nonce is counted here once an action of this object is in a block (the API's proof of the
      account trails the newest block by one). A nonce of the account that this object did not use
      means another signer has the key: that is a ``Refusal`` too.
    """

    def __init__(self, api, *, account, seed=None, act: bool = False, out=print, sleep=time.sleep, wait_seconds: int = 120, poll_seconds: int = 2):
        if act and seed is None:
            raise Refusal("To act, the script needs the signing key: name where it is kept (--key-store or --key-env)")
        self._api, self._account, self._seed, self.act = api, int(account), seed, bool(act)
        self._out, self._sleep, self._wait, self._poll, self._next = out, sleep, int(wait_seconds), max(1, int(poll_seconds)), None

    def send(self, kind: int, payload: dict, what: str) -> dict | None:
        status, state = self._api.status(), self._api.account_state(self._account)
        network, account = status["network"], state["account"]
        fee = actions.action_fee(kind, payload, network["fee_micros"])
        self._out(f"{'SENDING' if self.act else 'WOULD SEND'}: {what}")
        self._out(f"  kind {kind}, payload {wire.canonical_payload(kind, payload).decode('utf-8')}")
        self._out(f"  fee {seconds(fee)} ({fee} microseconds)")
        if not self.act:
            self._out("  DRY RUN: nothing was signed and nothing was sent. (To send: --act for a script, act=True in your own code.)")
            return None
        proven = int(account["nonce"]) + 1
        if self._next is not None and proven > self._next:
            raise Refusal("The nonce of this account moved without this script: something else signs with its key. Nothing is sent; find out what it was before you run this again")
        nonce = proven if self._next is None else self._next
        signed = wire.sign_action(network_id=network["network_id"], kind=kind, sender=self._account, nonce=nonce, auth_epoch=account["auth_epoch"], payload=payload, seed=self._seed)
        name = wire.transaction_hash(signed)
        self._out(f"  hash {name}, nonce {nonce}")
        self._submit(signed, name, nonce)
        answer = self._included(name)
        self._next = nonce + 1
        self._out(f"  in block {answer['action']['height']}")
        return answer

    def _submit(self, signed: bytes, name: str, nonce: int) -> None:
        for attempt in range(4):
            try:
                self._api.submit(signed)
                return
            except ApiError as error:
                if error.code == "already_submitted":
                    return
                if error.code == "nonce_used":
                    raise Refusal(f"Another action of this account already used nonce {nonce}: these bytes can never be included. Look at the account's activity before anything else is signed") from None
                if error.status is None or error.status in (429, 502, 503):
                    # No answer, or a service that is busy: the node may have the bytes or not. The same bytes go again.
                    if attempt < 3:
                        self._sleep(min(error.retry_after or self._poll, 30))
                        continue
                    raise NotKnown(f"The API did not take the action {name} in four tries; it may have reached the chain all the same. Look the hash up before you run this again") from None
                raise Refusal(f"Refused, and nothing happened: {error}") from None

    def _included(self, name: str) -> dict:
        for _ in range(max(1, self._wait // self._poll)):
            try:
                answer = self._api.action(name)
                if answer["action"].get("results_checked") is True:
                    return answer
            except ApiError as error:
                if error.status not in (None, 404, 429, 502, 503):
                    raise
            self._sleep(self._poll)
        raise NotKnown(f"The action {name} was sent and is in no checked block after {self._wait} seconds. It may still enter one: look the hash up (GET /v1/actions/{name}) before you run this again, and sign nothing new for the same purpose until you know")


def _made(api, account, rows: str, fits, what: str, height, sleep, wait_seconds: int, poll_seconds: int) -> dict:
    found = []
    for _ in range(max(1, wait_seconds // max(1, poll_seconds))):
        try:
            mine = api.account_market(account)
            check_index(mine)
            found = [row for row in mine[rows] if row["created"]["height"] == str(height) and fits(row)]
        except (ApiError, Refusal):
            found = []
        if found:
            break
        sleep(poll_seconds)
    if len(found) != 1:
        raise NotKnown(f"The action is in block {height}, and the API's index shows {len(found)} {what} of this account made in that block, not one. Read what the account has in the market (GET /v1/accounts/{account}/market) and each row by itself before anything is paid or signed")
    return found[0]


def fill_made(api, account, *, order, height, role: str, sleep=time.sleep, wait_seconds: int = 60, poll_seconds: int = 2) -> dict:
    """The open fill that the account's action in block ``height`` made against ``order``, from the API's index.

    The chain gives a new fill its id, and no answer of the API names it for the action that made it.
    So it is found among the account's open fills: the one against that order, created in that block,
    in which the account is ``role`` (``payer`` for a take, ``owner`` for a sale to a buy order). The
    index shows a block when the next one has come, so this asks again for a while. It raises
    ``NotKnown`` when it does not find exactly one. What it returns is the index's word: read the
    fill itself (``TimeApi.market_fill``) before anything is done with it.
    """
    return _made(api, account, "fills", lambda fill: role in fill["roles"] and fill["order"] == str(order), f"fills against order {order}", height, sleep, wait_seconds, poll_seconds)


def order_made(api, account, *, side: str, price, height, sleep=time.sleep, wait_seconds: int = 60, poll_seconds: int = 2) -> dict:
    """The open order that the account's action in block ``height`` made, from the API's index: found as ``fill_made`` finds a fill."""
    return _made(api, account, "orders", lambda order: order["side"] == side and order["price"] == str(price), f"{side} orders", height, sleep, wait_seconds, poll_seconds)
