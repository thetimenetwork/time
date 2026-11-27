"""What a proof of payment (kind 54) needs of Bitcoin: transactions without witness data, and a Merkle proof.

A proof of payment (spec/market.md, 5.2 and 6.5) carries the payment's transaction and the coinbase
transaction of its block, each serialized WITHOUT witness data, and a Merkle proof of the two. A
Bitcoin node gives transactions with their witness data. ``strip_witness`` removes it, and
``proof_payload`` puts a proof together from what a node gives. Nothing here calls a node.

The same rules, messages and test vectors as web-v4/shared/bitcoin-address.mjs. Standard library only.
Every refusal is a ``ValueError`` that says why.
"""
from __future__ import annotations

import re

from .address import hex_bytes, script_form, sha256d

_MAX_TRANSACTION_BYTES = 4_000_000
_MAX_PAYMENT_BYTES = 100_000
_MAX_COINBASE_BYTES = 150_000
_MAX_MERKLE_PROOF_BYTES = 4096
_MAX_SATS = 2_100_000_000_000_000
_NULL_INPUT = "00" * 32 + "ffffffff"
_SHORT_TRANSACTION = "This is not a whole Bitcoin transaction: it ends too early"
_SHORT_PROOF = "merkle_proof is not a whole Merkle proof: it ends too early"


def _size_at(data: bytes, at: int, short: str) -> tuple[int, int]:
    """Reads a size as Bitcoin writes one (1, 3 or 5 bytes here), in its shortest form only: (value, next offset)."""
    if at >= len(data):
        raise ValueError(short)
    first = data[at]
    if first < 0xFD:
        return first, at + 1
    if first == 0xFF:
        raise ValueError("This is not Bitcoin data: it names a size nothing has")
    width = 2 if first == 0xFD else 4
    if width > len(data) - at - 1:
        raise ValueError(short)
    value = int.from_bytes(data[at + 1 : at + 1 + width], "little")
    if value < (0xFD if width == 2 else 0x10000):
        raise ValueError(
            "A size is written in a longer form than needed: this is not serialized the one way Bitcoin data is"
        )
    return value, at + 1 + width


class _Transaction:
    """A serialized transaction, read strictly: its bytes without witness data, its inputs and its outputs."""

    def __init__(self, data: bytes):
        self._data, self._at = data, 0
        if len(data) > _MAX_TRANSACTION_BYTES:
            raise ValueError("This is larger than any Bitcoin transaction")
        self._take(4)
        witness = len(data) > 4 and data[4] == 0x00
        if witness:
            self._take(1)
            if data[self._take(1)] != 0x01:
                raise ValueError(
                    "This is not a Bitcoin transaction: it has no input, or a marker this code does not know"
                )
        body_start, count = self._at, self._size()
        if count == 0:
            raise ValueError("A Bitcoin transaction has at least one input")
        if count > (len(data) - self._at) / 41:
            raise ValueError(_SHORT_TRANSACTION)
        self.inputs: list[str] = []
        for _ in range(count):
            start = self._take(36)
            self.inputs.append(data[start : start + 36].hex())
            self._take(self._size())
            self._take(4)
        output_count = self._size()
        if output_count == 0:
            raise ValueError("A Bitcoin transaction has at least one output")
        if output_count > (len(data) - self._at) / 9:
            raise ValueError(_SHORT_TRANSACTION)
        self.outputs: list[tuple[int, str]] = []
        for _ in range(output_count):
            start = self._take(8)
            length = self._size()
            script = self._take(length)
            self.outputs.append((int.from_bytes(data[start : start + 8], "little"), data[script : script + length].hex()))
        body_end = self._at
        if witness:
            some = False
            for _ in range(count):
                items = self._size()
                if items > len(data) - self._at:
                    raise ValueError(_SHORT_TRANSACTION)
                some = some or items > 0
                for _ in range(items):
                    self._take(self._size())
            if not some:
                raise ValueError(
                    "This transaction is marked as having witness data and has none: it is not serialized the one way a transaction is"
                )
        lock = self._take(4)
        if self._at != len(data):
            raise ValueError("This is not one Bitcoin transaction: bytes follow its end")
        self.bare = data[:4] + data[body_start:body_end] + data[lock : lock + 4] if witness else data

    def _take(self, count: int) -> int:
        if count > len(self._data) - self._at:
            raise ValueError(_SHORT_TRANSACTION)
        self._at += count
        return self._at - count

    def _size(self) -> int:
        value, self._at = _size_at(self._data, self._at, _SHORT_TRANSACTION)
        return value


def strip_witness(transaction_hex: str) -> str:
    """A serialized Bitcoin transaction (lowercase hexadecimal) without its witness data.

    The marker and flag after the version and the witness stacks before the lock time are removed. A
    transaction serialized without witness data comes back as it is. The transaction id is the same
    before and after: it never covered the witness. Raises ``ValueError`` for anything that is not
    exactly one transaction serialized the canonical way.
    """
    return _Transaction(hex_bytes(transaction_hex, "A Bitcoin transaction")).bare.hex()


def transaction_id(transaction_hex: str) -> str:
    """The id of a serialized Bitcoin transaction (with or without witness data), as Bitcoin software prints it.

    The double SHA-256 of its serialization without witness data, byte-reversed, in lowercase hexadecimal.
    """
    return sha256d(_Transaction(hex_bytes(transaction_hex, "A Bitcoin transaction")).bare)[::-1].hex()


def transaction_outputs(transaction_hex: str) -> list[dict]:
    """The outputs of a serialized Bitcoin transaction, in their order: ``[{"sats": int, "script": hex}, …]``.

    The place of an output in the list is its ``vout``.
    """
    outputs = _Transaction(hex_bytes(transaction_hex, "A Bitcoin transaction")).outputs
    return [{"sats": sats, "script": script} for sats, script in outputs]


def merkle_proof_matches(merkle_proof_hex: str, block_hash: str) -> list[dict]:
    """The transactions a Merkle proof proves to be in the block ``block_hash``: ``[{"hash": hex, "place": int}, …]``.

    Reads a Merkle proof as Bitcoin Core's gettxoutproof writes one (a block header, the number of
    transactions in the block, hashes, and flag bits: BIP37's partial Merkle tree), strictly, and
    checks it: it is for the block ``block_hash`` and its hashes and flags give the Merkle root of
    that header. ``hash`` is the transaction id as its bytes stand (not reversed, as Bitcoin software
    prints an id) and ``place`` the transaction's place in the block, from 0. The sizes are the
    engine's for a proof of payment: at most 4,096 bytes and 64 hashes.
    """
    if not isinstance(block_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", block_hash):
        raise ValueError("block_hash is 64 lowercase hexadecimal characters")
    proof = hex_bytes(merkle_proof_hex, "merkle_proof")

    def wrong(why: str) -> ValueError:
        return ValueError(f"merkle_proof is not a Merkle proof Bitcoin software writes: {why}")

    if len(proof) < 86 or len(proof) > _MAX_MERKLE_PROOF_BYTES:
        raise ValueError("merkle_proof is 86 to 4,096 bytes: what gettxoutproof returns for the two transaction ids")
    if sha256d(proof[:80])[::-1].hex() != block_hash:
        raise ValueError("merkle_proof is for another block than block_hash")
    total = int.from_bytes(proof[80:84], "little")
    # A block holds at most 4,000,000 weight units and a transaction weighs at least 240.
    if total < 1 or total > 16666:
        raise wrong("it names a number of transactions no block has")
    hash_count, after_count = _size_at(proof, 84, _SHORT_PROOF)
    if hash_count < 1 or hash_count > 64 or hash_count > total or after_count + 32 * hash_count >= len(proof):
        raise wrong("it holds a number of hashes that no proof of two transactions has")
    flag_count, after_flags = _size_at(proof, after_count + 32 * hash_count, _SHORT_PROOF)
    if flag_count < 1 or flag_count > 1024 or after_flags + flag_count != len(proof):
        raise wrong("it does not end where its own sizes say")
    if flag_count * 8 < hash_count:
        raise wrong("it has fewer flag bits than hashes")

    def width(height: int) -> int:
        return (total + (1 << height) - 1) >> height

    height = 0
    while width(height) > 1:
        height += 1
    used = {"hashes": 0, "bits": 0}
    matched: list[dict] = []

    def walk(level: int, place: int) -> bytes:
        if used["bits"] >= flag_count * 8:
            raise wrong("its flag bits run out")
        above = (proof[after_flags + (used["bits"] >> 3)] >> (used["bits"] & 7)) & 1
        used["bits"] += 1
        if level == 0 or not above:
            if used["hashes"] >= hash_count:
                raise wrong("its hashes run out")
            start = after_count + 32 * used["hashes"]
            used["hashes"] += 1
            if level == 0 and above:
                matched.append({"hash": proof[start : start + 32].hex(), "place": place})
            return proof[start : start + 32]
        left = walk(level - 1, place * 2)
        right = left
        if place * 2 + 1 < width(level - 1):
            right = walk(level - 1, place * 2 + 1)
            # Two equal halves would let one transaction stand at two places.
            if right == left:
                raise wrong("two halves of its tree are the same")
        return sha256d(left + right)

    root = walk(height, 0)
    # The bits of the last flag byte that nothing uses are not read, as Bitcoin software does not read them.
    if used["hashes"] != hash_count or (used["bits"] + 7) // 8 != flag_count:
        raise wrong("it holds hashes or flag bytes that nothing uses")
    if root != proof[36:68]:
        raise ValueError(
            "merkle_proof does not lead to the Merkle root of its block: it does not prove that its transactions are in the block"
        )
    return matched


def _carried(transaction_hex: str, what: str, most: int, least: int) -> _Transaction:
    """A transaction as a proof carries it (bitcoin-bridge/src/payment.rs, ``carried``), from one a node gave."""
    read = _Transaction(hex_bytes(transaction_hex, f"The {what}"))
    if len(read.bare) > most:
        raise ValueError(f"The {what} is larger than a proof may carry ({most:,} bytes without its witness data)")
    if len(read.bare) < least:
        raise ValueError(f"The {what} is too short to be proven (64 bytes or fewer)")
    if sum(sats for sats, _ in read.outputs) > _MAX_SATS:
        raise ValueError(f"The outputs of the {what} sum to more bitcoin than exists")
    return read


def proof_payload(
    *,
    fill: int | str,
    script: str,
    block_hash: str,
    transaction: str,
    coinbase: str,
    merkle_proof: str,
    vout: int | str | None = None,
) -> dict:
    """The payload of a proof of payment (kind 54) from what a Bitcoin node gives. It calls no node.

    With Bitcoin Core::

        getblock <block hash> 2      -> tx[0].hex is the block's coinbase transaction, tx[0].txid its id;
                                        the payment is the entry whose txid is the payment's (its hex)
        getrawtransaction <txid> false <block hash>      gives the same hex for one transaction
        gettxoutproof '["<coinbase txid>","<txid>"]' <block hash>      -> the Merkle proof of the two

    Arguments (all by name):

    - ``fill``: the fill's id (an integer, or a decimal string);
    - ``script``: the fill's receiving script, lowercase hexadecimal, read from the chain;
    - ``block_hash``: the hash of the block the payment is in, as Bitcoin software prints it;
    - ``transaction``: the payment, lowercase hexadecimal, with or without witness data;
    - ``coinbase``: the coinbase transaction of that block, likewise;
    - ``merkle_proof``: what gettxoutproof returned;
    - ``vout``: optional, which output to prove. Left out, the one output that pays ``script`` is
      found; a transaction with several such outputs needs it named, one proof for each.

    Both transactions lose their witness data. Refused here, before anything is signed: a payment that
    does not pay ``script`` at that output, a coinbase that is not one, a Merkle proof that is not for
    ``block_hash``, does not lead to that block's Merkle root, or does not prove exactly the two
    transactions with the coinbase at the first place of the block, and anything the engine's size
    bounds refuse. What only the chain can say stays unsaid: whether the block is on the chain of most
    work with the confirmations the fill asks, and whether the output has paid already.

    Returns ``{"block_hash", "coinbase", "fill", "merkle_proof", "transaction", "vout"}``.
    """
    if isinstance(fill, int) and not isinstance(fill, bool):
        fill = str(fill)
    if not isinstance(fill, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", fill) or int(fill) >= 1 << 64:
        raise ValueError("fill is the id of a fill: a whole number from 1")
    script_form(script)
    if not isinstance(block_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", block_hash):
        raise ValueError("block_hash is 64 lowercase hexadecimal characters")
    # The payment is longer than 64 bytes (a shorter one could pass for a node of the Merkle tree); the
    # coinbase may be as short as a miner makes it.
    payment = _carried(transaction, "payment", _MAX_PAYMENT_BYTES, 65)
    first = _carried(coinbase, "coinbase transaction", _MAX_COINBASE_BYTES, 0)
    if first.inputs != [_NULL_INPUT]:
        raise ValueError(
            "coinbase is the first transaction of the block, which spends nothing: this is another transaction"
        )
    if _NULL_INPUT in payment.inputs:
        raise ValueError("The payment is a coinbase transaction, or spends nothing: it cannot pay for a fill")
    if len(set(payment.inputs)) != len(payment.inputs):
        raise ValueError("The payment spends one output twice")
    paying = [index for index, (_, paid_to) in enumerate(payment.outputs) if paid_to == script]
    listed = ", ".join(str(index) for index in paying)
    if vout is None:
        if not paying:
            raise ValueError("No output of this transaction pays the receiving script of the fill")
        if len(paying) > 1:
            raise ValueError(
                f"Outputs {listed} of this transaction pay the receiving script of the fill: name one with vout, and prove each with a proof of its own"
            )
        vout = paying[0]
    else:
        if isinstance(vout, str) and re.fullmatch(r"0|[1-9][0-9]{0,9}", vout):
            vout = int(vout)
        if not isinstance(vout, int) or isinstance(vout, bool) or vout < 0 or vout > 0xFFFFFFFF:
            raise ValueError("vout is the place of an output: a whole number from 0")
        if vout >= len(payment.outputs):
            raise ValueError(f"This transaction has {len(payment.outputs)} outputs: it has no output {vout}")
        if payment.outputs[vout][1] != script:
            where = f": output {listed} does" if paying else ", and no other output does"
            raise ValueError(f"Output {vout} of this transaction does not pay the receiving script of the fill{where}")
    if payment.outputs[vout][0] < 1:
        raise ValueError("The output that pays the fill has no value")
    matched = merkle_proof_matches(merkle_proof, block_hash)
    ids = [sha256d(first.bare).hex(), sha256d(payment.bare).hex()]
    hashes = [match["hash"] for match in matched]
    if ids[0] not in hashes:
        raise ValueError(
            "merkle_proof does not hold the coinbase transaction: ask gettxoutproof for both ids, the coinbase and the payment"
        )
    if ids[1] not in hashes:
        raise ValueError(
            "merkle_proof does not hold the payment: ask gettxoutproof for both ids, the coinbase and the payment"
        )
    if len(matched) != 2:
        raise ValueError(
            f"merkle_proof is a proof of {len(matched)} transactions: a proof of payment is one of exactly two, the coinbase and the payment"
        )
    if matched[0] != {"hash": ids[0], "place": 0}:
        raise ValueError("The transaction given as coinbase is not at the first place of the block")
    return {
        "block_hash": block_hash,
        "coinbase": first.bare.hex(),
        "fill": fill,
        "merkle_proof": merkle_proof,
        "transaction": payment.bare.hex(),
        "vout": str(vout),
    }
