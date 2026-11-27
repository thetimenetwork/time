"""The HTTP client, against a small server on this machine that answers as client-v4/api.mjs does.

The forms of the answers (the body of POST /v1/transactions, an error as {"error": {"code", "message"}}, Retry-After)
are those of client-v4/api.mjs; no network beyond 127.0.0.1 is used.
"""
import base64
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from timemarket import wire
from timemarket.api import ApiError, TimeApi

from . import ENGINE

ACTION = bytes.fromhex(next(entry for entry in ENGINE["actions"] if entry["name"] == "take")["signed_hex"])


SCRIPT = "0014" + "01" * 20
INDEX = {"as_of_height": "12", "ready": True, "consistent": True, "tape_reconciled": True}
MARKET = {
    "/v1/market": {"source": "state_proof", "market": True, "summary": {"orders": "1"}, "last_recorded_price": "250000000", "market_index": INDEX},
    "/v1/market/orders": {"source": "index", "proven": False, "side": "sell", "items": [{"id": "1", "price": "250000000", "takes_fill": True}], "has_more": False, "next_cursor": "250000000.1", "market_index": INDEX},
    "/v1/market/depth": {"source": "index", "levels": 20, "sell": [{"price": "250000000", "amount_micros": "100000000", "orders": 1}], "buy": [], "market_index": INDEX},
    "/v1/market/orders/1": {"source": "state_proof", "order": {"id": "1", "owner": "5"}, "takes_fill": True, "owner_stands": {"stands": True}},
    "/v1/market/fills/2": {"source": "state_proof", "fill": {"id": "2", "script": SCRIPT, "sats": "3000"}, "last_height": "12"},
    "/v1/market/scripts/" + SCRIPT: {"source": "state_proof", "script": SCRIPT, "status": "listed", "order": "1"},
    "/v1/market/trades": {"source": "index", "items": [{"id": "12.0", "fill": "2", "sats": "3000"}], "has_more": False, "next_cursor": "12.0", "market_index": INDEX},
    "/v1/market/candles": {"source": "index", "interval": "hour", "items": [], "has_more": False, "next_to": None, "market_index": INDEX},
    "/v1/accounts/6/market": {"source": "index", "account": "6", "orders": [], "fills": [{"id": "2", "roles": ["payer", "to"]}], "ended": {"items": []}, "market_index": INDEX},
}


class Handler(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *arguments):
        pass

    def answer(self, status, body, headers=()):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        Handler.seen.append(("GET", self.path, None, dict(self.headers)))
        if self.path == "/v1/status":
            self.answer(200, {"api": "v1", "network": {"network_id": ENGINE["network_id"], "fee_micros": "1000"}})
        elif self.path == "/v1/health":
            self.answer(503, {"error": {"code": "unhealthy", "message": "The indexer is behind"}, "reasons": ["indexer_stopped"]}, [("Retry-After", "7")])
        elif self.path == "/v1/accounts/6/state":
            self.answer(200, {"source": "state_proof", "account": {"id": 6, "nonce": 4, "auth_epoch": 0, "balance": 1000000000}})
        elif self.path == "/v1/accounts/6":
            self.answer(200, {"account": {"id": "6", "nonce": "4"}, "indexed": {"state_is_behind": True}})
        elif self.path == "/v1/accounts/7/state":
            self.answer(404, {"error": {"code": "account_not_found", "message": "No such account in the verified state"}})
        elif self.path == "/v1/actions/" + wire.transaction_hash(ACTION):
            self.answer(200, {"hash": wire.transaction_hash(ACTION), "height": "12", "source": "index"})
        elif self.path == "/v1/actions/" + "AB" * 32:
            self.answer(404, {"error": {"code": "not_found", "message": "No action with this hash is in the index"}})
        elif self.path.split("?")[0] in MARKET:
            # The forms of client-v4/api.mjs: a list from the index with its market_index, a row with its proof.
            self.answer(200, MARKET[self.path.split("?")[0]])
        elif self.path == "/v1/market/fills/9":
            self.answer(404, {"error": {"code": "fill_not_found", "message": "No such fill in the verified state"}, "source": "state_proof", "fill": None, "indexed": {"ended": {"how": "paid"}}})
        elif self.path == "/nomarket/v1/market":
            self.answer(404, {"error": {"code": "no_market", "message": "This network has no market: its genesis does not have the setting"}})
        elif self.path == "/syncing/v1/market/orders?side=sell":
            self.answer(503, {"error": {"code": "market_index_not_ready", "message": "The index of the market has not proven the book yet"}, "market_index": {"ready": False}}, [("Retry-After", "5")])
        elif self.path == "/slow/v1/status":
            time.sleep(6)
            self.answer(200, {})
        elif self.path == "/moved/v1/status":
            self.answer(302, {}, [("Location", "/v1/status")])
        elif self.path == "/text/v1/status":
            self.answer(200, b"<html>not the API</html>")
        elif self.path == "/words/v1/status":
            self.answer(500, b"Internal Server Error")
        elif self.path == "/large/v1/status":
            self.answer(200, b'"' + b"x" * (8 * 1024 * 1024 + 10) + b'"')
        else:
            self.answer(404, {"error": {"code": "unknown_route", "message": "No such route"}})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        Handler.seen.append(("POST", self.path, raw, dict(self.headers)))
        if self.path == "/moved/v1/transactions":
            return self.answer(307, {}, [("Location", "/v1/transactions")])
        if self.path == "/busy/v1/transactions":
            return self.answer(503, {"error": {"code": "busy", "message": "The service is full"}}, [("Retry-After", "3")])
        if self.path == "/refusing/v1/transactions":
            return self.answer(422, {"error": {"code": "rejected", "message": "The node refused the action: no such order."}, "hash": wire.transaction_hash(ACTION)})
        if self.path != "/v1/transactions" or self.headers.get("Content-Type") != "application/json":
            return self.answer(415, {"error": {"code": "unsupported_media_type", "message": "Send JSON with Content-Type: application/json"}})
        body = json.loads(raw)
        # The handler of client-v4/api.mjs: exactly {"tx": "<canonical base64 of one signed action>"}.
        if list(body) != ["tx"] or base64.b64encode(base64.b64decode(body["tx"])).decode() != body["tx"]:
            return self.answer(400, {"error": {"code": "invalid_body", "message": 'The body is {"tx": "<the signed action in base64>"}'}})
        signed = base64.b64decode(body["tx"])
        self.answer(202, {"hash": wire.transaction_hash(signed), "status": "submitted", "kind": signed[19 + 32], "note": "Submitted is not included."})


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # a client that stopped waiting (the timeout test) is not news


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        Handler.seen.clear()

    def test_status_and_the_state_of_an_account(self):
        api = TimeApi(self.base + "/")
        self.assertEqual(api.status()["network"]["fee_micros"], "1000")
        self.assertEqual(api.account_state(6)["account"]["nonce"], 4)
        self.assertEqual(api.account_state("6")["account"]["auth_epoch"], 0)
        self.assertEqual([entry[:2] for entry in Handler.seen], [("GET", "/v1/status"), ("GET", "/v1/accounts/6/state"), ("GET", "/v1/accounts/6/state")])
        # The account's summary: what the index already holds beside the proven state.
        self.assertIs(api.account(6)["indexed"]["state_is_behind"], True)
        self.assertEqual(Handler.seen[-1][:2], ("GET", "/v1/accounts/6"))
        with self.assertRaises(ApiError) as caught:
            api.account_state(7)
        self.assertEqual((caught.exception.status, caught.exception.code, str(caught.exception)), (404, "account_not_found", "No such account in the verified state"))
        for bad in (-1, "06", "6/state", "../6", "6?x=1", 6.0, True, None, 2**64 - 1, ""):
            with self.assertRaisesRegex(ValueError, "An account is its number"):
                api.account_state(bad)
        self.assertEqual(len(Handler.seen), 5, "a refused argument asks nothing of the server")

    def test_an_action_by_its_hash(self):
        api, name = TimeApi(self.base), wire.transaction_hash(ACTION)
        self.assertEqual(api.action(name)["height"], "12")
        self.assertEqual(api.action(name.lower())["height"], "12")
        with self.assertRaises(ApiError) as caught:
            api.action("ab" * 32)
        self.assertEqual((caught.exception.status, caught.exception.code), (404, "not_found"))
        for bad in ("", "ab" * 31, "zz" * 32, name + "/x", None, ACTION):
            with self.assertRaisesRegex(ValueError, "A hash is 64 hexadecimal characters"):
                api.action(bad)

    def test_a_submission_is_the_body_the_api_expects_and_is_sent_once(self):
        api = TimeApi(self.base)
        answer = api.submit(ACTION)
        self.assertEqual((answer["status"], answer["hash"], answer["kind"]), ("submitted", wire.transaction_hash(ACTION), 52))
        method, path, raw, headers = Handler.seen[0]
        self.assertEqual((method, path), ("POST", "/v1/transactions"))
        self.assertEqual(raw, b'{"tx":"' + base64.b64encode(ACTION) + b'"}')
        self.assertEqual(headers.get("Content-Type"), "application/json")
        for bad in (ACTION.hex(), base64.b64encode(ACTION).decode(), None, b"", ACTION[:50], [ACTION]):
            with self.assertRaisesRegex(ValueError, "A signed action is bytes"):
                api.submit(bad)
        self.assertEqual(len(Handler.seen), 1)
        # A refusal by the node, a busy service, a redirect: each is an error with what the API said, and nothing is sent again.
        for prefix, status, code, wait in (("/refusing", 422, "rejected", None), ("/busy", 503, "busy", 3), ("/moved", 307, None, None)):
            Handler.seen.clear()
            with self.assertRaises(ApiError) as caught:
                TimeApi(self.base + prefix).submit(ACTION)
            error = caught.exception
            self.assertEqual((error.status, error.code, error.retry_after), (status, code, wait), prefix)
            self.assertEqual([entry[:2] for entry in Handler.seen], [("POST", prefix + "/v1/transactions")], "sent once, and not followed elsewhere")
        with self.assertRaises(ApiError) as caught:
            TimeApi(self.base + "/refusing").submit(ACTION)
        self.assertEqual(caught.exception.body["hash"], wire.transaction_hash(ACTION))
        self.assertIn("no such order", str(caught.exception))

    def test_the_market_each_route_with_the_parameters_the_api_takes(self):
        api = TimeApi(self.base)
        self.assertEqual(api.market()["last_recorded_price"], "250000000")
        self.assertEqual(api.market_orders("sell")["items"][0]["id"], "1")
        self.assertEqual(api.market_orders("buy", limit=5, cursor="250000000.1")["market_index"]["as_of_height"], "12")
        self.assertEqual(api.market_depth()["levels"], 20)
        self.assertEqual(api.market_depth(50)["sell"][0]["orders"], 1)
        self.assertEqual(api.market_order(1)["owner_stands"]["stands"], True)
        self.assertEqual(api.market_order("1")["order"]["owner"], "5")
        self.assertEqual(api.market_fill(2)["fill"]["sats"], "3000")
        self.assertEqual(api.market_script(SCRIPT)["status"], "listed")
        self.assertEqual(api.market_trades()["items"][0]["id"], "12.0")
        self.assertEqual(api.market_trades(limit=1, cursor="12.0", order="asc")["next_cursor"], "12.0")
        self.assertEqual(api.market_candles("hour")["interval"], "hour")
        self.assertEqual(api.market_candles("1m", from_micros=0, to_micros=1800000000000000, limit=200)["items"], [])
        self.assertEqual(api.account_market(6)["fills"][0]["roles"], ["payer", "to"])
        self.assertEqual(api.account_market("6", limit=10, cursor="12.0")["account"], "6")
        # Exactly the addresses of the API: a parameter that was not given is not sent, and nothing else is.
        self.assertEqual([entry[1] for entry in Handler.seen], [
            "/v1/market", "/v1/market/orders?side=sell", "/v1/market/orders?side=buy&limit=5&cursor=250000000.1", "/v1/market/depth", "/v1/market/depth?levels=50",
            "/v1/market/orders/1", "/v1/market/orders/1", "/v1/market/fills/2", "/v1/market/scripts/" + SCRIPT, "/v1/market/trades", "/v1/market/trades?limit=1&cursor=12.0&order=asc",
            "/v1/market/candles?interval=hour", "/v1/market/candles?interval=1m&from=0&to=1800000000000000&limit=200", "/v1/accounts/6/market", "/v1/accounts/6/market?limit=10&cursor=12.0"])
        self.assertTrue(all(entry[0] == "GET" for entry in Handler.seen))

    def test_the_market_refusals_of_the_api_and_arguments_that_are_never_sent(self):
        api = TimeApi(self.base)
        # A fill that has ended: the error carries what the API said of it, and a bot stops paying.
        with self.assertRaises(ApiError) as caught:
            api.market_fill(9)
        self.assertEqual((caught.exception.status, caught.exception.code, caught.exception.body["indexed"]["ended"]["how"]), (404, "fill_not_found", "paid"))
        with self.assertRaises(ApiError) as caught:
            TimeApi(self.base + "/nomarket").market()
        self.assertEqual((caught.exception.status, caught.exception.code), (404, "no_market"))
        with self.assertRaises(ApiError) as caught:
            TimeApi(self.base + "/syncing").market_orders("sell")
        self.assertEqual((caught.exception.status, caught.exception.code, caught.exception.retry_after, caught.exception.body["market_index"]["ready"]), (503, "market_index_not_ready", 5, False))
        Handler.seen.clear()
        refused = (
            (lambda: api.market_orders("both"), 'side is "sell" or "buy"'), (lambda: api.market_orders(None), "side is"), (lambda: api.market_orders("sell", limit=0), "limit is a whole number from 1 to 200"),
            (lambda: api.market_orders("sell", limit="5"), "limit is"), (lambda: api.market_orders("sell", limit=True), "limit is"), (lambda: api.market_orders("sell", cursor="12.0"), "cursor is a next_cursor"),
            (lambda: api.market_orders("sell", cursor="1.1&side=buy"), "cursor is"), (lambda: api.market_depth(201), "limit is"), (lambda: api.market_order(0), "An order is its number"),
            (lambda: api.market_order("1/../../status"), "An order is"), (lambda: api.market_order("01"), "An order is"), (lambda: api.market_order(None), "An order is"), (lambda: api.market_fill(-1), "A fill is its number"),
            (lambda: api.market_fill("2?x=1"), "A fill is"), (lambda: api.market_fill(2.0), "A fill is"), (lambda: api.market_script("0014" + "AB" * 20), "standard forms"), (lambda: api.market_script("0014ab"), "standard forms"),
            (lambda: api.market_script(None), "standard forms"), (lambda: api.market_trades(order="up"), 'order is "asc" or "desc"'), (lambda: api.market_trades(cursor="250000000.1x"), "cursor is"),
            (lambda: api.market_candles("1h"), "interval is one of hour, 1m, 5m, 15m, 1d"), (lambda: api.market_candles("hour", from_micros="0"), "from_micros is a moment"), (lambda: api.market_candles("hour", to_micros=-1), "to_micros is a moment"),
            (lambda: api.market_candles("hour", to_micros=10**16), "to_micros is"), (lambda: api.account_market("06"), "An account is its number"), (lambda: api.account_market(6, cursor="x"), "cursor is"),
        )
        for call, why in refused:
            with self.assertRaisesRegex(ValueError, why):
                call()
        self.assertEqual(Handler.seen, [], "a refused argument asks nothing of the server")

    def test_what_is_not_an_answer_of_the_api(self):
        with self.assertRaises(ApiError) as caught:
            TimeApi(self.base).health()
        self.assertEqual((caught.exception.status, caught.exception.code, caught.exception.retry_after, caught.exception.body["reasons"]), (503, "unhealthy", 7, ["indexer_stopped"]))
        for prefix, status, why in (("/moved", 302, "a redirect"), ("/text", 200, "not JSON"), ("/words", 500, "refused the request"), ("/large", 200, "larger than 8 MiB")):
            Handler.seen.clear()
            with self.assertRaisesRegex(ApiError, why) as caught:
                TimeApi(self.base + prefix).status()
            self.assertEqual(caught.exception.status, status, prefix)
            self.assertEqual(len(Handler.seen), 1, "asked once")
        started = time.monotonic()
        with self.assertRaisesRegex(ApiError, "No answer from the API") as caught:
            TimeApi(self.base + "/slow", timeout=0.3).status()
        self.assertIsNone(caught.exception.status)
        self.assertLess(time.monotonic() - started, 5, "the request was given up at its timeout, before the answer came")
        # Nobody listens there.
        free = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = free.server_address[1]
        free.server_close()
        with self.assertRaisesRegex(ApiError, "No answer from the API"):
            TimeApi(f"http://127.0.0.1:{port}", timeout=2).status()

    def test_the_address_of_the_api(self):
        for bad in ("", "api.example.org", "ftp://api.example.org", "file:///etc/passwd", "https://", "https://api.example.org?x=1", "https://api.example.org/#x", "https://user:secret@api.example.org", None, 5):
            with self.assertRaisesRegex(ValueError, "The address of the API"):
                TimeApi(bad)
        for bad in (0, -1, 301, "10", None, True, float("nan")):
            with self.assertRaisesRegex(ValueError, "timeout is a number of seconds"):
                TimeApi("https://api.example.org", timeout=bad)
        self.assertTrue(TimeApi("https://api.example.org/time/", timeout=2.5))


if __name__ == "__main__":
    unittest.main()
