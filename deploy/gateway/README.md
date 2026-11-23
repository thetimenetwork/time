# Separate private HTTPS gateway component

This bootstrap wraps the protocol4 SDK factory with fixed private upstream ports, independently pinned trust, durable state and explicit HTTPS origins. It provides no Bitcoin payment or registration sponsor signing callbacks. A newly registering device must obtain a valid paid sponsor action from an explicit external funding route. The gateway never receives a wallet device password, consensus secret or foundation spending key.

Use the separately allowlisted SDK distribution with Node **26.13.0**. Copy `settings.example.json` into an operator directory outside every source/build context. Provision its trust manifest and SHA256 through a channel independent of the RPC being verified. Set the merchant recipient, fixed listener ports and two canonical HTTPS origins. The data directory contains durable checkpoints, SQLite orders, receipt archive and inbox; back it up with the service stopped. Changing the trusted manifest requires independent checkpoint verification, stopping the service and an explicit configuration update.

```sh
node deploy/gateway/start.mjs /etc/time-v4/gateway.json
```

The supplied container definition requires a pinned runtime digest and refuses another Node version. Only gateway source/public assets enter that context. Mount the operator directory read-only and the separate gateway data directory read-write. Configure the private RPC endpoint via an authenticated operator tunnel or reviewed read/submission relay. Keep this gateway outside the validator/ABCI/remote-signer network namespace; the Dockerfile deliberately supplies no network topology or host port publication. Do not change the RPC URL to an arbitrary external website or pass user-selected RPC endpoints to this adapter.

Once it serves, the process prints one JSON line with `status` `PRIVATE_HTTPS_PROXY_UPSTREAMS_READY`. Its field `nodes_report_upgrades` says whether the pinned manifest's trust data declares that the network's nodes report scheduled upgrades (`trust.nodes_report_upgrades: true`; `tools/genesis-v5.mjs` writes it for a production network). When it is `true`, every state this server verifies carries the question about scheduled upgrades, and so does every read of a wallet that installs this trust data. When it is `false`, a second line on the error log, `UPGRADE_REPORTS_NOT_DECLARED`, warns that the weaker way is in use: the question is asked apart, where a gateway can leave it unanswered. If the network's nodes are time-node-v5 0.7.0 or later, pin a manifest whose trust data says so.

The bootstrap first verifies a fresh authenticated state view and permits only one process per checkpoint/order data directory. A crash leaves its local lock intact: confirm the old process is stopped and authenticate its highest checkpoint before removing that lock. This is a single-host storage guard, not a cross-host signing fence. The optional systemd unit runs as `timegateway`; set its data directory to `/var/lib/time-v4-gateway` and provision Node26.13.0, the service user and reviewed private RPC tunnel separately.

Provision DNS and certificates separately. Apply the frozen `client-v4/nginx.example.conf` with exact origins and matching fixed loopback upstream ports. The bootstrap rejects the factory's dynamic-port fallback so an occupied port cannot silently redirect a configured TLS proxy to another process. The application ignores forwarded trust headers; the proxy must preserve the configured exact Host. TLS private keys and CA-test fixtures are never bundled. No container, DNS, certificate, external signer or public monetary network is automatically deployed.

Native and gateway component identities are separate. Keep the native operator's original release manifest and lease scope; the top-level distribution records the immutable native image and gateway asset hashes. Publishing/signing a registry manifest digest is a separate controlled operator step: a local Docker image config ID alone is not a registry `NAME@sha256` manifest reference. Component/version smoke and local private-CA tests do not satisfy independent review, operator-independence or multi-host launch gates.

## The demo blog on the merchant origin

The second origin (`public_origins.merchant`) serves the demo blog `web-v4/merchant`: people sign in with their wallet, write posts of up to 500 characters, delete their own, and can support the blog with 0.1 seconds through the order routes; an account with a settled order gets a "supporter" mark. The routes and their checks are in `client-v4/README.md`, "The demo blog on the second origin". It needs no setting.

- **Where the posts are.** In the data directory, beside the orders: `orders.json.blog.sqlite` (the orders are in `orders.json.sqlite`), with its `-wal` and `-shm` files while the gateway runs. Back it up with the rest of the directory. The posts are public: the file holds account numbers, names, texts and times, nothing secret.
- **Limits.** 20 posts per account in 24 hours (deleting one does not give it back), the newest 500 posts kept, and the request limit of each origin, as for every route.
- **Wiping the blog.** Stop the service, delete `orders.json.blog.sqlite` and its `-wal` and `-shm` files if they are there, start it again. The orders and the supporter marks stay; they go only with `orders.json.sqlite`. The file belongs to one network id: with a reset network the gateway refuses to start until it is removed, as it does for the orders database.

## Where a new account is registered (optional)

A new account needs a sponsor: an existing account pays the registration charge and signs for the new key (`deploy/faucet/README.md`, "Sponsored registrations"). This gateway holds no key and sponsors nothing. With

```json
"registration_service": "https://faucet.example"
```

it tells the wallet page where to ask, and lets that page (not the blog page) connect to that origin. The wallet then creates an account like this:

- It asks `GET /v1/faucet` of that origin which account sponsors and for which network, and stops if the network is not its own.
- It signs its consent for exactly that sponsor account and sends the new public key, the commitment of the name (not the name) and the consent to `POST /v1/faucet/registrations`. No password and no private key leaves the browser.
- About the chain it believes only the chain: it waits for the receipt of the sponsor's action, checks that it names its key and its commitment, reads the commitment in proven state, and reveals the name. If the service answers that this very registration waits on the chain already, there is no receipt, and the wallet reads proven state for up to half a minute.

What to set up with it:

- The value is a canonical HTTPS origin, other than the wallet's and the shop's: `https://`, a host name of letters, digits, hyphens and dots, and a port if it is not 443. No wildcard, no path. It is written into the wallet page's Content-Security-Policy as it stands, so the start script refuses anything else. The service must answer the wallet's origin: in the faucet's config, `cors_origins` names it.
- What the service learns: the address the person comes from, the new public key and the commitment. Once the wallet has revealed the name on the chain under that key, the service can put that address and that name together. It gets no power over the account.
- What it can do to a sign-up: refuse it, or not answer. The wallet waits fifteen seconds for an answer and reads 64 KiB of it at most; a refusal is shown in the wallet's notice as the service's words, marked and made plain. The key and its encrypted vault stay in the browser, and unlocking again goes on from what the chain shows.
- A faucet sponsors one registration for a key in 24 hours. If it took the request and its action never reached a block, that browser's key for that name gets no second one from it that day.
- Without the setting a wallet served by this gateway cannot create an account: it says that its service names no registration sponsor, before it makes a key.

This path ran in a real browser against a live network for the first time on 2026-11-19 (see `campaign/README.md`, "The browser check"), with the harness's gateway on a loopback address, not behind this bootstrap and TLS.

## Own full node for large payments (optional)

With `own_node`, the gateway settles an order of a given amount or more only once a full node you run also reports the payment committed. Why, how to run that node and what is checked: "Large payments: confirm with your own node" in `client-v4/README.md`. JSON allows no comments, so `settings.example.json` leaves the setting out; add it to your settings file:

```json
"own_node": {
  "rpc_url": "http://127.0.0.1:26757/",
  "above_micros": "1000000000",
  "timeout_ms": 5000
}
```

- `rpc_url` (required): the RPC of your node, as an explicit literal-loopback HTTP origin like `native_rpc_url`; reach a node on another machine through an authenticated tunnel. It must not be `native_rpc_url`: the light client checks what that endpoint serves, and the own-node check must not depend on it. (Comparing the two addresses is a sanity check; it cannot tell that a tunnel leads to the same node.)
- `above_micros` (default `"0"`: every order): orders of this amount or more, in microseconds as a decimal string like `recipient`, need your node's confirmation. The threshold applies to each order by itself.
- `timeout_ms` (default `5000`, from 100 to 60000): the longest one check may take.

The node must be on the network of the pinned manifest. After it could not confirm a payment, that order is refused at once for two seconds.

Without `own_node` the gateway settles as before. With it, the gateway also starts while your node is down; large orders then stay unsettled until the node answers and agrees. The blog page asks again for five minutes and tells the buyer not to pay again; it keeps the payment in the browser and finishes the settlement when reopened, and any later settlement request for that order and payment settles it. A node that contradicts the light client is written to the gateway's error log (order, payment, node address, reason) and kept on the order.
