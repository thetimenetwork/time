#!/usr/bin/env bash
# Sets up a validator node of the Time test network on this machine, and prints the text with which your account
# registers it. Read it before you run it. It is published with the network's source, byte for byte as the network
# hands it out:
#   https://github.com/thetimenetwork/time/blob/main/testnet/join.sh
# so `sha256sum join.sh` prints the same hash for the copy you downloaded, for that file, and on the explorer's page
# "Run a validator".
#
#   sudo bash join.sh --account NUMBER [--commission PERCENT] [--name NAME]
#   sudo bash join.sh --status
#   sudo bash join.sh --registration --account NUMBER [--commission PERCENT]
#   sudo bash join.sh --uninstall [--purge]
#
# What it does, in this order:
#   1. checks the machine: Linux on 64-bit Intel or AMD, systemd, OpenSSL 3, a few common commands;
#   2. downloads the network's description (its chain, the hashes of its programs, its sentries) and the signature of
#      it, and stops unless the network's release key, written below, made that signature. Once installed, a
#      validator keeps the release key it was installed with, and refuses what another key signed;
#   3. downloads the node program, CometBFT and the genesis file, and stops unless each has the SHA-256 that the
#      signed description names;
#   4. makes two users without a login: time-validator runs CometBFT and alone can read the validator key; time-node
#      runs the node program, which reads every action anyone sends to the network: it has no network of its own and
#      cannot read the key. The two speak through a socket file only they can open;
#   5. makes the validator key with CometBFT, on this machine, unless there is one already;
#   6. writes CometBFT's settings (it connects out to the network's sentries and listens on this machine only) and
#      two systemd services, time-node and time-cometbft, each held to what it needs, and starts them;
#   7. signs, with the validator key, the statement that the account you named may register this validator, and
#      prints it: the registration text you paste into the wallet;
#   8. watches the node read the chain from its first block (about half an hour for each day the network has run),
#      until it has caught up or you press Ctrl-C. The node goes on either way.
# The only things it asks of the network are the downloads. The validator key never leaves this machine, and nothing
# here knows a key or a password of your account.
#
# To follow the network later, run the copy it keeps, not a new download: sudo bash /opt/time-validator/join.sh. It keeps
# the key and the data, and brings the programs, the settings and the sentries up to what the network's signed
# description says now. It replaces itself only with the script that description names by its SHA-256.
#
# What it cannot do: tell you whether the copy of this script you run the first time is the real one. Compare it with
# the one published with the source, from a computer you trust, before you run it.
#
# This is a test network: its seconds have no value and it may be reset.
set -euo pipefail
umask 022
ARGS=("$@")

# ---- the network. The two values a copy of this script is made for: where it downloads from, and the public half of
# the key that signs the network's description (testnet/release.mjs in the source). Nothing else is written here.
BASE='https://testnet.thetimenetwork.org/join'
RELEASE_KEY='9aebba27a34baec44d6184b8ac2ecc4517d4a0ba5922b54c54ce726d0a4111aa'

# ---- where things go on this machine
OPT=/opt/time-validator
DATA=/var/lib/time-validator
NODE_HOME=$DATA/node             # CometBFT's: the validator key and the blocks, time-validator's alone
APP_DIR=$DATA/app                # the node program's state, time-node's alone
SOCKET_DIR=$DATA/abci            # the socket file between the two
SOCKET=$SOCKET_DIR/abci.sock
PINNED=$DATA/release-key         # the release key this validator was installed with
DESCRIPTION=$DATA/network.txt    # the last description it took, with its signature beside it
COMET_USER=time-validator
APP_USER=time-node
SOCKET_GROUP=time-abci
KEY_FILE=$NODE_HOME/config/priv_validator_key.json

say() { printf '%s\n' "$*"; }
die() { printf 'join.sh: %s\n' "$*" >&2; exit 1; }
hex2bin() { printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
bin2hex() { od -An -v -tx1 | tr -d ' \n'; }
as_comet() { runuser -u "$COMET_USER" -- "$@"; }
as_app() { runuser -u "$APP_USER" -- "$@"; }

ACCOUNT='' COMMISSION=10 NAME='' ACTION=install PURGE=no NEW_KEY=no
while [ $# -gt 0 ]; do
  case "$1" in
    --account) ACCOUNT=${2:-}; shift 2 ;;
    --commission) COMMISSION=${2:-}; shift 2 ;;
    --name) NAME=${2:-}; shift 2 ;;
    --status) ACTION=status; shift ;;
    --registration) ACTION=registration; shift ;;
    --uninstall) ACTION=uninstall; shift ;;
    --purge) PURGE=yes; shift ;;
    --trust-new-release-key) NEW_KEY=yes; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown word: $1 (see --help)" ;;
  esac
done
[ "$(id -u)" = 0 ] || die 'run it as root: sudo bash join.sh ...'
case "$ACCOUNT" in ''|*[!0-9]*) [ -z "$ACCOUNT" ] || die '--account is the number of your account, as the wallet shows it on Home' ;; esac
case "$ACCOUNT" in 0?*) die '--account is the number of your account, as the wallet shows it on Home (no zero in front)' ;; esac
[ ${#ACCOUNT} -le 15 ] || die '--account is the number of your account, as the wallet shows it on Home'
case "$COMMISSION" in ''|*[!0-9]*) die '--commission is a whole number of percent, from 0 to 20' ;; esac
[ "$COMMISSION" -le 20 ] || die '--commission is a whole number of percent, from 0 to 20'
[ -n "$NAME" ] || NAME="validator-${ACCOUNT:-new}"
case "$NAME" in *[!A-Za-z0-9_-]*) die '--name is letters, digits, - and _ only' ;; esac
[ ${#NAME} -le 32 ] || die '--name is at most 32 characters'

# ---- what the node is doing
ask() { curl -fsS --max-time 5 "http://127.0.0.1:26657/$1" 2>/dev/null | tr -d ' \n'; }
field() { sed -n "s/.*\"$1\":\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -n 1; }
status() {
  local s height catching power peers
  say "time-node:     $(systemctl is-active time-node 2>/dev/null || true)"
  say "time-cometbft: $(systemctl is-active time-cometbft 2>/dev/null || true)"
  [ -f "$PINNED" ] && say "release key:   $(tr -d ' \n\r' < "$PINNED")"
  s=$(ask status) || true
  if [ -z "$s" ]; then say 'CometBFT does not answer on this machine yet (it answers some seconds after it starts).'; return 0; fi
  height=$(printf '%s' "$s" | field latest_block_height); catching=$(printf '%s' "$s" | field catching_up); power=$(printf '%s' "$s" | field voting_power)
  peers=$(ask net_info | field n_peers) || true
  say "chain:         $(printf '%s' "$s" | field network)"
  say "block:         ${height:-?}$( [ "$catching" = true ] && printf ' (still catching up with the network)' )"
  say "connected to:  ${peers:-0} node(s)"
  if [ "${power:-0}" != 0 ]; then say "votes:         $power - this validator is in the set"; else say 'votes:         0 - not in the set (not registered yet, or the registration is less than two blocks old)'; fi
}

uninstall() {
  systemctl disable --now time-cometbft.service time-node.service 2>/dev/null || true
  rm -f /etc/systemd/system/time-cometbft.service /etc/systemd/system/time-node.service
  systemctl daemon-reload
  rm -rf "$OPT"
  if [ "$PURGE" = yes ]; then
    rm -rf "$DATA"
    userdel "$COMET_USER" 2>/dev/null || true
    userdel "$APP_USER" 2>/dev/null || true
    groupdel "$SOCKET_GROUP" 2>/dev/null || true
    say 'Removed: the services, the programs, the validator key and the data.'
  else
    say "Removed: the services and the programs. Kept: $DATA, with the validator key and the data."
    say 'Your validator stays registered on the chain. Take its bond out in the wallet if you are not coming back.'
  fi
}

case "$ACTION" in
  status) status; exit 0 ;;
  uninstall) uninstall; exit 0 ;;
esac

# ---- 1. the machine
[ "$(uname -s)" = Linux ] || die 'this script is for Linux'
[ "$(uname -m)" = x86_64 ] || die "the node program is built for 64-bit Intel and AMD machines (x86_64); this one is $(uname -m)"
[ -d /run/systemd/system ] || die 'this script sets up systemd services, and this machine does not run systemd'
for tool in curl sha256sum tar gzip openssl base64 od sed awk grep head tail tr wc useradd groupadd usermod install runuser mktemp df readlink; do
  command -v "$tool" >/dev/null 2>&1 || die "the command '$tool' is missing: install it and run the script again"
done
OPENSSL_MAJOR=$(openssl version | awk '{ split($2, v, "."); print v[1] }')
[ "${OPENSSL_MAJOR:-0}" -ge 3 ] || die "OpenSSL 3 or newer is needed to check the network's signature; this machine has $(openssl version)"
# The work folder: in memory where the machine has /dev/shm (the registration text is signed there, see below).
TMP=$(mktemp -d -p /dev/shm 2>/dev/null || mktemp -d); trap 'rm -rf "$TMP"' EXIT

# ---- 2. the network's description, signed by its release key
# The key this validator trusts: the one it was installed with, if it was.
if [ -f "$PINNED" ]; then
  PIN=$(tr -d ' \n\r\t' < "$PINNED")
  if [ "$PIN" != "$RELEASE_KEY" ]; then
    [ "$NEW_KEY" = yes ] || die "this validator was installed trusting the release key $PIN, and this copy of the script carries $RELEASE_KEY. A copy of the script from somewhere else, or a network that changed its key? Compare this script with the published one (see its first lines). If you are sure, run it again with --trust-new-release-key."
    say "Note: this validator was installed trusting the release key $PIN; from now on it trusts $RELEASE_KEY, as you asked." >&2
  fi
fi
[[ $RELEASE_KEY =~ ^[0-9a-f]{64}$ ]] || die 'this copy of the script carries no release key of 32 bytes in hexadecimal'
fetch() { # name, where to
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --max-time 600 -o "$2" "$BASE/$1" || die "could not download $BASE/$1"
}
verify_description() { # the description, its signature (hexadecimal)
  local signature
  signature=$(tr -d ' \n\r\t' < "$2")
  [[ $signature =~ ^[0-9a-f]{128}$ ]] || return 1
  hex2bin "$signature" > "$TMP/signature.bin"
  # The public key in the wrapping OpenSSL reads (SubjectPublicKeyInfo for Ed25519, RFC 8410).
  hex2bin "302a300506032b6570032100$RELEASE_KEY" > "$TMP/release.der"
  openssl pkeyutl -verify -pubin -inkey "$TMP/release.der" -keyform DER -rawin -in "$1" -sigfile "$TMP/signature.bin" >/dev/null 2>&1
}
# The description is the line FORMAT=time-join-manifest-1, then these thirteen fields in this order, one NAME=value a
# line, each in its form below (testnet/join.mjs, manifestText). Anything else is refused.
FIELDS=(CHAIN_ID NETWORK_ID NODE_SHA256 COMET_SHA256 GENESIS_SHA256 PEERS PACE MIN_BOND_MICROS WALLET EXPLORER SCRIPT_SHA256 SEQUENCE EXPIRES)
form_of() {
  case "$1" in
    CHAIN_ID) printf '%s' '^[a-z0-9-]{3,64}$' ;;
    NETWORK_ID|NODE_SHA256|COMET_SHA256|GENESIS_SHA256|SCRIPT_SHA256) printf '%s' '^[0-9a-f]{64}$' ;;
    SEQUENCE|EXPIRES) printf '%s' '^[1-9][0-9]{0,15}$' ;;
    PEERS) printf '%s' '^[0-9a-f]{40}@([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}(,[0-9a-f]{40}@([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}){0,7}$' ;;
    PACE) printf '%s' '^([1-9][0-9]{2}ms|[1-5]s)$' ;;
    MIN_BOND_MICROS) printf '%s' '^[1-9][0-9]{0,14}$' ;;
    WALLET) printf '%s' '^https://[a-z0-9.-]+(:[0-9]{1,5})?$' ;;
    EXPLORER) printf '%s' '^https://[a-z0-9.-]+(:[0-9]{1,5})?/explorer/$' ;;
  esac
}
read_description() { # file
  local file=$1 line name value form i=0
  [ "$(wc -l < "$file")" -eq $(( ${#FIELDS[@]} + 1 )) ] && [ -z "$(tail -c 1 "$file" | tr -d '\n')" ] || die 'the network description does not have its lines'
  while IFS= read -r line; do
    if [ $i -eq 0 ]; then
      [ "$line" = 'FORMAT=time-join-manifest-1' ] || die 'the network description is not in a format this script reads: download the script again'
    else
      name=${FIELDS[$((i - 1))]}
      case "$line" in "$name="*) value=${line#"$name="} ;; *) die "line $((i + 1)) of the network description is not $name" ;; esac
      form=$(form_of "$name")
      [[ $value =~ $form ]] || die "$name in the network description is not in its form"
      printf -v "$name" '%s' "$value"
    fi
    i=$((i + 1))
  done < "$file"
}
# Progress goes to the error stream: with --registration the script prints the registration text and nothing else.
say "Downloading the network's description and its signature ..." >&2
fetch network.txt "$TMP/network.txt"
fetch network.sig "$TMP/network.sig"
verify_description "$TMP/network.txt" "$TMP/network.sig" || die "the network's description is not signed by the release key $RELEASE_KEY. Nothing was installed."
read_description "$TMP/network.txt"
# A description that has expired is of a network that has ended, or whose operator has not signed it again.
[ "$(date +%s)" -le "$EXPIRES" ] || die "the network's description expired at $(date -u -d "@$EXPIRES" 2>/dev/null || printf '%s' "$EXPIRES"): the network has ended, or its operator has not signed its description again. Nothing was changed."
# An installed validator takes no description older than the one it took: the release key signed every description it
# was ever asked to, and an old one would name sentries or programs of before.
if [ -f "$DESCRIPTION" ]; then
  KEPT=$(sed -n 's/^SEQUENCE=\([1-9][0-9]\{0,15\}\)$/\1/p' "$DESCRIPTION" | head -n 1)
  if [ -n "$KEPT" ] && [ "$SEQUENCE" -lt "$KEPT" ]; then die "the network handed out a description older than the one this validator took (signed at $SEQUENCE, before $KEPT). Nothing was changed."; fi
fi
say "The description is signed by the release key: chain $CHAIN_ID." >&2

# ---- the registration text: what the account signs to register this validator's key.
# The chain accepts a registration only with a signature of the validator key over these bytes:
#   "TIME-POS-REGISTER-V1", a zero byte, the network id (32 bytes), the account number (8 bytes),
#   the validator's public key (32 bytes), the commission in hundredths of a percent (2 bytes).
# So a registration text made for one account, network or commission is of no use for another.
registration() {
  [ -n "$ACCOUNT" ] || die 'the registration text is made for one account: pass --account NUMBER'
  [ -f "$KEY_FILE" ] || die "there is no validator key at $KEY_FILE yet: run the script without --registration first"
  local key hex seed public stated bps proof
  # CometBFT keeps the key as base64 of 64 bytes: the 32-byte secret seed, then the 32-byte public key.
  key=$(tr -d ' \n\r\t' < "$KEY_FILE" | sed -n 's/.*"priv_key":{"type":"tendermint\/PrivKeyEd25519","value":"\([A-Za-z0-9+\/=]*\)".*/\1/p')
  stated=$(tr -d ' \n\r\t' < "$KEY_FILE" | sed -n 's/.*"pub_key":{"type":"tendermint\/PubKeyEd25519","value":"\([A-Za-z0-9+\/=]*\)".*/\1/p')
  [ -n "$key" ] && [ -n "$stated" ] || die "$KEY_FILE is not a CometBFT Ed25519 key file"
  hex=$(printf '%s' "$key" | base64 -d | bin2hex)
  [ ${#hex} = 128 ] || die "$KEY_FILE does not hold a 64-byte key"
  seed=${hex:0:64}; public=${hex:64:64}
  [ "$(printf '%s' "$stated" | base64 -d | bin2hex)" = "$public" ] || die "$KEY_FILE names two different public keys"
  bps=$((COMMISSION * 100))
  { printf 'TIME-POS-REGISTER-V1\0'; hex2bin "$NETWORK_ID$(printf '%016x' "$ACCOUNT")$public$(printf '%04x' "$bps")"; } > "$TMP/statement"
  # The seed, in the wrapping OpenSSL reads (PKCS#8 for Ed25519, RFC 8410: sixteen fixed bytes, then the seed), goes to
  # the work folder, which is in memory (/dev/shm) on a machine that has it, readable by root alone, and is removed as
  # soon as OpenSSL has signed.
  ( umask 077; hex2bin "302e020100300506032b657004220420$seed" > "$TMP/key.der" )
  openssl pkeyutl -sign -inkey "$TMP/key.der" -keyform DER -rawin -in "$TMP/statement" -out "$TMP/signature" 2>/dev/null || { rm -f "$TMP/key.der"; die 'OpenSSL could not sign with the validator key (OpenSSL 3 is needed)'; }
  rm -f "$TMP/key.der"
  proof=$(bin2hex < "$TMP/signature")
  [ ${#proof} = 128 ] || die 'the signature is not 64 bytes'
  printf '{"commission_bps":%s,"consensus_key":"%s","networkId":"%s","owner":"%s","proof":"%s"}\n' "$bps" "$public" "$NETWORK_ID" "$ACCOUNT" "$proof"
}
if [ "$ACTION" = registration ]; then registration; exit 0; fi

# ---- the script itself. The description names the script this network hands out by its SHA-256. A copy that is not that
# script (the copy kept on this machine, from before) takes it, by that hash only, and runs it in its own place.
SELF=$(readlink -f "$0" 2>/dev/null || true)
if [ -f "$SELF" ] && [ "$(sha256sum "$SELF" | cut -d' ' -f1)" != "$SCRIPT_SHA256" ]; then
  [ -z "${TIME_JOIN_REPLACED:-}" ] || die 'the script the network hands out is not the one its signed description names. Nothing was changed.'
  fetch join.sh "$TMP/join.sh"
  printf '%s  %s\n' "$SCRIPT_SHA256" "$TMP/join.sh" | sha256sum -c --status - || die "the network hands out a script that its signed description does not name (it names $SCRIPT_SHA256). Nothing was changed."
  install -d -m 755 "$OPT"
  install -m 755 "$TMP/join.sh" "$OPT/join.sh"
  say "The network's signed description names another join script: it is now $OPT/join.sh, and runs in place of this one."
  rm -rf "$TMP"; trap - EXIT
  TIME_JOIN_REPLACED=1 exec bash "$OPT/join.sh" ${ARGS[@]+"${ARGS[@]}"}
fi

FREE_GB=$(df -Pk /var/lib | awk 'NR == 2 { printf "%d", $4 / 1048576 }')
[ "${FREE_GB:-0}" -ge 20 ] || say "Note: /var/lib has ${FREE_GB:-?} GB free. The chain grows by about three quarters of a GB a day."
if command -v timedatectl >/dev/null 2>&1 && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" != yes ]; then
  say 'Note: this machine does not say that its clock is kept right (timedatectl). A validator whose clock is more than 30 seconds off is not listened to.'
fi
# A machine that ran a chain of this network before it was reset: its data and its validator belong to a chain that is
# gone. Nothing is changed before this is said.
if [ -f "$NODE_HOME/config/genesis.json" ] && ! printf '%s  %s\n' "$GENESIS_SHA256" "$NODE_HOME/config/genesis.json" | sha256sum -c --status -; then
  die "the data in $DATA is of another chain than $CHAIN_ID: the network was reset since this machine joined it (or this machine ran another network). The old chain is gone, with your account and your validator. 'sudo bash join.sh --uninstall --purge' removes the old data and the old validator key; then make an account again in the wallet ($WALLET), run this script again with its number, and register the validator again."
fi

# ---- 3. the three files, each by the SHA-256 the signed description names
get() { # name, SHA-256
  say "Downloading $1 ..."
  fetch "$1" "$TMP/$1"
  printf '%s  %s\n' "$2" "$TMP/$1" | sha256sum -c --status - || die "$1 does not have the SHA-256 the network's signed description names ($2). Nothing was installed from it."
}
get time-node-v5 "$NODE_SHA256"
get cometbft.tar.gz "$COMET_SHA256"
get genesis.json "$GENESIS_SHA256"
tar -xzf "$TMP/cometbft.tar.gz" -C "$TMP" cometbft || die 'cometbft.tar.gz does not hold the program cometbft'

# ---- 4. the users and the folders
NOLOGIN=$(command -v nologin || printf /bin/false)
getent group "$SOCKET_GROUP" >/dev/null 2>&1 || groupadd --system "$SOCKET_GROUP"
id -u "$COMET_USER" >/dev/null 2>&1 || useradd --system --user-group --home-dir "$NODE_HOME" --no-create-home --shell "$NOLOGIN" "$COMET_USER"
id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --user-group --home-dir "$APP_DIR" --no-create-home --shell "$NOLOGIN" "$APP_USER"
usermod -a -G "$SOCKET_GROUP" "$COMET_USER"
install -d -m 755 "$OPT" "$OPT/bin"
install -d -m 755 -o root -g root "$DATA"
install -d -m 700 -o "$COMET_USER" -g "$COMET_USER" "$NODE_HOME"
install -d -m 700 -o "$APP_USER" -g "$APP_USER" "$APP_DIR"
# The socket file takes the group of its folder: only the node program makes it, only CometBFT's user may open it.
install -d -m 2750 -o "$APP_USER" -g "$SOCKET_GROUP" "$SOCKET_DIR"
systemctl stop time-cometbft.service time-node.service 2>/dev/null || true
install -m 755 "$TMP/time-node-v5" "$OPT/bin/time-node-v5"
install -m 755 "$TMP/cometbft" "$OPT/bin/cometbft"
# The downloaded programs run as their users, never as root, from the first time they run.
(cd / && as_app "$OPT/bin/time-node-v5" --version) >/dev/null 2>&1 || die 'the node program does not start on this system. It needs a Linux from 2022 or later (glibc 2.34): Ubuntu 22.04, Debian 12, Amazon Linux 2023, RHEL 9 or newer.'
(cd / && as_comet "$OPT/bin/cometbft" version) >/dev/null 2>&1 || die 'CometBFT does not start on this system'

# ---- 5. the validator key, made here and kept here
if [ ! -f "$KEY_FILE" ]; then
  as_comet "$OPT/bin/cometbft" init validator --home "$NODE_HOME" >/dev/null
  say "Made a new validator key: $KEY_FILE"
else
  say "Kept the validator key that is here: $KEY_FILE"
fi
install -m 644 -o "$COMET_USER" -g "$COMET_USER" "$TMP/genesis.json" "$NODE_HOME/config/genesis.json"

# ---- 6. CometBFT's settings, and the two services
set_toml() { # section ('' for the top of the file), key, value as it is written
  local file=$NODE_HOME/config/config.toml next
  next=$(mktemp)
  awk -v section="$1" -v key="$2" -v value="$3" '
    /^[[:space:]]*\[/ { current = $0; gsub(/^[[:space:]]*\[|\].*$/, "", current) }
    { if (current == section && $0 ~ ("^[[:space:]]*" key "[[:space:]]*=")) { print key " = " value; done++ } else print }
    END { if (done != 1) exit 3 }' "$file" > "$next" || { rm -f "$next"; die "CometBFT's settings file has no single line for $2 in [$1]"; }
  cat "$next" > "$file"; rm -f "$next"
}
set_toml '' proxy_app "\"unix://$SOCKET\""          # the node program, through the socket file only these two users open
set_toml '' moniker "\"$NAME\""
set_toml '' log_level '"error"'
set_toml rpc laddr '"tcp://127.0.0.1:26657"'        # CometBFT's own questions: from this machine only
set_toml rpc unsafe false
set_toml p2p laddr '"tcp://127.0.0.1:26656"'        # nobody connects in: this node connects out
set_toml p2p persistent_peers "\"$PEERS\""          # the network's sentries, as its signed description names them
set_toml p2p pex false
set_toml p2p addr_book_strict false
set_toml p2p persistent_peers_max_dial_period '"30s"'
set_toml mempool max_tx_bytes 524480                # as on the network's validators
set_toml mempool size 20000
set_toml mempool max_txs_bytes 268435456
set_toml mempool cache_size 40000
set_toml consensus timeout_commit "\"$PACE\""
set_toml consensus timeout_propose '"3s"'
set_toml storage discard_abci_responses false
set_toml tx_index indexer '"null"'
set_toml instrumentation prometheus false

# What both services may not do (systemd.exec(5)): gain a privilege, write anywhere but their own folder, see a home
# folder, the machine's devices, another program's files in /proc or /tmp, change a setting of the kernel or the
# clock, or make a system call outside those of an ordinary service.
HARDENING='NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities='
cat > /etc/systemd/system/time-node.service <<EOF
[Unit]
Description=Time test network $CHAIN_ID: the node
After=network.target
[Service]
User=$APP_USER
Group=$APP_USER
UMask=0007
ExecStartPre=/bin/rm -f $SOCKET
ExecStart=$OPT/bin/time-node-v5 --devnet --db $APP_DIR/application.redb --listen unix:$SOCKET --snapshot-seconds 60 --stay-after-disconnect
# The node makes its socket for its own user alone (mode 0600). Once it is there, root lets the socket's group in as
# well: CometBFT's user is the only member, and nobody else can even enter the folder.
ExecStartPost=+/bin/sh -c 'for try in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do if [ -S $SOCKET ]; then chgrp $SOCKET_GROUP $SOCKET && chmod 0660 $SOCKET && exit 0; fi; sleep 1; done; exit 1'
Restart=always
RestartSec=3
TimeoutStopSec=150
LimitNOFILE=65536
# It reads every action anyone sends to the network: it has no network at all, only the socket file.
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
ReadWritePaths=$APP_DIR $SOCKET_DIR
$HARDENING
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/time-cometbft.service <<EOF
[Unit]
Description=Time test network $CHAIN_ID: CometBFT
After=time-node.service
Requires=time-node.service
PartOf=time-node.service
[Service]
User=$COMET_USER
Group=$COMET_USER
SupplementaryGroups=$SOCKET_GROUP
UMask=0077
ExecStartPre=/bin/sh -c 'for try in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -S $SOCKET ] && exit 0; sleep 1; done; exit 1'
ExecStart=$OPT/bin/cometbft start --home $NODE_HOME
Restart=always
RestartSec=5
LimitNOFILE=65536
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=$NODE_HOME
$HARDENING
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now time-node.service time-cometbft.service >/dev/null 2>&1 || die "the services did not start: see 'journalctl -u time-node -u time-cometbft'"

# What this validator trusts from now on, and a copy of this script to run again (the copy of the script run from a
# file; one piped into bash leaves none).
printf '%s\n' "$RELEASE_KEY" > "$PINNED.next" && chmod 644 "$PINNED.next" && mv -f "$PINNED.next" "$PINNED"
install -m 644 "$TMP/network.txt" "$DESCRIPTION"
install -m 644 "$TMP/network.sig" "$DESCRIPTION.sig"
SELF=$(readlink -f "$0" 2>/dev/null || true)
if [ -f "$SELF" ] && [ "$SELF" != "$OPT/join.sh" ]; then install -m 755 "$SELF" "$OPT/join.sh"; fi

# ---- 7. the registration text
say ''
say 'The node is running, and the system starts it again by itself.'
if [ -z "$ACCOUNT" ]; then
  say 'No account was named, so no registration text was made. When you have an account:'
  say "  sudo bash $OPT/join.sh --registration --account NUMBER"
else
  BOND=$(awk -v m="$MIN_BOND_MICROS" 'BEGIN { printf "%g", m / 1000000 }')
  say "The registration text for account $ACCOUNT, with a commission of $COMMISSION%:"
  say ''
  registration
  say ''
  say "Copy that one line. In the wallet ($WALLET) open More, then Validator operator, paste it and confirm."
  say "If your account is protected, type its payment password there as well: the bond and the fee count against its daily limit."
  say "A bond of $BOND second(s) is taken from your balance. Two blocks later your validator is in the set:"
  say "  $EXPLORER#/validators"
  say ''
  say 'Never run this validator key on a second machine while this one runs: two machines signing with one key lose the bond.'
  say "Keep a copy of $KEY_FILE somewhere safe if this validator matters to you, and start a copy only once this machine is gone for good."
fi

# ---- 8. the node catches up with the network: every block since the first, checked on this machine.
# It signs nothing before it has caught up. A validator that does not sign earns nothing and loses nothing, so
# registering before that costs nothing but the wait.
say ''
say 'The node now reads the chain from its first block: about half an hour for each day the network has run.'
say 'Your validator signs once the node has caught up. This script watches it: stop watching with Ctrl-C whenever you like, the node goes on.'
while true; do
  S=$(ask status) || true
  if [ -n "$S" ]; then
    if [ "$(printf '%s' "$S" | field catching_up)" = false ]; then say "The node has caught up with the network, at block $(printf '%s' "$S" | field latest_block_height)."; break; fi
    say "  block $(printf '%s' "$S" | field latest_block_height)"
  fi
  sleep 60
done
