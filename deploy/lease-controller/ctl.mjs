#!/usr/bin/env node
// The operator's commands for the signer-lease controller: who holds which consensus key, which
// releases are approved, and the keys of the authority and the hosts. Run it on the controller
// host, as the controller's user. It changes the numbered state files directly, beside the
// running service: a change is one new numbered file, and the service reads it before its next
// answer (docs/design/signer-lease-controller.md, sections 5.2 and 6). Nothing listens for it.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { json } from '../lib.mjs';
import { KEY_PURPOSES, generateKeyRecord, writeKeyFile } from '../lease-protocol.mjs';
import { ClockRefused, CommandRefused, approveRelease, assign, checkBinding, checkClock, emptyState, move, rebaseClock, refence, retireRelease, stamped, summary, timing, unassign, unfreeze, validateState } from './core.mjs';
import { Conflict, fileStore } from './store.mjs';
import { readConfig, validateConfig } from './start.mjs';

export const USAGE = `Usage:
  node deploy/lease-controller/ctl.mjs keygen authority NEW_FILE ID     a lease authority key; prints the entry for the hosts' trust files
  node deploy/lease-controller/ctl.mjs keygen host NEW_FILE ID          a host key (or make it on the host: lease-agent.mjs keygen)
  node deploy/lease-controller/ctl.mjs CONFIG list                      the state: holders, tokens, waits, releases
  node deploy/lease-controller/ctl.mjs CONFIG assign KEY HOST           give a key that has no holder to a host
  node deploy/lease-controller/ctl.mjs CONFIG move KEY HOST --from OLD  move a key; refused unless OLD holds it
  node deploy/lease-controller/ctl.mjs CONFIG unassign KEY              the key has no holder any more
  node deploy/lease-controller/ctl.mjs CONFIG unfreeze KEY              after a freeze, once exactly one machine is that host
  node deploy/lease-controller/ctl.mjs CONFIG refence KEY [--above N]   a new, higher fence token for the same holder
  node deploy/lease-controller/ctl.mjs CONFIG approve-release RELEASE_JSON [--again]
  node deploy/lease-controller/ctl.mjs CONFIG retire-release RELEASE_ID
  node deploy/lease-controller/ctl.mjs CONFIG clock-was-ahead           after the state was written while this machine's clock was ahead; check the clock FIRST
KEY is the validator's consensus public key, 64 hexadecimal characters. Every command that changes
who may hold a key starts a wait that nothing shortens; "list" shows it.`;

function options(words, allowed) {
  const positional = [], flags = {};
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    if (!word.startsWith('--')) { positional.push(word); continue; }
    if (!Object.hasOwn(allowed, word)) throw new CommandRefused(`Unknown option ${word}.\n${USAGE}`);
    if (allowed[word] === 'flag') flags[word] = true;
    else { if (words[i + 1] === undefined) throw new CommandRefused(`${word} needs a value.\n${USAGE}`); flags[word] = words[++i]; }
  }
  return { positional, flags };
}
const exactly = (positional, count) => { if (positional.length !== count) throw new CommandRefused(USAGE); return positional; };

/// Runs one command on the state of `config`. Returns `{changed, result}`; `result` is printed
/// as JSON. `inject` replaces the store, the clock and the manifest reader for tests.
export async function runCommand(config, words, inject = {}) {
  const store = inject.store ?? fileStore(config.data_directory), now = inject.now ?? Date.now, readManifest = inject.readManifest ?? json;
  const [command, ...rest] = words;
  if (command === 'list') {
    exactly(rest, 0);
    const loaded = await store.read();
    if (!loaded) return { changed: false, result: { note: 'This controller has no state yet. It is created by the first start of the service or the first command that changes something.' } };
    const state = checkBinding(validateState(loaded.state), config), at = now();
    let warning = {};
    try { checkClock(state, config, at); } catch (error) { if (!(error instanceof ClockRefused)) throw error; warning = { warning: error.message }; }
    return { changed: false, result: { ...warning, ...summary(state, at) } };
  }
  const t = timing(config);
  // Each change is a function of the newest state. If the service wrote in between, it is
  // applied again to what the service wrote.
  let change, describe = () => ({});
  const about = (id, extra = {}) => (state, at) => ({ ...summary(state, at).keys.find((key) => key.validator_public_key_hex === id), ...extra });
  if (command === 'assign') { const [id, host] = exactly(rest, 2); change = (state, at) => assign(state, config, id, host, at); describe = about(id); }
  else if (command === 'move') {
    const { positional, flags } = options(rest, { '--from': 'value' }), [id, host] = exactly(positional, 2);
    change = (state, at) => move(state, config, id, host, flags['--from'], at);
    describe = about(id, { before_the_new_host_starts: 'Stop the validator on the old host. Move the signer\'s record of what it last signed together with the key, and delete both on the old host. Do not move a key while the chain stands still unless that record moves with it. The lease does not check any of this.' });
  } else if (command === 'unassign') { const [id] = exactly(rest, 1); change = (state, at) => unassign(state, config, id, at); describe = about(id); }
  else if (command === 'unfreeze') { const [id] = exactly(rest, 1); change = (state, at) => unfreeze(state, config, id, at); describe = about(id); }
  else if (command === 'refence') {
    const { positional, flags } = options(rest, { '--above': 'value' }), [id] = exactly(positional, 1), above = flags['--above'];
    if (above !== undefined && (!/^(?:0|[1-9][0-9]{0,19})$/.test(above) || BigInt(above) >= 18446744073709551615n)) throw new CommandRefused('--above takes a fence token: a whole number in decimal, as a lease file shows it');
    change = (state, at) => refence(state, config, id, at, above === undefined ? 0n : BigInt(above)); describe = about(id);
  } else if (command === 'approve-release') {
    const { positional, flags } = options(rest, { '--again': 'flag' }), [file] = exactly(positional, 1);
    let manifest;
    try { manifest = await readManifest(file); } catch (error) { throw new CommandRefused(`The release manifest could not be read (${error.message}).`); }
    change = (state) => approveRelease(state, manifest, { again: flags['--again'] === true });
    describe = (state, at) => ({ approved: manifest.release_id, releases: summary(state, at).releases });
  } else if (command === 'retire-release') { const [id] = exactly(rest, 1); change = (state) => retireRelease(state, id); describe = (state, at) => ({ retired: id, releases: summary(state, at).releases }); }
  else if (command === 'clock-was-ahead') {
    exactly(rest, 0);
    let report = [];
    // The one command that works on a state written with a later clock: it is the way out of that.
    change = (state, at) => { const done = rebaseClock(state, config, at); report = done.report; return done.state; };
    describe = () => ({ every_wait_is_now_counted_from_this_clock: new Date(now()).toISOString(), keys: report, next: 'Start the controller. Keys whose lease is not running wait five minutes plus the margin from that start.' });
  } else throw new CommandRefused(USAGE);

  for (let attempt = 0; attempt < 8; attempt++) {
    const loaded = await store.read(), at = now();
    const base = loaded ? checkBinding(validateState(loaded.state), config) : emptyState(config, at);
    // No command changes a state that holds a time later than this clock, except the way out of it.
    if (command !== 'clock-was-ahead') checkClock(base, config, at);
    const next = stamped(change(base, at), at);
    try { await store.write((loaded?.seq ?? 0) + 1, next, loaded?.sha256 ?? null); } catch (error) { if (error instanceof Conflict) continue; throw error; }
    return { changed: true, result: { done: command, ...describe(next, at), margin_seconds: t.marginMs / 1000 } };
  }
  throw new Error('The controller state kept changing. Nothing was changed by this command. Try again.');
}

async function main(argv) {
  if (argv[0] === 'keygen') {
    const [, kind, file, id] = argv;
    if (argv.length !== 4 || !Object.hasOwn(KEY_PURPOSES, kind)) throw new CommandRefused(USAGE);
    const made = await writeKeyFile(path.resolve(file), generateKeyRecord(KEY_PURPOSES[kind], id));
    // Public values only. What to do with them is in the README.
    return kind === 'authority'
      ? { made: 'lease authority key', trust_file_entry: { id: made.id, organization: 'REPLACE_WITH_YOUR_ORGANIZATION', public_key_hex: made.public_key_hex, roles: ['signer_lease'] } }
      : { made: 'host key', controller_config_host_entry: { id: made.id, public_key_hex: made.public_key_hex, signer_identity: 'REPLACE_WITH_THE_HOSTS_SIGNER_IDENTITY', signer_fencing: 'NOT_DECLARED' } };
  }
  if (argv.length < 2) throw new CommandRefused(USAGE);
  const config = validateConfig(await readConfig(argv[0]));
  return (await runCommand(config, argv.slice(1))).result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((result) => console.log(JSON.stringify(result, null, 2))).catch((error) => {
    const refusal = error instanceof CommandRefused || error instanceof ClockRefused;
    console.error(refusal ? 'Refused: ' + error.message : error.message);
    process.exitCode = refusal ? 2 : 1;
  });
}
