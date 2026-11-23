// A validator owner's upgrade signal in the browser wallet: everything that is not the page.
//
// The SDK (`/sdk/time-sdk.js`) reads the status from proven state (`getSignalStatus`), judges a
// signal as the engine would (`judgeSignal`) and builds its bytes. This module turns what the
// owner typed into a plan, says how that plan relates to what validators have signalled, and
// writes every sentence the page shows: the status, the review before signing, each refusal with
// what to do, and the result. It touches no page and no network.
//
// The rule behind every text here: a plan's version, specification hash and start time come from
// the release announcement, typed in by the owner. Nothing fills them in. What validators have
// signalled is proven, but it is not evidence that a plan is the right one: any owner of a
// validator can signal anything. So proven plans are shown for comparison only, with their hash
// in groups, and the form takes a hash only as one run of 64 characters.
//
// Nothing a gateway answers is shown by this tab, in any form: not quoted, not shortened. A
// gateway chooses those words, and a sentence with a hash in it under this form would read as
// the wallet's. What happened to a signal is read from proven state, and said in this module's
// own sentences.

const MAX_U64 = 18446744073709551615n;

// ------------------------------------------------------------------ this wallet's own refusals
// A refusal this wallet states itself (the form is wrong, a rule of the network refuses the
// signal, this key may not sign). Only these are written under the form. The mark is a symbol of
// this module, so an error that came from anywhere else (the SDK with a gateway's words, the
// browser) cannot carry it.
const OWN = Symbol('a refusal of this wallet');
export function refusal(message) { const error = new Error(message); error[OWN] = true; return error; }
export const isOwnRefusal = error => typeof error === 'object' && error !== null && error[OWN] === true;
const fail = message => { throw refusal(message); };
/// In place of a refusal the SDK marks as a gateway's: the gateway's words are not shown here.
export const GATEWAY_REFUSED_TEXT = 'The gateway refused a request of this wallet, so this step was not finished. This tab does not show what a gateway answers. Press "Read again from proven state", then try again.';
/// Under the form, for a failure that is not this wallet's own refusal.
export const NOT_FINISHED_TEXT = 'This step was not finished. The notice at the top of the page says why. Nothing is written here that this wallet did not check itself. Press "Read again from proven state" before you try again.';

// ------------------------------------------------------------------ how values are shown
/// A time of the chain (microseconds since the start of the network) as a date in UTC.
export function utc(genesisMicros, elapsedMicros) {
  const ms = (BigInt(genesisMicros) + BigInt(elapsedMicros)) / 1000n;
  if (ms > 8640000000000000n) return 'a date beyond the calendar';
  return new Date(Number(ms)).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
/// A specification hash in eight groups of eight, for reading and comparing.
export const groupHash = hex => String(hex).match(/.{1,8}/g).join(' ');
/// A share in percent with two decimals, rounded down: 79.999% is shown as 79.99%, never as 80%.
export function share(support, total) {
  const whole = BigInt(total); if (whole === 0n) return '0.00%';
  const hundredths = BigInt(support) * 10000n / whole;
  return `${hundredths / 100n}.${String(hundredths % 100n).padStart(2, '0')}%`;
}
/// A length of time in the largest unit that divides it.
export function duration(micros) {
  const seconds = BigInt(micros) / 1000000n;
  const unit = (count, word) => `${count} ${word}${count === 1n ? '' : 's'}`;
  if (seconds >= 86400n && seconds % 86400n === 0n) return unit(seconds / 86400n, 'day');
  if (seconds >= 3600n && seconds % 3600n === 0n) return unit(seconds / 3600n, 'hour');
  if (seconds >= 60n && seconds % 60n === 0n) return unit(seconds / 60n, 'minute');
  return unit(seconds, 'second');
}
const when = (status, elapsedMicros) => utc(status.genesisTimeMicros, elapsedMicros);
const samePlan = (a, b) => Boolean(a && b) && a.version === b.version && a.spec === b.spec && a.activate_elapsed_micros === b.activate_elapsed_micros;
const planWords = (status, plan) => `version ${plan.version}, start ${when(status, plan.activate_elapsed_micros)}, specification hash ${groupHash(plan.spec)}`;
/// Whether two payloads of a signal are the same signal: two withdrawals ({}), or the same plan.
export const samePayload = (a, b) => Boolean(a && b) && (Object.keys(a).length === 0 || Object.keys(b).length === 0 ? Object.keys(a).length === Object.keys(b).length : samePlan(a, b));

// ------------------------------------------------------------------ what the owner typed
/// The three values of a plan as the owner typed them, checked for form only. Surrounding space
/// is dropped and a hash in capital letters is taken as the same hash; nothing else is repaired.
/// What it throws is this wallet's own refusal.
export function parsePlanInput({ version, spec, start }) {
  const text = value => (typeof value === 'string' ? value.trim() : '');
  const number = (value, what) => {
    const typed = text(value);
    if (!/^[1-9][0-9]{0,19}$/.test(typed) || BigInt(typed) > MAX_U64) fail(what);
    return typed;
  };
  const versionText = number(version, 'Enter the version as the release announcement gives it: a whole number, for example 5.');
  const hash = text(spec);
  if (!hash) fail('Enter the specification hash from the release announcement.');
  if (/\s/.test(hash)) fail('Enter the specification hash as the release announcement gives it: one run of 64 characters, with no spaces. Do not copy it from this page.');
  if (!/^[0-9a-fA-F]*$/.test(hash)) fail('A specification hash has only the characters 0 to 9 and a to f. Check it against the release announcement.');
  if (hash.length !== 64) fail(`A specification hash has 64 characters. You entered ${hash.length}. Check it against the release announcement.`);
  const startText = number(start, 'Enter the start time as the release announcement gives it: a number of microseconds of network time, digits only.');
  return { version: versionText, spec: hash.toLowerCase(), activateElapsedMicros: startText };
}

// ------------------------------------------------------------------ the plan against what is proven
/// How a plan the owner entered relates to the plans in proven state.
/// - `kind`: 'scheduled' (it is the scheduled plan), 'signalled' (validators of the current sets
///   support exactly it) or 'new' (none does).
/// - `plan`: the proven plan it equals, with its tally, or null.
/// - `near`: the proven plans that have the version and the start time of the entry and another
///   specification hash: a mistyped hash, or two different sets of rules under one number. Only
///   these are called similar. A plan with another start or another version is another plan:
///   whoever signals could otherwise put a warning, with a hash of their choice, into the review
///   of every owner.
export function planMatch(status, plan) {
  const entered = { version: plan.version, spec: plan.spec, activate_elapsed_micros: plan.activateElapsedMicros ?? plan.activate_elapsed_micros };
  const equal = status.plans.find(known => samePlan(known, entered)) || null;
  const near = status.plans.filter(known => known.version === entered.version && known.activate_elapsed_micros === entered.activate_elapsed_micros && known.spec !== entered.spec).map(known => ({ plan: known, differs: ['specification hash'] }));
  return { kind: equal ? (equal.scheduled ? 'scheduled' : 'signalled') : 'new', plan: equal, near, entered };
}
/// Said with every share this wallet could not check. A tally that is not exact (`tally.exact` is
/// false) is a count the network may not share, in either direction.
const UNCHECKED = 'not checked: this wallet could not read whether each of these signals counts, or which validators are jailed, so the share the network counts can be lower or higher';
/// How many validators support a plan and with what share, with the caveat when it was not checked.
const tallyWords = plan => `${plan.supporters.length} validator${plan.supporters.length === 1 ? '' : 's'} with ${share(plan.tally.lowest.support, plan.tally.lowest.total)} of the votes${plan.tally.exact ? '' : ` (${UNCHECKED})`}`;
/// One sentence on what the entry is, for the line under the form and for the review.
export function matchText(status, match) {
  if (match.kind === 'scheduled') return `This is the scheduled plan. ${tallyWords(match.plan)} support it.`;
  if (match.kind === 'signalled') return `${tallyWords(match.plan)} support exactly this plan. It is scheduled at four fifths (80%).`;
  return 'No validator of the current validator sets has signalled exactly this plan.';
}
/// A warning for each proven plan that is close to the entry and is not it. Empty when there is none.
export function nearTexts(status, match) {
  return match.near.map(({ plan, differs }) => {
    const who = plan.scheduled ? `The scheduled plan (${tallyWords(plan)})` : `A plan that ${tallyWords(plan)} support`;
    return `${who} differs from what you entered in the ${differs.join(' and the ')}: it is ${planWords(status, plan)}. If you meant that plan, cancel, and compare what you entered with the release announcement. If the announcement gives what you entered, go on: your signal then counts for your plan only.`;
  });
}

// ------------------------------------------------------------------ the status, as lines
const inForce = status => status.rosters[0];
function ownSignalText(status, own) {
  if (!own.entry) return 'Your validator has not signalled.';
  if (own.entry.withdrawn) return `Your validator supports no plan. It withdrew on ${when(status, own.entry.changed_elapsed_micros)}.`;
  return `Your validator supports ${planWords(status, own.supports)}. It signalled this on ${when(status, own.entry.changed_elapsed_micros)}.`;
}
/// The end of a freeze in words. It is a moment on the clock of the waits (security-flows.mjs, waitsOf): on a network
/// whose waits survive a stop of the chain, the total of the stops is added to make it a date, and the date is only the
/// earliest, said "not before". The status the SDK reads carries both, of the state the status was read from
/// (`status.waits`, TimeSDK.signalStatusOf).
function freezeEnd(status, moment) {
  if (status.waits?.rule !== true) return ` until ${when(status, moment)}`;
  return `; the freeze ends not before ${when(status, (BigInt(moment) + BigInt(status.waits.stoppedMicros)).toString())}`;
}
/// Why the account's signal does not count now, and what to do, or null.
export function stoppedText(status, own) {
  if (own.stopped === 'frozen') return `This account is frozen${own.frozenUntilElapsedMicros ? freezeEnd(status, own.frozenUntilElapsedMicros) : ' while a change of its keys waits'}. Until the freeze ends its signal does not count, and it can neither signal nor withdraw. If you did not freeze it, see Keys.`;
  if (own.stopped === 'recovery') return 'A recovery of this account through its guardians has its approvals. Until it is cancelled or finished the account signs nothing, and its signal does not count. If you did not start it, cancel it under More, Guardian recovery.';
  return null;
}
/// The lines of one plan in the list. A tally that is not exact states no threshold as reached or
/// missed: only what proven state itself says (scheduled or not), the rule, and that the count
/// was not checked.
function planLines(status, plan) {
  const low = plan.tally.lowest, lines = [`Supported by ${plan.supporters.length} of ${status.validators.length} validators: ${low.support} of ${low.total} votes (${share(low.support, low.total)})${status.rosters.length > 1 ? ', in the validator set where its share is lowest' : ''}.`];
  if (!plan.tally.exact) {
    lines.push(plan.scheduled ? 'Scheduled. It stays scheduled while it keeps three quarters (75%) of the votes the network counts. This wallet could not check that count.' : 'Not scheduled. A plan is scheduled at four fifths (80%) of the votes the network counts. This wallet could not check that count.');
    lines.push('For some of these validators this wallet could not read whether the owner account is frozen or in a recovery, or which validators are jailed. A signal of a frozen or recovering owner does not count, and a jailed validator is left out of the count. So the share the network counts can be lower or higher than shown.');
    return lines;
  }
  lines.push(plan.scheduled ? (plan.tally.keep ? 'Scheduled. It keeps the three quarters (75%) it needs.' : 'Scheduled, but below the three quarters (75%) it needs: the next block cancels it unless support returns.')
    : plan.tally.schedule ? `It has the four fifths (80%) that schedule a plan${status.hold ? '; nothing is scheduled during the hold' : ''}.` : 'Not scheduled. It needs four fifths (80%) of the votes.');
  return lines;
}
/// Everything the page shows of the status: {summary, own, plans, validators, note}.
export function statusLines(status) {
  const own = status.account, roster = inForce(status);
  const summary = [`The network runs version ${status.version} of its rules.`];
  if (status.scheduled) summary.push(`Version ${status.scheduled.version} is scheduled. It starts on ${when(status, status.scheduled.activate_elapsed_micros)} at the earliest, if it keeps three quarters (75%) of the votes in every block until then.${status.known ? '' : ' This app does not know that version: update it before then.'}`);
  else summary.push('No change of the rules is scheduled.');
  if (status.hold) summary.push('A validator safety hold is on: a validator is jailed or the validator set is too small. Nothing is scheduled and nothing starts while it lasts. Signals are still taken.');
  const ownLines = [];
  if (own) {
    if (!own.ownsValidator) ownLines.push('This account owns no validator.');
    else {
      ownLines.push(own.inRoster && own.power !== '0' ? `Your validator holds ${own.power} of ${roster.total} votes in the validator set in force (${share(own.power, roster.total)}).` : own.inRoster ? 'Your validator is in an announced validator set and not yet in the one in force. Its signal counts once it is.' : 'Your validator is in no validator set now. It may signal; its signal counts once it is in a set.');
      ownLines.push(ownSignalText(status, own));
      if (own.jailed) ownLines.push('Your validator is jailed. It is left out of the count, and it leaves the validator set two blocks after it was jailed.');
      const stopped = stoppedText(status, own); if (stopped) ownLines.push(stopped);
      if (own.entry && !own.mayChangeNow) ownLines.push(`The network takes one change of a validator's signal every ${duration(status.rules.intervalMicros)}. You can change yours again after ${when(status, own.mayChangeFromElapsedMicros)}.`);
    }
  }
  const plans = status.plans.map(plan => ({ title: `Version ${plan.version}, start ${when(status, plan.activate_elapsed_micros)}`, hash: groupHash(plan.spec), lines: planLines(status, plan) }));
  // A validator's plan is named with its whole hash, in groups: two hashes that begin and end
  // alike are two plans, and a shortened hash would give them one line.
  const validators = status.validators.map(item => {
    const signal = !item.signal ? 'no signal' : item.signal.withdrawn ? 'withdrew' : `supports version ${item.signal.version}, start ${when(status, item.signal.activate_elapsed_micros)}, hash ${groupHash(item.signal.spec)}`;
    const mark = item.jailed === true ? ' · jailed, left out of the count' : item.stopped === 'frozen' ? ' · owner account frozen, does not count' : item.stopped === 'recovery' ? ' · owner account in a recovery, does not count' : item.signal && !item.signal.withdrawn && item.counts === null ? ' · not read whether it counts' : '';
    return { title: `Validator of account ${item.owner}${own && item.owner === own.id ? ' (yours)' : ''}`, detail: `${item.inForce ? `${item.power} votes` : 'not in the validator set in force'} · ${signal}${mark}` };
  });
  const heights = status.heights && status.heights.first !== status.heights.last ? `blocks ${status.heights.first} to ${status.heights.last}` : `block ${status.height}`;
  const note = `Read from proven state of ${heights}, dated ${when(status, status.nowElapsedMicros)}. The validator sets and the signals are those of block ${status.height}.${status.complete === false ? ' Not every owner account could be read: see the note at each plan.' : ''}`;
  return { summary, own: ownLines, plans, validators, note };
}

// ------------------------------------------------------------------ refusals, each with what to do
/// The text for a refusal of `judgeSignal` (`judged.ok` is false). `intent` is the parsed plan, or
/// {withdraw: true}.
export function refusalText(status, judged, intent, { fee } = {}) {
  const own = status.account, plan = intent.withdraw ? null : intent;
  switch (judged.refusal) {
    case 'not_owner': return 'This account owns no validator, or its validator was retired. Only the owner account of a validator can signal.';
    case 'recovery': case 'frozen': return stoppedText(status, { ...own, stopped: judged.refusal });
    case 'fee': return `A signal costs the network fee${fee ? ` of ${fee} seconds` : ''}, and this account holds less. Add seconds to the account first.`;
    case 'version': return `The network runs version ${judged.current}. A plan can only name the next one, version ${judged.next}, and you entered ${plan.version}. Check the version in the release announcement.`;
    case 'start_too_soon': return `The start you entered is ${when(status, plan.activateElapsedMicros)}. A new plan must start at least ${duration(status.rules.noticeMicros)} after the block that takes the signal: as of now, not before ${when(status, judged.earliestElapsedMicros)}. Check the start time in the release announcement. If the announcement gives this start, it is too late to signal this plan: ask the people who published the release for a new start time. Do not pick a start time yourself: validators count together only if they signal exactly the same plan.`;
    case 'start_too_far': return `The start you entered is ${when(status, plan.activateElapsedMicros)}. A plan may start at most ${duration(status.rules.farthestMicros)} ahead: as of now, not after ${when(status, judged.latestElapsedMicros)}. Check the start time in the release announcement. If it is right, signal on or after ${when(status, (BigInt(plan.activateElapsedMicros) - BigInt(status.rules.farthestMicros)).toString())}.`;
    case 'no_change': return plan ? 'Your validator already supports exactly this plan. Nothing was sent.' : 'Your validator supports no plan, so there is nothing to withdraw. Nothing was sent.';
    case 'interval': return `Your validator's signal changed on ${when(status, own.entry.changed_elapsed_micros)}. The network takes one change every ${duration(status.rules.intervalMicros)}. Try again after ${when(status, judged.fromElapsedMicros)}.`;
    case 'table_full': return 'The network holds as many signals as it can (256). A validator that has no entry yet cannot signal until one is dropped. Try again later.';
    default: return 'This signal would be refused. Read the status again.';
  }
}
/// A signed signal stays valid until another action of the account is IN A BLOCK (the engine
/// takes an action whose number is the account's next one: v5/src/engine.rs). Signing another
/// action does not end it: whoever has the bytes of both can have either one included.
const KEPT = ' The signed signal is kept as pending (see below, and Activity). It stays valid until another action of this account is in a block.';
/// After a request to the gateway was refused, a status was read with a proof afterwards, the
/// signal is in no block and proven state shows no rule against it. The one reason this wallet
/// cannot see is the node's own policy. What the gateway answered is not shown.
export function notTakenText(intent) {
  if (intent.withdraw) return `The node this wallet reached did not take the withdrawal, and proven state shows no rule against it. Read the status again and try once more in a minute.${KEPT}`;
  return `The node this wallet reached did not take the signal, and proven state shows no rule against it. The usual reason is the node's own policy: a node takes a signal of support only if the program it runs implements version ${intent.version} with exactly this specification hash. Check two things. First the hash: compare what you entered with the release announcement once more. Then the node: this wallet's gateway must stand in front of a node that runs the release. Your own validator's node does, once you have installed the release.${KEPT}`;
}
/// After a signal was signed and no status could be read with a proof afterwards: this wallet
/// knows neither whether the signal left it nor what proven state shows.
export const NOT_READ_TEXT = 'The signal was signed, and this wallet could not read proven state afterwards. It does not know whether the signal reached the network. The signed signal is kept as pending (see below, and Activity). Press "Read again from proven state" in a moment: your validator\'s signal above then shows what happened. Do not sign it again.';
export const NO_RECEIPT_TEXT = 'The signal was signed, and this wallet has no verified receipt for it yet. It is kept as pending (see below, and Activity). Read the status again in a moment: once a block holds it, your validator\'s signal above shows it. Do not sign it again.';

// ------------------------------------------------------------------ the review before signing
/// The fields of the review dialog for a signal of support.
export function supportReview({ status, judged, match, secured, fee }) {
  const own = status.account, plan = judged.plan, roster = inForce(status), start = BigInt(plan.activate_elapsed_micros), now = BigInt(status.nowElapsedMicros);
  const days = start > now ? (start - now) / 86400000000n : 0n;
  const fields = [
    ['You support', `Version ${plan.version} of the network's rules, in place of version ${status.version}.`],
    ['Which rules', `The rules whose specification has this hash: ${groupHash(plan.spec)}. The hash decides what the network will run. Compare all eight groups with the release announcement.`],
    ['Start', `${when(status, plan.activate_elapsed_micros)} at the earliest${days > 0n ? ` (about ${days} day${days === 1n ? '' : 's'} from now)` : ''}. Entered as ${plan.activate_elapsed_micros} microseconds of network time. Compare the date with the release announcement.`],
    ['At the start', `Every program that does not implement version ${plan.version} with exactly these rules stops: validators, gateways, wallets and shops that were not updated. The network goes on only if validators with more than two thirds of the votes run the release.`],
    ['Your validator', `Your own node must run a release that implements version ${plan.version} with this hash before the start. If it does not, it stops there and signs nothing. You ticked that you checked this.`],
    ['Your votes', own.inRoster && own.power !== '0' ? `${own.power} of ${roster.total} in the validator set in force (${share(own.power, roster.total)}).` : 'Your validator is not in the validator set in force. The signal is recorded and counts once it is.'],
    ['This plan now', matchText(status, match)],
  ];
  for (const text of nearTexts(status, match)) fields.push(['Warning: a similar plan', text]);
  if (status.scheduled && match.kind !== 'scheduled') fields.push(['Warning: another plan is scheduled', `The scheduled plan is ${planWords(status, status.scheduled)}. A validator supports one plan at a time${samePlan(own.supports, status.scheduled) ? ', and yours supports the scheduled one now: this signal takes that support away' : ''}. A scheduled plan that falls under three quarters of the votes is cancelled.`]);
  if (own.supports && !samePlan(own.supports, plan)) fields.push(['Replaces', `Your validator's signal for ${planWords(status, own.supports)}.`]);
  if (judged.tight) fields.push(['Timing', `This start is close to the earliest a new plan may name. If the signal is not in a block within a few minutes, the network refuses it.`]);
  if (status.hold) fields.push(['Safety hold', 'A validator safety hold is on. The signal is taken, but nothing is scheduled while the hold lasts.']);
  fields.push(['Changing it', `After this you can change the signal again only after ${duration(status.rules.intervalMicros)}. You can withdraw it then.`]);
  fields.push(['Signed by', secured ? 'Your payment key, with your payment password. The login key and the recovery keys cannot signal.' : 'This browser\'s key.']);
  fields.push(['Fee', `${fee} seconds`]);
  return fields;
}
/// What the owner ticks in the review before the button that signs can be pressed.
export const SUPPORT_ACKNOWLEDGE = 'I compared the version, all eight groups of the hash and the start date with the release announcement.';
export const WITHDRAW_ACKNOWLEDGE = 'I read this, and I want to withdraw my validator\'s support.';
export const DISCARD_ACKNOWLEDGE = 'I read what discarding does and what it does not do.';
/// The fields of the review dialog for a withdrawal.
export function withdrawReview({ status, secured, fee }) {
  const own = status.account, scheduled = samePlan(own.supports, status.scheduled), plan = status.plans.find(known => samePlan(known, own.supports));
  return [
    ['You withdraw', `Your validator's support for ${planWords(status, own.supports)}.`],
    ['Effect', `Your validator's votes no longer count for that plan${plan ? `, which ${tallyWords(plan)} support now` : ''}.${scheduled ? ' That plan is scheduled: if it falls under three quarters (75%) of the votes, the next block cancels it, and scheduling it again takes four fifths and a new notice.' : ''}`],
    ['Changing it', `After this you can signal again only after ${duration(status.rules.intervalMicros)}.`],
    ['Signed by', secured ? 'Your payment key, with your payment password.' : 'This browser\'s key.'],
    ['Fee', `${fee} seconds`],
  ];
}

// ------------------------------------------------------------------ the result, from proven state
/// What a plan's support is now, after a signal for it was included.
const supportNow = plan => (plan.scheduled ? `That plan is scheduled: ${tallyWords(plan)} support it.` : `${tallyWords(plan)} support that plan now. It is scheduled at four fifths (80%).`);
const showsWords = (status, own) => (!own.entry ? 'no signal of your validator' : own.entry.withdrawn ? 'that your validator supports no plan' : `your validator supporting ${planWords(status, own.supports)}`);
/// What to say after a verified receipt, from a status read after it. `intent` is the plan that
/// was signed ({version, spec, activate_elapsed_micros}) or {withdraw: true}; `receipt` gives the
/// block. Returns {ok, lines}: `ok` is false when proven state does not show what was signed.
export function resultLines({ status, intent, receipt }) {
  const own = status.account, block = `block ${receipt.height}`;
  const lines = [];
  if (intent.withdraw) {
    if (own.supports) return { ok: false, lines: [`The withdrawal is in ${block}, but proven state of block ${status.height} shows your validator supporting ${planWords(status, own.supports)}. Read the status again. If it still shows that and you sent no other signal, someone else holds a key of this account that may spend: freeze the account under Keys.`] };
    lines.push(`Done. The withdrawal is in ${block}, and proven state of block ${status.height} shows that your validator supports no plan.`);
  } else if (samePlan(own.supports, intent)) {
    const plan = status.plans.find(known => samePlan(known, intent));
    lines.push(`Done. The signal is in ${block}, and proven state of block ${status.height} shows that your validator supports ${planWords(status, intent)}.`);
    if (plan) lines.push(supportNow(plan));
    else lines.push('Your validator is in no validator set now, so the signal counts for nothing yet.');
    const stopped = stoppedText(status, own); if (stopped) lines.push(stopped);
    if (own.jailed) lines.push('Your validator is jailed, so it is left out of the count.');
    lines.push(`Before the start, make sure your validator's node runs a release that implements version ${intent.version} with this hash.`);
  } else {
    return { ok: false, lines: [`The signal is in ${block}, but proven state of block ${status.height} shows ${showsWords(status, own)}. The network drops a signal whose start has come closer than the notice, whose version is no longer the next one, or whose validator was retired; a later signal of this account replaces it. Read the status again before you do anything else.`] };
  }
  return { ok: true, lines };
}
/// A signed signal for which this wallet verified no receipt, while proven state shows that an
/// action of the account is in a block in its place (its action number is used). Proven state
/// says whether that action was this signal. `intent` as for resultLines. `discarded` lists the
/// signed signals the owner discarded in this wallet ({payload, nonce}): if proven state shows one
/// of them, that one took the place.
export function withoutReceiptLines({ status, intent, discarded = [] }) {
  const own = status.account, check = 'This wallet has no verified receipt for it: under Activity, press "Check pending receipt".';
  if (intent.withdraw ? own.supports === null && Boolean(own.entry?.withdrawn) : samePlan(own.supports, intent)) {
    const plan = intent.withdraw ? null : status.plans.find(known => samePlan(known, intent));
    const lines = [`The signal was included. Proven state of block ${status.height} shows that your validator supports ${intent.withdraw ? 'no plan' : planWords(status, intent)}. ${check}`];
    if (plan) lines.push(supportNow(plan));
    return { ok: true, lines };
  }
  const clear = 'The signal you signed last can no longer be included. Under Activity, press "Check pending receipt" to clear it, then read the status again.';
  if (discardedShown(status, discarded)) return { ok: false, lines: [`The signed signal you discarded took the place of the one you signed last: whoever had its bytes had it put in a block. ${changeLines(status, 'discarded').join(' ')} ${clear}`] };
  return { ok: false, lines: [`Another action of this account is in a block in the place of this signal, and proven state of block ${status.height} shows ${showsWords(status, own)}. ${clear}`] };
}

// ------------------------------------------------------------------ a signed signal that waits, and discarding it
/// What a signed signal that is kept as pending says, from its own bytes (decoded by the SDK).
/// `canCancel`: this browser's key may sign "Cancel pending action" (Activity tab), which puts
/// another action of the account in a block and so ends the signed signal for certain.
export function pendingText(status, action, { canCancel = false } = {}) {
  const what = Object.keys(action.payload).length === 0 ? 'a withdrawal of your validator\'s support' : `support for ${planWords(status, action.payload)}`;
  return `This wallet holds a signed signal that it has not seen in a block: ${what}. It stays valid until another action of this account is in a block: until then, whoever has its bytes can have it included. To send the same signal again, use "Retry the exact signed action" under Activity.${canCancel ? ' To end it for certain, use "Cancel pending action" there.' : ''}`;
}
/// The fields of the review before a signed signal is discarded.
export function discardReview({ canCancel = false } = {}) {
  return [
    ['What discarding does', 'This wallet forgets the signed signal, so that you can sign something else.'],
    ['What it does not do', 'It does not make the signed signal invalid. The gateway received its bytes. Until another action of this account is in a block, whoever has the bytes can have this signal included, also in place of the next action you sign.'],
    ['To end it for certain', canCancel ? 'Do not discard it. Close this review and use "Cancel pending action" under Activity. That puts another action of this account in a block, and after that the signed signal can never be included.' : 'This browser\'s key cannot cancel a pending action. The signed signal ends only when another action of this account is in a block.'],
    ['Afterwards', 'This wallet remembers the discarded signal. If it is included after all, this page says so, and what to do then.'],
  ];
}
export const DISCARDED_NOTICE = 'The signed signal was discarded. It stays valid until another action of this account is in a block. This page tells you if it is included after all.';
export const ALREADY_PLACED_TEXT = 'Another action of this account is already in a block in this signal\'s place. Use "Check pending receipt" under Activity, to see which one was included.';

// ------------------------------------------------------------------ a change of the signal this wallet did not make
// What this wallet remembers of one account's signal between readings of proven state:
//   {seen: true, entry, nonce, expected: [payload], discarded: [{hash, nonce, payload}], alert}
// - `entry`: the account's entry as last read (`entryMark`), `nonce`: its action number then;
// - `expected`: the payloads of signals signed in this wallet whose effect was not yet read;
// - `discarded`: signed signals the owner discarded here, until their action number is used;
// - `alert`: {kind, entry} while proven state shows an entry this wallet did not make.
// Every reading is compared with it (`compareEntry`). An entry can only be created or changed by
// a signed action of the account, so a change this wallet did not sign means: another device of
// the owner, or someone else with a key of the account that may spend.
const payloadOfEntry = own => (!own.entry ? null : own.entry.withdrawn ? {} : { activate_elapsed_micros: own.supports.activate_elapsed_micros, spec: own.supports.spec, version: own.supports.version });
/// The account's entry as one string: what it names and when it last changed.
export const entryMark = own => (!own.entry ? 'none' : `${own.entry.withdrawn ? 'withdrawn' : `${own.supports.version}:${own.supports.spec}:${own.supports.activate_elapsed_micros}`}@${own.entry.changed_elapsed_micros}`);
const discardedShown = (status, discarded) => { const now = payloadOfEntry(status.account); return Boolean(now) && discarded.some(item => samePayload(item.payload, now) && BigInt(status.account.nonce) >= BigInt(item.nonce)); };
const cleanMemory = memory => (memory && memory.seen === true && typeof memory.entry === 'string' && Array.isArray(memory.expected) && Array.isArray(memory.discarded) ? memory : null);
/// Compares a status read with a proof with what this wallet remembers. Returns the memory to
/// keep and `change`: null (nothing changed, or this wallet made the change), 'foreign' (the
/// entry changed and this wallet did not sign that), 'discarded' (the entry is a signal the
/// owner discarded here) or 'dropped' (the entry is gone: the network dropped it; no action
/// removes an entry). `pending` is the payload of a signed signal this wallet still holds.
/// The first reading of an account is taken as it is: there is nothing to compare it with.
export function compareEntry(memory, status, { pending = null } = {}) {
  const own = status.account, mark = entryMark(own), now = payloadOfEntry(own), known = cleanMemory(memory);
  let expected = known ? known.expected : [], discarded = known ? known.discarded : (Array.isArray(memory?.discarded) ? memory.discarded : []), alert = known ? known.alert ?? null : null, change = null;
  if (known && known.entry !== mark) {
    alert = null;
    if (!now) change = 'dropped';
    else {
      const at = expected.findIndex(payload => samePayload(payload, now));
      if (at >= 0) expected = expected.filter((_, index) => index !== at);
      else if (!samePayload(pending, now)) change = discardedShown(status, discarded) ? 'discarded' : 'foreign';
      if (change) alert = { kind: change, entry: mark };
    }
  }
  // A discarded signal whose action number is used can never be included: nothing to remember.
  discarded = discarded.filter(item => BigInt(item.nonce) > BigInt(own.nonce));
  return { memory: { seen: true, entry: mark, nonce: own.nonce, expected: expected.slice(-8), discarded: discarded.slice(-8), alert }, change };
}
/// The memory after this wallet signed a signal with this payload.
export const expectSignal = (memory, payload) => ({ ...(memory || {}), expected: [...(Array.isArray(memory?.expected) ? memory.expected : []), payload].slice(-8), discarded: Array.isArray(memory?.discarded) ? memory.discarded : [] });
/// The memory after an attempt in which nothing was signed: the expectation is taken back.
export function unexpectSignal(memory, payload) {
  const expected = Array.isArray(memory?.expected) ? [...memory.expected] : [], at = expected.findIndex(known => samePayload(known, payload));
  if (at < 0) return memory;
  expected.splice(at, 1); return { ...memory, expected };
}
/// The memory after the owner discarded a signed signal ({hash, nonce, payload}) in this wallet.
export function forgetSignal(memory, item) {
  const expected = Array.isArray(memory?.expected) ? [...memory.expected] : [], at = expected.findIndex(payload => samePayload(payload, item.payload));
  if (at >= 0) expected.splice(at, 1);
  return { ...(memory || {}), expected, discarded: [...(Array.isArray(memory?.discarded) ? memory.discarded : []), { hash: item.hash, nonce: item.nonce, payload: item.payload }].slice(-8) };
}
/// What the page says while proven state shows an entry this wallet did not make. `kind` is
/// 'foreign' or 'discarded'. Each case ends with what to do.
export function changeLines(status, kind) {
  const own = status.account, at = when(status, own.entry.changed_elapsed_micros);
  const shows = own.entry.withdrawn ? 'supports no plan: its support was withdrawn' : `supports ${planWords(status, own.supports)}`;
  const next = own.mayChangeNow ? 'now' : `after ${when(status, own.mayChangeFromElapsedMicros)}`;
  const undo = own.entry.withdrawn ? `If your validator should support a plan, signal it again on this page: the network takes the next change of your signal ${next}.` : `If your validator should not support that plan, press "Withdraw support" on this page: the network takes the next change of your signal ${next}.`;
  if (kind === 'discarded') return [`The signed signal you discarded was included after all, on ${at}: whoever had its bytes had it put in a block. Your validator now ${shows}.`, undo];
  return [`Warning: your validator's signal changed on ${at}, and this wallet did not send that change. Your validator now ${shows}.`,
    'If you sent it from another device or another wallet, nothing is wrong.',
    own.secured ? 'If you did not, someone else holds your payment key. On Home, freeze the account now (the switch "Freeze" under Protection), then make a new payment password under Keys ("Change something", "New payment password"). A frozen account can neither signal nor withdraw: do the next step once the freeze has ended.' : 'If you did not, someone else holds a key of this account that may spend. Under More, Devices, remove every key you do not know, now.',
    undo];
}
/// Said once when the account's entry is gone from proven state.
export const DROPPED_TEXT = 'Your validator\'s signal is no longer in proven state. No action of an account removes a signal: the network drops one whose start has come closer than the notice, whose version is no longer the next one, or whose validator was retired.';
