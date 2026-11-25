// A service that is busy, as the wallet tells it (the web audit's W-9; a trial network on 24 November 2026, where a
// proxy refused 9 requests of 1,130 for load and wallets stopped for them).
//
// A 429 (too many requests from this caller) or a 503 (busy) is told by its status alone: the SDK (client-v4/time-sdk.js,
// BUSY) waits and asks again for the requests it makes, and this module does the same, by the same rule, for the
// requests the wallet makes itself to other services (the trust file, the test faucet, the registration service, the
// alert service). A busy answer means the service did not act on the request, so asking again is safe; its body is never
// read. A refusal whose Retry-After is longer than the longest wait (30 seconds) is not "busy for a moment": it is the
// service's answer, and the caller reads it as before (the test faucet's limits of a day).
//
// The words the wallet says of it are here too. Nothing here touches a page or a storage.

/// The header while the wallet waits for a busy network, and before its first answer.
export const BUSY_STATUS = 'The network is busy. Trying again…';
export const BUSY_CONNECTING = 'Connecting… The network is busy. Trying again…';
/// The quiet notice of a wallet that is starting while the network is busy.
export const BUSY_STARTING = 'The network is busy. The wallet keeps asking and is ready as soon as it answers. Nothing needs doing.';
/// An action that could not be done because the network stayed busy, before anything was signed or sent.
export const BUSY_NOTHING = 'The network is busy, so this could not be done now. Nothing was signed or sent. Try again in a moment.';
/// A signed action that could not be sent because the network stayed busy. Its bytes are kept (the pending record).
export const BUSY_KEPT = 'The network is busy, so this signed action was not sent yet. It is kept in this browser, and nothing was signed again. Send the same action in a moment: under Activity, “Retry the exact signed action”.';
/// The same, for a cancellation that keeps a place of its own (a guardian recovery's, signing.mjs): its button sends the
/// kept bytes.
export const BUSY_KEPT_PRESS_AGAIN = 'The network is busy, so this signed cancellation was not sent yet. It is kept in this browser, and nothing was signed again. Press the same button again in a moment: it sends the same action.';
/// An action that protects the account (a freeze, a cancellation, new recovery keys) that could not be sent: urgent.
export const busyProtective = label => `The network is busy, and “${label}” could not be sent yet. It is signed and kept in this browser. Press “Try again” to send the same action now.`;
/// An account that is being opened while the network is busy: the session stays, and the five-second reads open it.
export const BUSY_OPENING = 'The network is busy. Your account opens as soon as it answers: this browser keeps asking. Nothing needs doing.';
/// An account that could not be opened because the network stayed busy before it was read: locked again, nothing lost.
export const BUSY_UNLOCK = 'The network is busy, so your account could not be opened now. Nothing was changed. Open it again in a moment.';
/// A sign-up that could not go on because the network stayed busy: what is kept goes on at the next opening.
export const BUSY_SIGNUP = 'The network is busy, so creating your account could not go on now. Everything is kept in this browser: open your account again in a moment, and it goes on from what the network shows.';
/// The services the wallet asks itself.
export const BUSY_FAUCET = 'The test faucet is busy. Nothing was asked. Try again in a minute.';
/// A request for test time answered busy: it is not sent again by itself, since the faucet may have sent something.
export const BUSY_FAUCET_ASKED = 'The test faucet is busy, and this browser did not ask it again. If it sent test time anyway, your balance shows it in a moment. Otherwise try again in a minute.';
export const BUSY_REGISTRATION = 'The registration service is busy. Nothing more was sent. Open your account again in a moment: the wallet goes on from what the network shows.';
export const BUSY_ALERTS = 'The alert service is busy. Nothing was changed. Try again in a minute.';

/// Whether an error is a busy answer (the SDK's mark: code 'BUSY').
export const isBusyError = error => typeof error === 'object' && error !== null && error.busy === true && error.code === 'BUSY';

/// The longest Retry-After, in seconds, that still counts as busy: a longer one is the service's own refusal.
const longRefusal = (response, rule) => { const seconds = Number(String(response.headers?.get?.('Retry-After') ?? '').trim()); return Number.isFinite(seconds) && seconds * 1000 > rule.maxMs; };

/// Whether a 429 or 503 is a service's own refusal in its own form: JSON whose `error` is an object with a `code`, as the
/// test faucet and registration service answer their limits of a day and their "not giving now" (client-v4/faucet.mjs,
/// ApiError). A refusal for load by the proxy or the gateway in front is plain text, or JSON whose `error` is a sentence.
/// It is asked only of the answer to a request that is not sent again by itself (`ownForm`), because those services are
/// on another origin, and a browser does not let the wallet read their Retry-After (it is not a header a page may read
/// across origins unless the service says so): the long Retry-After that marks their limits of a day cannot be seen
/// there. A copy of the answer is read, to 64 KiB at most; nothing of it is shown.
export async function inOwnForm(response, maxBytes = 65536) {
  try {
    const reader = response.clone().body?.getReader(); if (!reader) return false;
    const parts = []; let size = 0;
    for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > maxBytes) { await reader.cancel().catch(() => {}); return false; } parts.push(value); }
    const bytes = new Uint8Array(size); let at = 0; for (const part of parts) { bytes.set(part, at); at += part.byteLength; }
    const answer = JSON.parse(new TextDecoder().decode(bytes));
    return typeof answer?.error === 'object' && answer.error !== null && typeof answer.error.code === 'string';
  } catch { return false; }
}

/// Sends `send()` (which gives a fetch Response) until its answer is not busy: waits as the SDK's rule says between
/// sends, at most `tries` sends within `budgetMs`. Returns the answer that is not busy (or a long refusal, or with
/// `ownForm` a refusal in the service's own form, which the caller reads as before). When the service stays busy, throws
/// the SDK's busy error. `sdk` is TimeSDK; `timing` is {now, sleep, random}, for tests; `onBusy(error)` is told of each
/// busy answer.
export async function askWhenFree(send, { sdk, budgetMs, tries, timing = {}, onBusy = null, ownForm = false } = {}) {
  const rule = sdk.BUSY, clock = { now: () => Date.now(), sleep: ms => new Promise(resolve => setTimeout(resolve, ms)), random: Math.random, ...timing };
  const until = clock.now() + (budgetMs ?? rule.budgetMs), most = tries ?? rule.tries;
  for (let attempt = 1; ; attempt++) {
    const response = await send(), busy = sdk.busyAnswer(response);
    if (!busy || longRefusal(response, rule) || (ownForm && await inOwnForm(response))) return response;
    try { await response.body?.cancel?.(); } catch { /* nothing to read */ }
    try { onBusy?.(busy); } catch { /* the hook's own trouble */ }
    const delay = sdk.busyDelayMs(busy.retryAfterMs, attempt, clock.random);
    if (attempt >= most || clock.now() + delay > until) throw busy;
    await clock.sleep(delay);
  }
}
