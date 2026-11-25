// The passwords the wallet made (vault.mjs, makePassword: the rule), shown once in a dialog of their own (#made-dialog in
// index.html), before what they seal is kept or sent. The login password stands in that dialog's form under the
// account's name as the user name, so that the browser's password manager may offer to keep it (web audit W-6 keeps the
// login password saveable); the payment password is in no field, only shown, to be written down apart from the recovery
// words. Nothing is asked back.
//
// The step goes on only when the person presses "I have them" ("I have it" for one password): that button closes the
// dialog with the value `done`. Any other way it closes (Escape, a phone's back gesture, the wallet locking, a script)
// ends the step with an error that says nothing was kept, and the caller keeps nothing and sends nothing (review of 24
// November 2026, finding 1). What was shown leaves the page either way.
//
// No network access and no storage here: the page (app.js) makes the dialog once, with its `$`, and hands showMade to
// the modules of its steps; the tests drive the same dialog on their stand-in page.

/// What the person reads when the dialog closed without "I have them": nothing was kept, and the step starts again.
export const NOT_HAD = Object.freeze({
  one: 'Nothing was kept: the password was closed without "I have it". Start again for a new one.',
  two: 'Nothing was kept: the passwords were closed without "I have them". Start again for new ones.',
});
/// The value of the button that goes on (index.html, #made-done).
export const HAD = 'done';

/// The dialog of the page whose elements `$` gives. Returns showMade({ name, login, payment, why, single }): shows the
/// passwords (`login` and `payment`: texts, either may be null), and resolves when "I have them" closed the dialog; it
/// rejects with NOT_HAD (an Error with `notHad`) when it closed any other way. `single`: the one password of an account
/// with one key (it opens the wallet and pays).
export function madeDialog($) {
  const assert = (value, message) => { if (!value) throw new Error(message); };
  // Escape, or a phone's back gesture, asks the dialog to close: it does, as not had.
  $('made-dialog').addEventListener('cancel', () => { if ($('made-dialog').open) $('made-dialog').close(''); });
  return function showMade({ name, login = null, payment = null, why = '', single = false }) {
    assert(!$('made-dialog').open && !$('review-dialog').open, 'Another step is already open.');
    const two = Boolean(login && payment);
    $('made-why').textContent = why;
    $('made-title').textContent = two ? 'Your new passwords' : 'Your new password';
    $('made-name').value = name;
    $('made-login-name').textContent = single ? 'Password' : 'Login password';
    $('made-login-note').textContent = single ? 'Opens this wallet and pays from it. Let your browser save it, or write it down.' : 'Opens this wallet and signs you in to websites. It cannot pay. Let your browser save it, or write it down.';
    $('made-login-part').hidden = !login; $('made-login-shown').textContent = login ?? ''; $('made-login').value = login ?? '';
    $('made-payment-part').hidden = !payment; $('made-payment-shown').textContent = payment ?? '';
    $('made-done').textContent = two ? 'I have them' : 'I have it';
    $('made-dialog').returnValue = ''; $('made-dialog').showModal(); $('made-title').focus?.();
    return new Promise((resolve, reject) => $('made-dialog').addEventListener('close', () => {
      const had = $('made-dialog').returnValue === HAD;
      for (const id of ['made-login-shown', 'made-payment-shown']) $(id).textContent = '';
      $('made-login').value = $('made-name').value = '';
      $('made-dialog').returnValue = '';
      if (had) resolve(); else reject(Object.assign(new Error(two ? NOT_HAD.two : NOT_HAD.one), { notHad: true }));
    }, { once: true }));
  };
}
