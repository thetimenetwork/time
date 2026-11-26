import { loadIdentity, safetyNumber, pinPeer, isPeerPinned, roomId, encryptEvent, decryptEvent } from './crypto.mjs';
import { materializeThread } from './thread.mjs';

const $ = id => document.getElementById(id);
const by = (tag, className, text) => {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
};
const button = (label, className, action) => {
  const el = by('button', className, label);
  el.type = 'button';
  el.addEventListener('click', action);
  return el;
};
const field = (label, placeholder = '') => {
  const el = by('label', 'field', label);
  const input = by('input');
  input.placeholder = placeholder;
  input.autocomplete = 'off';
  input.spellcheck = false;
  input.setAttribute('autocorrect', 'off');
  input.translate = false;
  el.append(input);
  return { el, input };
};
const append = (...nodes) => $('dialog-body').append(...nodes);
const canonicalKey = key => String(key || '').replace(/\r\n/g, '\n').trim() + '\n';
const labelFor = user => user.name ? '@' + user.name.replace(/^@/, '') : 'Account ' + user.id;
const initials = str => (Array.from(str.replace(/^@/, '').trim())[0] || '?').toLocaleUpperCase();
const utf8 = new TextEncoder();
const toHex = bytes => Array.from(new Uint8Array(bytes), x => x.toString(16).padStart(2, '0')).join('');
const keyNonce = async (salt, key) => toHex(await crypto.subtle.digest('SHA-256', utf8.encode(JSON.stringify(['time-chat-key/v1', salt, canonicalKey(key)]))));
let config, user, identity, csrf, stream, chats = [], active, dialogSerial = 0, signing = false;
let refreshBusy = false, refreshAgain = false, refreshed = false;
let sessionReady = false, notificationsEnabled = false, sseTimer, fallbackTimer;
const sessionChanges = globalThis.BroadcastChannel ? new BroadcastChannel('time-chat-session-v1') : null;
if (sessionChanges) sessionChanges.onmessage = ({ data }) => {
  if (data === 'logout') endSession('Signed out in another tab.');
};
window.addEventListener('pageshow', e => { if (e.persisted) location.reload(); });

async function api(path, payload) {
  const options = { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } };
  if (payload !== undefined) {
    options.method = 'POST';
    options.headers['Content-Type'] = 'application/json';
    if (csrf) options.headers['X-CSRF-Token'] = csrf;
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && sessionReady) endSession('Your session ended. Sign in again.');
    const reason = typeof data.error === 'string' ? data.error.slice(0, 180) : 'Request failed (' + response.status + ').';
    throw new Error(reason);
  }
  return data;
}
function showDialog(title) {
  ++dialogSerial;
  $('dialog-title').textContent = title;
  $('dialog-body').replaceChildren();
  $('dialog-status').textContent = '';
  if (!$('dialog').open) $('dialog').showModal();
  return dialogSerial;
}
function closeDialog() { if ($('dialog').open) { ++dialogSerial; $('dialog').close(); } }
$('dialog-close').onclick = closeDialog;
$('dialog').addEventListener('close', () => {
  // A native close event may arrive after a different dialog view has opened.
  if (!$('dialog').open) { ++dialogSerial; $('dialog-body').replaceChildren(); }
});
const report = (id, error) => { $(id).textContent = error instanceof Error ? error.message : error; };
function privacy() {
  showDialog('Conversation privacy');
  append(by('p', '', 'Your device encrypts each message for the people in the chat and signs it. Their devices check the signature before displaying the text.'),
    by('p', '', 'Compare a contact’s safety code in person or through another trusted channel. A matching code ties the conversation to the keys on both devices.'),
    by('p', '', 'The service can see account IDs, chat membership, delivery times and the size of encrypted messages. Notifications carry no message text.'),
    by('p', '', 'A stolen chat key can decrypt saved traffic for that device, including past messages.'),
    by('p', '', 'Your device keyboard and browser extensions can see what you type.'),
    by('p', '', 'Participants can copy messages. Someone who controls your device or the code running on it can read them. Losing this browser’s keys also loses access to your messages.'));
}
for (const el of document.querySelectorAll('[data-privacy]')) el.onclick = privacy;

function endSession(message = '') {
  sessionReady = false;
  stream?.close();
  clearTimeout(sseTimer);
  clearInterval(fallbackTimer);
  closeDialog();
  stream = null; user = null; identity = null; csrf = null; active = null; chats = []; refreshed = false;
  clearMessageSearch(); clearMode(false);
  $('messages').replaceChildren(); $('chats').replaceChildren(); $('draft').value = ''; $('filter').value = '';
  $('room-title').textContent = ''; $('room-detail').textContent = ''; $('user-name').textContent = ''; $('user-avatar').textContent = '';
  $('workspace').classList.remove('room-open'); $('workspace').hidden = true; $('conversation').hidden = true;
  $('empty-room').hidden = false; $('welcome').hidden = false; $('signin-status').textContent = message;
  $('switch-account').hidden = true;
  setSignButton('Sign in with Time');
}
function setSignButton(label) {
  const sign = $('signin');
  $('signin-label').textContent = label;
  sign.disabled = !config || signing;
}
async function signIn() {
  if (!config || signing) return;
  const binding = Boolean(user && !user.publicKey && identity);
  signing = true;
  setSignButton(binding ? 'Link this device' : 'Sign in with Time');
  $('signin-status').textContent = 'Approve the request in your Time wallet.';
  try {
    // Opening the popup during the click is required on mobile browsers.
    const request = api('/api/login/challenge', binding ? { publicKey: identity.publicKey } : {}).then(async result => {
      const c = result.challenge;
      if (!c || c.origin !== location.origin || c.networkId !== config.networkId || c.purpose !== 'login') throw new Error('Wallet challenge belongs to a different app or network.');
      if (binding && c.nonce !== await keyNonce(result.salt, identity.publicKey)) throw new Error('The wallet challenge does not match this device’s chat key.');
      return { type: 'login', challenge: c };
    });
    const proof = await globalThis.TimeSDK.requestWallet({ walletOrigin: config.walletOrigin, request });
    await api('/api/login/finish', proof);
    await openSession();
  } catch (e) { report('signin-status', e); }
  finally { signing = false; $('signin').disabled = !config; }
}
$('signin').onclick = signIn;
async function openSession() {
  const me = await api('/api/me');
  if (!me.user) { endSession(); return; }
  user = me.user; csrf = me.csrf;
  identity = await loadIdentity(config.networkId, user.id);
  if (!user.publicKey) {
    setSignButton('Link this device');
    $('switch-account').hidden = false;
    $('signin-status').textContent = 'One more wallet approval links your private chat key to this Time account.';
    return;
  }
  if (canonicalKey(user.publicKey) !== canonicalKey(identity.publicKey)) {
    await api('/api/logout', {});
    endSession('This account is linked to another browser. Open Time Chat on the original device to read your messages.');
    return;
  }
  sessionReady = true;
  $('switch-account').hidden = true;
  $('signin-status').textContent = '';
  $('welcome').hidden = true; $('workspace').hidden = false;
  $('user-name').textContent = labelFor(user); $('user-avatar').textContent = initials(labelFor(user));
  await refresh();
  if (!sessionReady) return;
  stream?.close(); stream = new EventSource('/api/events');
  stream.addEventListener('change', scheduleRefresh);
  stream.addEventListener('open', scheduleRefresh);
  clearInterval(fallbackTimer);
  fallbackTimer = setInterval(() => { if (sessionReady && !document.hidden) scheduleRefresh(); }, 30000);
}
const owner = chat => chat.members.find(member => member.id === user.id);
const others = chat => chat.members.filter(member => member.id !== user.id);
const titleOf = chat => others(chat).map(labelFor).join(', ');
const membershipKey = id => 'time-chat/accepted/v1/' + config.networkId + '/' + user.id + '/' + id;
function memberLabel(chat) { return chat.members.length === 2 ? 'Direct message · #' + others(chat)[0].id : chat.members.length + ' members'; }
function drawRail() {
  const query = $('filter').value.toLocaleLowerCase().trim();
  const list = $('chats'); list.replaceChildren();
  for (const chat of chats) {
    const title = titleOf(chat);
    if (query && !title.toLocaleLowerCase().includes(query)) continue;
    const row = button('', 'chat-row', () => { selectRoom(chat).catch(e => report('room-status', e)); });
    if (active?.chat.id === chat.id) row.setAttribute('aria-current', 'true');
    const text = by('span', 'row-text'); text.append(by('strong', null, title), by('small', '', memberLabel(chat)));
    row.append(by('span', 'avatar', initials(title)), text);
    if (chat.unread > 0) row.append(by('span', 'unread', String(chat.unread)));
    list.append(row);
  }
  if (!list.childElementCount) list.append(by('p', 'list-note', query ? 'No matching conversations.' : refreshed ? 'No conversations yet.' : 'Loading conversations…'));
}
$('filter').addEventListener('input', drawRail);
async function assertRoom(chat) {
  const ids = chat.members.map(member => member.id);
  if (ids.length < 2 || ids.length > 16 || ids.length !== new Set(ids).size || !owner(chat) || canonicalKey(owner(chat).publicKey) !== canonicalKey(identity.publicKey) ||
      await roomId(config.networkId, ids) !== chat.id) throw new Error('Could not verify this conversation’s membership.');
}
function scheduleRefresh() { clearTimeout(sseTimer); sseTimer = setTimeout(refresh, 90); }
async function refresh() {
  if (!sessionReady) return;
  if (refreshBusy) { refreshAgain = true; return; }
  refreshBusy = true;
  try {
    const session = identity;
    const result = await api('/api/chats');
    if (session !== identity) return;
    chats = result.chats; refreshed = true; drawRail();
    const view = active;
    if (view) {
      const chat = chats.find(c => c.id === view.chat.id);
      if (!chat) { leaveRoom(); return; }
      await assertRoom(chat);
      if (active !== view) return;
      view.chat = chat;
      await checkRoom(view);
      if (active === view && view.ready) await loadMessages(view);
    }
  } catch (e) {
    if (sessionReady) {
      if (active) report('room-status', e);
      else { $('chats').replaceChildren(by('p', 'list-note', 'Could not refresh conversations.'), button('Try again', 'quiet', refresh)); }
    }
  } finally {
    refreshBusy = false;
    if (refreshAgain) { refreshAgain = false; scheduleRefresh(); }
  }
}
function leaveRoom() {
  active = null; $('workspace').classList.remove('room-open'); $('conversation').hidden = true; $('empty-room').hidden = false;
  $('draft').value = ''; $('messages').replaceChildren(); clearMode(false); clearMessageSearch(); closeEmoji(); drawRail();
}
$('back').onclick = leaveRoom;
function blockPrompt(member) {
  const serial = showDialog('Block ' + labelFor(member) + '?');
  append(by('p', '', 'This hides every chat you share with this person and stops messages and notifications from those chats. You can unblock them in account settings.'));
  const yes = button('Block contact', 'primary', async () => {
    yes.disabled = true;
    try {
      await api('/api/blocks', { id: member.id, blocked: true });
      if (dialogSerial !== serial) { scheduleRefresh(); return; }
      closeDialog(); leaveRoom(); await refresh();
    } catch (e) { if (dialogSerial === serial) report('dialog-status', e); }
    finally { yes.disabled = false; }
  });
  append(yes, button('Cancel', 'quiet', closeDialog));
}
$('room-options').onclick = () => {
  const view = active; if (!view) return;
  showDialog('Conversation settings');
  append(by('p', '', memberLabel(view.chat)), button('Verify contacts', 'action-row', verifyRoom));
  if (view.ready) append(button('Search messages on this device', 'action-row', () => {
    closeDialog(); $('message-search').hidden = false; applyMessageSearch(); $('message-query').focus();
  }));
  for (const member of others(view.chat)) append(button('Block ' + labelFor(member), 'action-row', () => blockPrompt(member)));
};
async function blockedContacts() {
  const serial = showDialog('Blocked contacts');
  try {
    const { users } = await api('/api/blocks');
    if (dialogSerial !== serial) return;
    if (!users.length) append(by('p', '', 'You have no blocked contacts.'));
    for (const member of users) {
      const undo = button('Unblock ' + labelFor(member), 'action-row', async () => {
        undo.disabled = true;
        try {
          await api('/api/blocks', { id: member.id, blocked: false });
          scheduleRefresh();
          if (dialogSerial === serial) await blockedContacts();
        } catch (e) { if (dialogSerial === serial) report('dialog-status', e); }
        finally { undo.disabled = false; }
      });
      append(undo);
    }
  } catch (e) { if (dialogSerial === serial) report('dialog-status', e); }
}
async function selectRoom(chat) {
  if (active?.chat.id === chat.id) return;
  const view = { chat, ready: false, messages: new Map(), decoded: new Map(), lastAck: 0, hasMore: false, sending: false, busy: false, again: false };
  active = view;
  $('workspace').classList.add('room-open'); $('empty-room').hidden = true; $('conversation').hidden = false; $('messages').replaceChildren();
  $('room-title').textContent = titleOf(chat); $('room-avatar').textContent = initials(titleOf(chat)); $('room-detail').textContent = memberLabel(chat);
  $('room-status').textContent = ''; $('draft').value = ''; $('older').hidden = true; clearMode(false); clearMessageSearch(); closeEmoji(); controls(); drawRail();
  await assertRoom(chat);
  if (active !== view) return;
  await checkRoom(view);
  if (active === view && view.ready) await loadMessages(view);
}
async function checkRoom(view) {
  const chat = view.chat;
  const pins = await Promise.all(others(chat).map(m => isPeerPinned(identity, m.id, m.publicKey)));
  if (active !== view) return;
  const groupAccepted = chat.members.length === 2 || localStorage.getItem(membershipKey(chat.id)) === 'yes';
  view.ready = pins.every(Boolean) && groupAccepted;
  $('room-detail').textContent = memberLabel(chat) + ' · ' + (view.ready ? 'Keys verified' : 'Verification needed');
  controls();
  if (!view.ready) {
    view.messages.clear(); view.decoded.clear(); $('older').hidden = true;
    clearMessageSearch(); clearMode(false);
    const gate = by('div', 'room-gate');
    gate.append(by('strong', '', 'Verify this conversation'), by('p', '', 'Check who is here and compare safety codes before reading or sending messages.'), button('Review contacts', 'primary', verifyRoom));
    $('messages').replaceChildren(gate);
  }
}
function controls() {
  const blocked = !active?.ready;
  $('draft').disabled = blocked; $('emoji').disabled = blocked;
  $('send').disabled = blocked || active?.sending || !$('draft').value.trim();
}

const unhex = s => Uint8Array.from(s.match(/../g), pair => Number.parseInt(pair, 16));
async function verifyEnrollment(member) {
  const record = await api('/api/contacts/' + encodeURIComponent(member.id) + '/proof');
  const a = record.attestation, m = a?.proof?.message, signature = a?.proof?.signature;
  if (!record.verified || record.id !== member.id || record.name !== member.name || canonicalKey(record.publicKey) !== canonicalKey(member.publicKey) || a?.version !== 1 ||
    !m || !(config.enrollmentOrigins ?? [location.origin]).includes(m.origin) || m.networkId !== config.networkId || m.accountId !== member.id || m.purpose !== 'login' ||
    !/^[0-9a-f]{64}$/.test(m.publicKey) || !/^[0-9a-f]{128}$/.test(signature) ||
    Object.keys(m).join(',') !== 'purpose,origin,networkId,accountId,authEpoch,publicKey,nonce,issuedAt,expiresAt' ||
    m.nonce !== await keyNonce(a.salt, record.publicKey)) throw new Error('Could not verify this contact’s Time wallet enrollment.');
  const signer = await crypto.subtle.importKey('raw', unhex(m.publicKey), 'Ed25519', false, ['verify']);
  const data = utf8.encode('TCDEVNET-LOGIN-V1\0' + JSON.stringify(m));
  if (!await crypto.subtle.verify('Ed25519', signer, unhex(signature), data)) throw new Error('The contact’s wallet signature could not be verified.');
}
async function verifyRoom() {
  const view = active; if (!view) return;
  const serial = showDialog('Verify contacts');
  const chat = view.chat;
  try {
    await assertRoom(chat);
    if (dialogSerial !== serial || active !== view) return;
    append(by('p', '', 'Compare the full safety code with each person in person or by another trusted channel. Enter the code they see on their device.'));
    if (chat.members.length > 2) append(by('strong', '', 'Members'), by('p', '', chat.members.map(m => labelFor(m) + ' (#' + m.id + ')').join(' · ')));
    for (const member of others(chat)) {
      const code = await safetyNumber(identity, member.id, member.publicKey);
      const pinned = await isPeerPinned(identity, member.id, member.publicKey);
      if (dialogSerial !== serial || active !== view) return;
      const card = by('section', 'peer-card');
      card.append(by('strong', '', labelFor(member) + ' · #' + member.id), by('code', '', code));
      if (pinned) card.append(by('p', '', 'Safety code verified on this device.'));
      else {
        const compare = field('Their safety code', 'Paste or type the full code');
        compare.input.spellcheck = false;
        const confirm = button('Verify code', 'quiet', async () => {
          confirm.disabled = true;
          try {
            await verifyEnrollment(member);
            if (dialogSerial !== serial || active !== view) return;
            await pinPeer(identity, member.id, member.publicKey, compare.input.value);
            if (dialogSerial !== serial || active !== view) return;
            await checkRoom(view);
            if (view.ready) { closeDialog(); await loadMessages(view); }
            else await verifyRoom();
          } catch (e) { if (dialogSerial === serial) report('dialog-status', e); }
          finally { confirm.disabled = false; }
        });
        card.append(compare.el, confirm);
      }
      append(card);
    }
    if (chat.members.length > 2) {
      const already = localStorage.getItem(membershipKey(chat.id)) === 'yes';
      const agree = button(already ? 'Members confirmed' : 'Confirm these members', 'primary', async () => {
        try {
          await assertRoom(chat);
          if (dialogSerial !== serial || active !== view) return;
          localStorage.setItem(membershipKey(chat.id), 'yes'); await checkRoom(view);
          if (view.ready) { closeDialog(); await loadMessages(view); }
          else await verifyRoom();
        } catch (e) { if (dialogSerial === serial) report('dialog-status', e); }
      });
      agree.disabled = already; append(agree);
    }
  } catch (e) { if (dialogSerial === serial) report('dialog-status', e); }
}
$('verify').onclick = verifyRoom;
function newChat() {
  const serial = showDialog('New conversation');
  const lookup = field('Find a Time account', '@name or account number');
  const selected = new Map();
  const chips = by('div', 'selected-list');
  const results = by('div');
  const search = by('form', 'peer-card');
  const find = by('button', 'quiet', 'Find contact'); find.type = 'submit';
  search.append(lookup.el, find);
  let searchCount = 0;
  const start = button('Start conversation', 'primary', async () => {
    if (!selected.size) return;
    start.disabled = true;
    try {
      const ids = [...selected.keys()];
      const expected = await roomId(config.networkId, [user.id, ...ids]);
      const { chat } = await api('/api/chats', { members: ids });
      await assertRoom(chat);
      if (chat.id !== expected || ids.some(id => canonicalKey(chat.members.find(m => m.id === id)?.publicKey) !== canonicalKey(selected.get(id).publicKey))) throw new Error('The returned conversation differs from your selection.');
      if (dialogSerial !== serial) return;
      if (chat.members.length > 2) localStorage.setItem(membershipKey(chat.id), 'yes');
      closeDialog();
      chats = [chat, ...chats.filter(c => c.id !== chat.id)];
      await selectRoom(chat);
      if (active?.chat.id === chat.id && !active.ready) await verifyRoom();
    } catch (e) { report($('dialog').open ? 'dialog-status' : 'room-status', e); }
    finally { start.disabled = false; }
  });
  function drawSelected() {
    chips.replaceChildren();
    for (const m of selected.values()) {
      const remove = button(labelFor(m) + ' ×', '', () => { selected.delete(m.id); drawSelected(); });
      remove.setAttribute('aria-label', 'Remove ' + labelFor(m)); chips.append(remove);
    }
    start.disabled = !selected.size;
    start.textContent = selected.size > 1 ? 'Start group chat' : 'Start conversation';
  }
  search.addEventListener('submit', async e => {
    e.preventDefault();
    const q = lookup.input.value.trim(); if (!q) return;
    const n = ++searchCount;
    results.textContent = 'Looking up account…'; $('dialog-status').textContent = '';
    try {
      const { users } = await api('/api/contacts?q=' + encodeURIComponent(q));
      if (dialogSerial !== serial || n !== searchCount) return;
      results.replaceChildren();
      for (const m of users.filter(m => m.id !== user.id && m.publicKey)) {
        const pick = button(labelFor(m) + ' · #' + m.id, 'action-row', () => {
          if (!selected.has(m.id) && selected.size >= 15) { report('dialog-status', 'A group holds up to 16 people, including you.'); return; }
          selected.set(m.id, m); results.replaceChildren(); lookup.input.value = ''; drawSelected(); lookup.input.focus();
        });
        results.append(pick);
      }
      if (!results.childElementCount) results.append(by('p', '', 'No matching contact. They need to have joined Time Chat.'));
    } catch (err) { if (dialogSerial === serial && n === searchCount) { results.replaceChildren(); report('dialog-status', err); } }
  });
  append(search, results, chips, by('p', '', 'Select one contact for a direct message, or add more for a group.'), start);
  drawSelected(); lookup.input.focus();
}
$('new-chat').onclick = newChat; $('empty-new').onclick = newChat;
const pathFor = chat => '/api/chats/' + encodeURIComponent(chat.id);
const reactions = ['👍','❤️','😂','🎉','😮','😢','🙏','🔥'];
function clipped(text) { return Array.from(text.replace(/\s+/g, ' ')).slice(0,95).join(''); }
function clearMode(restore = true) {
  if (restore && active?.mode?.type === 'edit') $('draft').value = active.mode.previousDraft;
  if (active) active.mode = null;
  $('compose-mode').hidden = true; $('mode-label').textContent = ''; $('mode-target').textContent = '';
  controls();
}
$('cancel-mode').onclick = () => { clearMode(); $('draft').focus(); };
function enterMode(view, item, type) {
  if (active !== view || !view.ready || item.deleted) return;
  clearMode();
  view.mode = { type, targetId: item.messageId, previousDraft: $('draft').value };
  if (type === 'edit') $('draft').value = item.text;
  $('compose-mode').hidden = false; $('mode-label').textContent = type === 'edit' ? 'Edit your message' : 'Reply to ' + labelFor(view.chat.members.find(m => m.id === item.senderId));
  $('mode-target').textContent = clipped(item.text);
  closeDialog(); controls(); $('draft').focus();
}
async function sendEvent(view, event) {
  if (view !== active || !view.ready || view.sending) return false;
  view.sending = true; controls(); closeEmoji(); $('room-status').textContent = '';
  try {
    // A lost relay response can be retried without creating another signed event.
    const key = JSON.stringify(event);
    if (view.pending?.key !== key) {
      const packet = await encryptEvent({ identity, chatId: view.chat.id, memberIds: view.chat.members.map(m => m.id), event });
      view.pending = { key, packet };
    }
    if (view !== active || !view.ready) return false;
    const ack = await api(pathFor(view.chat) + '/messages', view.pending.packet);
    if (ack.messageId !== view.pending.packet.messageId || !Number.isSafeInteger(ack.seq) || ack.seq < 1) throw new Error('Message receipt unavailable. Retry to check delivery.');
    view.pending = null;
    if (view === active) {
      try { await loadMessages(view); }
      catch { report('room-status', 'Sent. Waiting to refresh this conversation.'); }
      scheduleRefresh();
    }
    return true;
  } finally { view.sending = false; if (view === active) controls(); }
}
async function react(view, item, emoji) {
  const current = item.reactions.find(r => r.emoji === emoji);
  closeDialog();
  try { await sendEvent(view, { type: 'reaction', targetId: item.messageId, emoji, active: !current?.by.includes(user.id) }); }
  catch (e) { if (view === active) report('room-status', e); }
}
function messageActions(view, item) {
  if (active !== view || !view.ready || item.deleted) return;
  showDialog('Message actions');
  const tray = by('div', 'emoji-tray');
  for (const emoji of reactions) {
    const choice = button(emoji, '', () => react(view, item, emoji));
    choice.setAttribute('aria-label', 'React ' + emoji); tray.append(choice);
  }
  append(tray, button('Reply', 'action-row', () => enterMode(view, item, 'reply')));
  if (item.senderId !== user.id) return;
  append(button('Edit message', 'action-row', () => enterMode(view, item, 'edit')), button('Remove message…', 'action-row', () => {
    showDialog('Remove this message?');
    append(by('p', '', 'The message will appear as removed for chat participants. Earlier encrypted history and copies someone already saved can persist.'),
      button('Remove message', 'primary', async () => {
        closeDialog();
        try { await sendEvent(view, { type: 'delete', targetId: item.messageId }); }
        catch (e) { if (active === view) report('room-status', e); }
      }), button('Cancel', 'quiet', closeDialog));
  }));
}
function drawBubble(view, item) {
  const row = by('article', 'bubble' + (item.senderId === user.id ? ' mine' : '') + (item.deleted ? ' removed' : ''));
  if (view.chat.members.length > 2) row.append(by('span', 'from', labelFor(view.chat.members.find(m => m.id === item.senderId))));
  if (item.replyPreview && !item.deleted) {
    const ref = item.replyPreview;
    const sender = view.chat.members.find(m => m.id === ref.senderId);
    row.append(by('span', 'reply-preview', (sender ? labelFor(sender) + ' · ' : '') + (ref.deleted ? 'Message removed' : clipped(ref.text))));
  }
  row.append(by('p', '', item.deleted ? 'Message removed' : item.text));
  if (item.reactions?.length && !item.deleted) {
    const tray = by('div', 'reactions');
    for (const r of item.reactions) {
      const chip = button(r.emoji + ' ' + r.count, 'reaction', () => react(view, item, r.emoji));
      chip.setAttribute('aria-label', r.emoji + ', ' + r.count + (r.count === 1 ? ' reaction' : ' reactions'));
      chip.setAttribute('aria-pressed', String(r.by.includes(user.id)));
      tray.append(chip);
    }
    row.append(tray);
  }
  const foot = by('div', 'bubble-foot');
  const stamp = new Date(item.createdAt);
  if (Number.isFinite(stamp.valueOf())) {
    const display = stamp.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    const time = by('time', '', (item.edited && !item.deleted ? 'Edited · ' : '') + display);
    time.dateTime = stamp.toISOString(); foot.append(time);
  }
  if (!item.deleted && !item.failed) {
    const more = button('···', 'bubble-more', () => messageActions(view, item));
    more.setAttribute('aria-label', 'Message actions'); more.title = 'Message actions'; foot.append(more);
  }
  row.append(foot);
  return row;
}
function applyMessageSearch() {
  const query = $('message-query').value.trim().toLocaleLowerCase();
  let count = 0;
  for (const row of $('messages').querySelectorAll('article.bubble')) {
    const match = !query || row.querySelector('p').textContent.toLocaleLowerCase().includes(query);
    row.hidden = !match;
    if (match) ++count;
  }
  $('search-count').textContent = query ? count + (count === 1 ? ' match' : ' matches') : '';
}
function clearMessageSearch() {
  $('message-search').hidden = true; $('message-query').value = ''; applyMessageSearch();
}
$('message-query').addEventListener('input', applyMessageSearch);
$('end-search').onclick = clearMessageSearch;
async function loadMessages(view, earlier = false) {
  if (!view.ready || active !== view) return;
  if (view.busy) { if (!earlier) view.again = true; return; }
  view.busy = true;
  const atBottom = $('timeline').scrollTop + $('timeline').clientHeight >= $('timeline').scrollHeight - 100;
  const beforeHeight = $('timeline').scrollHeight;
  try {
    const url = pathFor(view.chat) + '/messages';
    const existing = [...view.messages.keys()];
    const before = earlier && existing.length ? Math.min(...existing) : null;
    const { messages, hasMore } = await api(before ? url + '?before=' + before : url);
    if (active !== view || !view.ready) return;
    if (!existing.length || earlier) view.hasMore = hasMore;
    const memberIds = view.chat.members.map(m => m.id);
    // If many messages arrived while disconnected, restart at the latest contiguous page.
    // Earlier pages can then be loaded in order without silently skipping the gap.
    const detached = !earlier && existing.length && messages.length && hasMore && !messages.some(m => view.messages.has(m.seq));
    if (detached) { view.decoded.clear(); view.hasMore = true; }
    const rows = detached ? new Map() : new Map(view.messages);
    for (const msg of messages) {
      if (!Number.isSafeInteger(msg.seq) || msg.seq <= 0 || !memberIds.includes(msg.senderId)) throw new Error('Received a message outside this conversation.');
      const previous = rows.get(msg.seq);
      if (previous && (previous.messageId !== msg.messageId || previous.senderId !== msg.senderId || previous.ciphertext !== msg.ciphertext)) throw new Error('A stored message changed. Its history cannot be verified.');
      rows.set(msg.seq, msg);
    }
    const sorted = [...rows.values()].sort((a,b) => a.seq - b.seq);
    const fragment = document.createDocumentFragment(), seen = new Set(), verified = [], failed = [];
    for (const msg of sorted) {
      if (seen.has(msg.messageId)) throw new Error('A message was repeated under another sequence number.');
      seen.add(msg.messageId);
      let event = view.decoded.get(msg.messageId);
      if (event === undefined) {
        try {
          event = await decryptEvent({ identity, chatId: view.chat.id, memberIds, senderId: msg.senderId, messageId: msg.messageId, ciphertext: msg.ciphertext });
          view.decoded.set(msg.messageId, event);
        } catch { failed.push({ ...msg, text: 'This message could not be verified.', failed: true }); }
      }
      if (active !== view || !view.ready) return;
      if (event) verified.push({ ...msg, event });
    }
    const items = [...materializeThread(verified), ...failed].sort((a,b) => a.seq - b.seq);
    for (const item of items) fragment.append(drawBubble(view, item));
    if (!items.length) {
      const empty = by('div', 'conversation-empty');
      if (!sorted.length) empty.append(by('strong', '', 'Start the conversation'), by('p', '', 'Your text and emojis are encrypted on this device.'));
      else empty.append(by('p', '', 'Load earlier messages to see the conversation these updates belong to.'));
      fragment.append(empty);
    }
    view.messages = rows; $('messages').replaceChildren(fragment); $('older').hidden = !view.hasMore;
    if (!$('message-search').hidden) applyMessageSearch();
    if (earlier) $('timeline').scrollTop += $('timeline').scrollHeight - beforeHeight;
    else if (atBottom || !existing.length || view.sending) $('timeline').scrollTop = $('timeline').scrollHeight;
    const newest = sorted.at(-1)?.seq;
    if (!failed.length && !$('message-query').value && !document.hidden && newest && newest > view.lastAck && (atBottom || !existing.length) && !earlier) {
      const last = view.lastAck; view.lastAck = newest;
      try {
        await api(pathFor(view.chat) + '/read', { seq: newest });
        if (view === active && view.chat.unread) { view.chat.unread = 0; drawRail(); }
      } catch (e) { view.lastAck = last; throw e; }
    }
  } finally {
    view.busy = false;
    if (view.again && active === view) { view.again = false; scheduleRefresh(); }
  }
}
$('older').onclick = () => { if (active) loadMessages(active, true).catch(e => report('room-status', e)); };
document.addEventListener('visibilitychange', () => { if (sessionReady && !document.hidden) scheduleRefresh(); });
function closeEmoji() { $('emoji-tray').hidden = true; $('emoji').setAttribute('aria-expanded', 'false'); }
$('emoji').onclick = () => {
  const show = $('emoji-tray').hidden; $('emoji-tray').hidden = !show; $('emoji').setAttribute('aria-expanded', String(show));
};
for (const emoji of ['🙂','😂','❤️','🙌','👍','👀','✨','🥳','🙏','💚','🤔','🎉','🔥','🫶']) {
  $('emoji-tray').append(button(emoji, '', () => {
    const draft = $('draft'); draft.setRangeText(emoji, draft.selectionStart, draft.selectionEnd, 'end'); closeEmoji(); draft.focus(); controls();
  }));
}
$('draft').addEventListener('input', controls);
$('draft').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); if (!$('send').disabled) $('composer').requestSubmit(); }
});
$('composer').addEventListener('submit', async e => {
  e.preventDefault();
  const view = active, text = $('draft').value;
  if (!view?.ready || view.sending || !text.trim()) return;
  if (Array.from(text).length > 4000) { report('room-status', 'Keep your message within 4,000 characters.'); return; }
  const mode = view.mode;
  try {
    const sent = await sendEvent(view, mode ? { type: mode.type, targetId: mode.targetId, text } : { type: 'text', text });
    if (!sent) return;
    if (view !== active) return;
    if ($('draft').value === text) $('draft').value = mode?.type === 'edit' ? mode.previousDraft : '';
    clearMode(false); controls();
  } catch (err) { if (view === active) report('room-status', err); }
});

function pushAvailable() {
  return Boolean(config?.pushKey && 'serviceWorker' in navigator && globalThis.PushManager && globalThis.Notification);
}
async function pushSubscription() {
  const reg = await navigator.serviceWorker.getRegistration('/');
  return reg?.pushManager?.getSubscription() ?? null;
}
async function disablePush() {
  const sub = await pushSubscription();
  if (sub) {
    try { await api('/api/push/remove', { endpoint: sub.endpoint }); }
    finally { await sub.unsubscribe(); }
  }
  localStorage.removeItem('time-chat/push-owner/v1');
  notificationsEnabled = false;
}
async function enablePush() {
  if (!pushAvailable()) throw new Error('Push notifications are unavailable in this browser.');
  const permission = await Notification.requestPermission();
  if (permission !== 'granted') throw new Error('Notifications need permission in your browser settings.');
  await navigator.serviceWorker.register('/sw.js', { scope: '/' });
  const reg = await navigator.serviceWorker.ready;
  const vapid = config.pushKey.replace(/-/g, '+').replace(/_/g, '/');
  const key = Uint8Array.from(atob(vapid.padEnd(Math.ceil(vapid.length / 4) * 4, '=')), c => c.charCodeAt(0));
  let sub = await reg.pushManager.getSubscription();
  if (sub && localStorage.getItem('time-chat/push-owner/v1') !== config.networkId + '/' + user.id) { await sub.unsubscribe(); sub = null; }
  sub ??= await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
  try { await api('/api/push', { subscription: sub.toJSON() }); }
  catch (e) { await sub.unsubscribe(); throw e; }
  localStorage.setItem('time-chat/push-owner/v1', config.networkId + '/' + user.id);
  notificationsEnabled = true;
}
async function logout() {
  let notice = 'Signed out.';
  try { if ('serviceWorker' in navigator) await disablePush(); }
  catch { notice = 'Signed out. Review this site’s notification permission in your browser settings.'; }
  try {
    await api('/api/logout', {});
    sessionChanges?.postMessage('logout');
    endSession(notice);
  } catch (e) { report('dialog-status', e); }
}
async function settings() {
  const serial = showDialog('Account settings');
  append(by('strong', '', labelFor(user)), by('p', '', 'Time account #' + user.id));
  if (pushAvailable()) {
    try { notificationsEnabled = Boolean(await pushSubscription()) && localStorage.getItem('time-chat/push-owner/v1') === config.networkId + '/' + user.id; } catch { notificationsEnabled = false; }
    if (dialogSerial !== serial) return;
    const push = button(notificationsEnabled ? 'Turn off notifications' : 'Turn on notifications', 'action-row', async () => {
      push.disabled = true;
      try { if (notificationsEnabled) await disablePush(); else await enablePush(); await settings(); }
      catch (e) { if (dialogSerial === serial) report('dialog-status', e); }
      finally { push.disabled = false; }
    });
    append(push, by('p', '', 'Show a generic alert when a message arrives. Message text and contact names stay off the notification.'));
  } else append(by('p', '', 'Background notifications are unavailable on this browser or server. Open chats update automatically.'));
  append(button('Blocked contacts', 'action-row', blockedContacts), button('How privacy works', 'action-row', privacy), button('Sign out', 'action-row', logout));
}
$('settings').onclick = settings;
$('switch-account').onclick = async () => {
  $('switch-account').disabled = true;
  try { await api('/api/logout', {}); sessionChanges?.postMessage('logout'); endSession(); }
  catch (e) { report('signin-status', e); }
  finally { $('switch-account').disabled = false; }
};
async function boot() {
  try {
    config = await api('/api/config');
    if (!globalThis.isSecureContext || !crypto.subtle || !globalThis.indexedDB) {
      config = null;
      throw new Error('Open Time Chat on HTTPS or localhost in a browser with encrypted device storage.');
    }
    setSignButton('Sign in with Time');
    await openSession();
  } catch (err) {
    report('signin-status', err);
    if (config && !sessionReady) $('signin').disabled = false;
  }
}
boot();
