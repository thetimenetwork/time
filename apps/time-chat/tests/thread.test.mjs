import assert from 'node:assert/strict';
import test from 'node:test';
import { createMessage, encrypt, readKey } from 'openpgp';
import { createIdentity, decryptEvent, decryptText, encryptEvent, newMessageId, pinPeer, roomId, safetyNumber } from '../public/crypto.mjs';
import { isReactionEmoji, materializeThread, validateEvent } from '../public/thread.mjs';

const id = n => '10000000-0000-4000-8000-' + String(n).padStart(12, '0');
const row = (seq, senderId, event) => ({ seq, messageId: id(seq), createdAt: seq * 100, senderId, event });
const text = (seq, sender, content) => row(seq, sender, { type: 'text', text: content });
const edit = (seq, sender, target, content, at = seq) => row(seq, sender, { type: 'edit', targetId: id(target), text: content, at });
const remove = (seq, sender, target) => row(seq, sender, { type: 'delete', targetId: id(target) });
const reaction = (seq, sender, target, emoji, active, at = seq) =>
  row(seq, sender, { type: 'reaction', targetId: id(target), emoji, active, at });

test('a reaction is one emoji, including families, professions, flags, skin tones, hearts and keycaps', () => {
  for (const emoji of ['🥳', '👨‍👩‍👧‍👧', '👩🏽‍⚕️', '🇵🇹', '👍🏿', '❤', '❤️', '1️⃣', '#️⃣'])
    assert.equal(isReactionEmoji(emoji), true, emoji);
  for (const value of ['a', '1', '#', 'ab', '', '🙂🙂', '☕️x', '🏽', '🇦', 'e\u0301', ' 🙂', 1])
    assert.equal(isReactionEmoji(value), false, String(value));
  assert.throws(() => validateEvent({ type: 'delete', targetId: id(1), text: 'surprise' }));
  assert.throws(() => validateEvent({ type: 'reaction', targetId: id(1), emoji: 'A', at: 1, active: true }));
  assert.throws(() => validateEvent({ type: 'reaction', targetId: id(1), emoji: '❣️', at: 1, active: 1 }));
});

test('only the author changes or deletes a message, with permanent removal in the rendered thread', () => {
  const original = text(1, '3', 'Monday?');
  const reply = row(2, '6', { type: 'reply', targetId: id(1), text: 'Yes 👍' });
  const corrections = [edit(3, '6', 1, 'changed'), remove(4, '6', 1), edit(5, '3', 1, 'Tuesday?')];
  const live = materializeThread([reply, ...corrections, original]);
  assert.equal(live.length, 2);
  assert.equal(live[0].text, 'Tuesday?');
  assert.equal(live[0].edited, true);
  assert.deepEqual(live[1].replyPreview, { messageId: id(1), senderId: '3', text: 'Tuesday?', deleted: false });
  const tombstoned = materializeThread([
    ...corrections, original, reply, reaction(6, '6', 1, '🥳', true), remove(7, '3', 1),
    edit(8, '3', 1, 'restored'), reaction(9, '6', 1, '🥳', true),
  ]);
  assert.equal(tombstoned[0].text, '');
  assert.equal(tombstoned[0].deleted, true);
  assert.deepEqual(tombstoned[0].reactions, []);
  assert.deepEqual(tombstoned[1].replyPreview, { messageId: id(1), senderId: '3', text: '', deleted: true });
  assert.equal(tombstoned[1].text, 'Yes 👍');
});

test('reactions and edits use signed actor time and a deterministic tie break', () => {
  const rows = [
    text(1, '1', 'hello'), edit(2, '1', 1, 'newer', 90), edit(3, '1', 1, 'older', 40),
    reaction(4, '2', 1, '🎉', false, 70), reaction(5, '2', 1, '🎉', true, 30),
    reaction(6, '1', 1, '🎉', true, 1), reaction(7, '3', 1, '🎉', false, 70), reaction(8, '3', 1, '🎉', true, 70),
  ];
  const expected = materializeThread(rows);
  assert.equal(expected[0].text, 'newer');
  assert.deepEqual(expected[0].reactions, [{ emoji: '🎉', count: 2, by: ['1', '3'] }]);
  assert.deepEqual(materializeThread([...rows].reverse().concat(rows[4], rows[0])), expected);
});

test('unseen or ambiguous targets cannot receive controls or be used as reply previews', () => {
  const reply = row(2, '2', { type: 'reply', targetId: id(1), text: 'okay' });
  const followUp = row(3, '2', { type: 'reply', targetId: id(2), text: 'great' });
  const withoutTarget = [reply, followUp, edit(4, '1', 1, 'newer'), reaction(5, '2', 1, '🎉', true)];
  assert.deepEqual(materializeThread(withoutTarget), []);
  assert.equal(materializeThread([...withoutTarget, text(1, '1', 'earlier')]).length, 3);
  const conflicting = [text(1, '1', 'first'), text(1, '2', 'different'), ...withoutTarget];
  assert.deepEqual(materializeThread(conflicting), []);
  assert.deepEqual(materializeThread(conflicting.reverse()), []);
});

test('earlier text envelopes and new signed commands open with the same pinned identities', async () => {
  const net = 'b'.repeat(64), memberIds = ['1', '2'], chatId = await roomId(net, memberIds);
  const [a, b] = await Promise.all(memberIds.map(who => createIdentity(net, who)));
  const code = await safetyNumber(a, '2', b.publicKey);
  await pinPeer(a, '2', b.publicKey, code);
  await pinPeer(b, '1', a.publicKey, code);
  const targetId = newMessageId();
  // The encoding before chat controls existed. Write this fixture independently of encryptEvent.
  const old = ['time-chat/text/v1', net, chatId, memberIds, '1', targetId, 'Hi there'];
  const ciphertext = await encrypt({
    message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(old)) }),
    encryptionKeys: await Promise.all([a.publicKey, b.publicKey].map(armoredKey => readKey({ armoredKey }))),
    signingKeys: a.privateKey,
  });
  const options = { identity: b, chatId, memberIds, senderId: '1' };
  assert.equal(await decryptText({ ...options, messageId: targetId, ciphertext }), 'Hi there');
  assert.deepEqual(await decryptEvent({ ...options, messageId: targetId, ciphertext }), { type: 'text', text: 'Hi there' });
  for (const event of [
    { type: 'reply', targetId, text: 'Hi!' }, { type: 'edit', targetId, text: 'Hello!' },
    { type: 'reaction', targetId, emoji: '👩🏽‍⚕️', active: true }, { type: 'delete', targetId },
  ]) {
    const packet = await encryptEvent({ identity: a, chatId, memberIds, event });
    assert.deepEqual(Object.keys(packet).sort(), ['ciphertext', 'messageId']);
    assert.equal(packet.ciphertext.includes(targetId), false);
    const result = await decryptEvent({ ...options, ...packet });
    if (event.type === 'edit' || event.type === 'reaction') { assert.ok(Number.isSafeInteger(result.at)); delete result.at; }
    assert.deepEqual(result, event);
    await assert.rejects(decryptEvent({ ...options, ...packet, messageId: newMessageId() }));
    await assert.rejects(decryptText({ ...options, ...packet }));
  }
});
