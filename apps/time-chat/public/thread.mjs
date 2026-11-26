const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const segmenter = typeof Intl.Segmenter === 'function' && new Intl.Segmenter(undefined, { granularity: 'grapheme' });
// Account for emoji in text form (like a plain heart) alongside flags, keycaps,
// skin-tone and ZWJ sequences. Require one grapheme even on older emoji tables.
let recommendedEmoji;
try { recommendedEmoji = new RegExp('^\\p{RGI_Emoji}$', 'v'); } catch { /* Older browsers use the grammar below. */ }
const pictograph = '\\p{Extended_Pictographic}\\uFE0F?\\p{Emoji_Modifier}?';
const emojiSequence = new RegExp('^(?:' + pictograph + '(?:\\u200D' + pictograph + ')*|[0-9#*]\\uFE0F?\\u20E3|\\p{Regional_Indicator}{2})$', 'u');
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;

export function isReactionEmoji(value) {
  if (typeof value !== 'string' || !value || value.length > 64 || !segmenter ||
      [...segmenter.segment(value)].length !== 1 || /^\p{Emoji_Modifier}$/u.test(value)) return false;
  if (recommendedEmoji) return recommendedEmoji.test(value) || /^\p{Extended_Pictographic}\uFE0F?$/u.test(value);
  return emojiSequence.test(value);
}

export function plainText(value) {
  if (typeof value !== 'string' || value.length > 8192 || [...value].length > 4096 ||
      !value.trim() || !value.isWellFormed() || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(value))
    throw new Error('Send text or emoji, up to 4,096 characters.');
  return value;
}

export function messageIdentifier(id) {
  if (typeof id !== 'string' || !uuid.test(id)) throw new Error('Invalid message ID.');
  return id;
}

const fields = {
  text: ['type', 'text'],
  reply: ['type', 'targetId', 'text'],
  edit: ['type', 'targetId', 'text', 'at'],
  delete: ['type', 'targetId'],
  reaction: ['type', 'targetId', 'emoji', 'active', 'at'],
};

// Returning the fields in one order also makes duplicate detection independent
// of an object's serialization order. The timestamp travels inside the signature.
export function validateEvent(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.type !== 'string' || !Object.hasOwn(fields, value.type))
    throw new Error('Unknown chat event.');
  const names = fields[value.type];
  if (Object.keys(value).length !== names.length || !names.every(field => Object.hasOwn(value, field)))
    throw new Error('Invalid chat event fields.');
  if (names.includes('text')) plainText(value.text);
  if (names.includes('targetId')) messageIdentifier(value.targetId);
  if (names.includes('at') && (!Number.isSafeInteger(value.at) || value.at <= 0))
    throw new Error('Invalid signed event time.');
  if (value.type === 'reaction' && (typeof value.active !== 'boolean' || !isReactionEmoji(value.emoji)))
    throw new Error('Choose one emoji for a reaction.');
  return Object.fromEntries(names.map(field => [field, value[field]]));
}

function later(candidate, previous) {
  return !previous || candidate.event.at > previous.event.at ||
    (candidate.event.at === previous.event.at && candidate.messageId > previous.messageId);
}

// All rows must come from decryptEvent for the same room. Their ciphertext has
// already authenticated the sender, room, roster, UUID and command. A conflicting
// signed UUID is ambiguous and excluded, even if the relay delivers it first.
function orderedRows(rows) {
  const seen = new Map();
  for (const row of rows) {
    if (!row || typeof row.messageId !== 'string' || !uuid.test(row.messageId) || typeof row.senderId !== 'string' ||
        !Number.isSafeInteger(row.seq) || row.seq < 1) continue;
    let event;
    try { event = validateEvent(row.event); } catch { continue; }
    const content = JSON.stringify([row.senderId, event]);
    const other = seen.get(row.messageId);
    if (other === null) continue;
    if (other && other.content !== content) { seen.set(row.messageId, null); continue; }
    if (!other || row.seq < other.row.seq ||
        (row.seq === other.row.seq && String(row.createdAt) < String(other.row.createdAt)))
      seen.set(row.messageId, { content, row: { ...row, event } });
  }
  return [...seen.values()].filter(Boolean).map(entry => entry.row)
    .sort((a, b) => a.seq - b.seq || compare(a.messageId, b.messageId));
}

export function materializeThread(rows) {
  const messages = new Map();
  for (const row of orderedRows(rows)) {
    const { event, messageId, senderId, seq, createdAt } = row;
    const target = messages.get(event.targetId);
    // Pagination may not yet include the original. Rebuilding with older rows
    // picked up applies its verified replies and controls on the next render.
    if (event.type !== 'text' && (!target || target.seq >= seq)) continue;
    if (event.type === 'text' || event.type === 'reply') {
      messages.set(messageId, {
        seq, messageId, senderId, createdAt, text: event.text, replyTo: event.targetId ?? null,
        deleted: false, lastEdit: null, reactionStates: new Map(),
      });
    } else if (event.type === 'reaction' && !target.deleted) {
      let people = target.reactionStates.get(event.emoji);
      if (!people) { people = new Map(); target.reactionStates.set(event.emoji, people); }
      if (later(row, people.get(senderId))) people.set(senderId, row);
    } else if (senderId === target.senderId && !target.deleted) {
      if (event.type === 'edit' && later(row, target.lastEdit)) {
        target.text = event.text;
        target.lastEdit = row;
      } else if (event.type === 'delete') {
        target.text = '';
        target.deleted = true;
        target.lastEdit = null;
        target.reactionStates.clear();
      }
    }
  }

  return [...messages.values()].map(({ lastEdit, reactionStates, ...message }) => {
    const reactions = [];
    for (const [emoji, participants] of reactionStates) {
      const by = [...participants.values()].filter(row => row.event.active).map(row => row.senderId).sort();
      if (by.length) reactions.push({ emoji, count: by.length, by });
    }
    reactions.sort((a, b) => compare(a.emoji, b.emoji));
    const parent = message.deleted ? null : messages.get(message.replyTo);
    const replyPreview = parent ? {
      messageId: parent.messageId, senderId: parent.senderId, text: parent.text, deleted: parent.deleted,
    } : null;
    return { ...message, replyTo: message.deleted ? null : message.replyTo, replyPreview, edited: Boolean(lastEdit), reactions };
  });
}
