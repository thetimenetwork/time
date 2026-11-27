import { createHash } from 'node:crypto';
import { statfsSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const day = 24 * 60 * 60 * 1000;
const dailyMessageBytes = 8 * 1024 * 1024;
const dailyRoomCreations = 100;
const pageBytes = 1024 * 1024;
const roomsPerPage = 24;
const diskReserve = 64n * 1024n * 1024n;

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function roomId(networkId, members) {
  const context = ['time-chat/room/v1', networkId, [...members].sort()];
  return createHash('sha256').update(JSON.stringify(context)).digest('hex');
}

export function openStore(path, networkId, { volumeStats = statfsSync } = {}) {
  const db = new DatabaseSync(path);
  function requireWriteSpace() {
    if (path === ':memory:') return;
    const { bavail, bsize } = volumeStats(path, { bigint: true });
    if (bavail * bsize <= diskReserve)
      throw new ApiError(503, 'Relay storage is nearly full. Try again later.');
  }
  db.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;
    PRAGMA busy_timeout=3000;
    CREATE TABLE IF NOT EXISTS network(id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, publicKey TEXT NOT NULL, attestation TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS rooms(id TEXT PRIMARY KEY, updatedAt INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS members(room TEXT REFERENCES rooms(id), user TEXT REFERENCES users(id), seen INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(room,user));
    CREATE TABLE IF NOT EXISTS room_creations(room TEXT PRIMARY KEY REFERENCES rooms(id), creator TEXT NOT NULL REFERENCES users(id), createdAt INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS creator_activity ON room_creations(creator, createdAt);
    CREATE INDEX IF NOT EXISTS member_rooms ON members(user,room);
    CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY, room TEXT NOT NULL REFERENCES rooms(id), senderId TEXT NOT NULL REFERENCES users(id),
      messageId TEXT NOT NULL, ciphertext TEXT NOT NULL, createdAt INTEGER NOT NULL, UNIQUE(room,messageId));
    CREATE INDEX IF NOT EXISTS room_history ON messages(room,seq);
    CREATE INDEX IF NOT EXISTS sender_volume ON messages(senderId,createdAt,octet_length(ciphertext));
    CREATE TABLE IF NOT EXISTS subscriptions(endpoint TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id), subscription TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS blocks(owner TEXT NOT NULL REFERENCES users(id), peer TEXT NOT NULL REFERENCES users(id), PRIMARY KEY(owner,peer));
  `);
  const pinned = db.prepare('SELECT id FROM network LIMIT 1').get();
  if (pinned && pinned.id !== networkId) {
    db.close();
    throw new Error('This database belongs to another Time network.');
  }
  db.prepare('INSERT OR IGNORE INTO network VALUES (?)').run(networkId);
  const transaction = (fn) => {
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      db.exec('COMMIT');
      return result;
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  };
  const user = (id) =>
    db.prepare('SELECT id,name,publicKey FROM users WHERE id=?').get(id);
  const participants = (id) =>
    db
      .prepare(
        'SELECT u.id,u.name,u.publicKey FROM members m JOIN users u ON m.user=u.id WHERE m.room=? ORDER BY u.id'
      )
      .all(id);
  const blockedRoom = (room, owner) =>
    !!db
      .prepare(
        `SELECT 1 FROM blocks b JOIN members m ON m.room=?
    WHERE (b.owner=? AND b.peer=m.user) OR (b.peer=? AND b.owner=m.user) LIMIT 1`
      )
      .get(room, owner, owner);
  const requireMember = (id, owner) => {
    if (
      !db
        .prepare('SELECT 1 FROM members WHERE room=? AND user=?')
        .get(id, owner) ||
      blockedRoom(id, owner)
    )
      throw new ApiError(404, 'Conversation unavailable.');
  };
  const chat = (id, owner) => {
    requireMember(id, owner);
    const row = db
      .prepare(
        `SELECT r.id,r.updatedAt,m.seen AS lastReadSeq,
      (SELECT count(*) FROM messages WHERE room=r.id AND seq>m.seen AND senderId<>m.user) AS unread
      FROM rooms r JOIN members m ON m.room=r.id WHERE r.id=? AND m.user=?`
      )
      .get(id, owner);
    return { ...row, title: '', members: participants(id) };
  };
  return {
    db,
    user,
    chat,
    requireMember,
    participants,
    visibleParticipants(id) {
      return participants(id).filter((member) => !blockedRoom(id, member.id));
    },
    blocks(owner) {
      return db
        .prepare(
          'SELECT u.id,u.name FROM users u JOIN blocks b ON b.peer=u.id WHERE b.owner=? ORDER BY u.name'
        )
        .all(owner);
    },
    block(owner, peer, blocked) {
      if (
        typeof peer !== 'string' ||
        !user(peer) ||
        peer === owner ||
        typeof blocked !== 'boolean'
      )
        throw new ApiError(400, 'Invalid contact.');
      if (blocked)
        return db.prepare('INSERT OR IGNORE INTO blocks VALUES(?,?)').run(owner, peer).changes !== 0;
      return db.prepare('DELETE FROM blocks WHERE owner=? AND peer=?').run(owner, peer).changes !== 0;
    },
    enroll({ id, name, publicKey, attestation }) {
      return transaction(() => {
        const existing = user(id);
        if (existing && existing.publicKey !== publicKey)
          throw new ApiError(
            409,
            'This account already has a different chat key. Open the original browser profile.'
          );
        if (!existing)
          db.prepare('INSERT INTO users VALUES (?,?,?,?)').run(
            id,
            name,
            publicKey,
            JSON.stringify(attestation)
          );
        else
          db.prepare('UPDATE users SET name=?,attestation=? WHERE id=?').run(
            name,
            JSON.stringify(attestation),
            id
          );
        return user(id);
      });
    },
    contact(query) {
      const byNumber = /^(0|[1-9][0-9]{0,19})$/.test(query);
      const name = query.replace(/^@/, '').toLowerCase();
      if (!byNumber && !/^[a-z0-9_]{2,15}$/.test(name)) return [];
      const who = byNumber
        ? user(query)
        : db
            .prepare('SELECT id,name,publicKey FROM users WHERE name=?')
            .get(name);
      return who ? [who] : [];
    },
    binding(id) {
      const row = db
        .prepare('SELECT id,name,publicKey,attestation FROM users WHERE id=?')
        .get(id);
      if (!row) throw new ApiError(404, 'Contact unavailable.');
      return { ...row, attestation: JSON.parse(row.attestation) };
    },
    createChat(owner, others) {
      if (
        !Array.isArray(others) ||
        others.length < 1 ||
        others.length > 15 ||
        others.some(
          (id) => typeof id !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(id)
        )
      )
        throw new ApiError(400, 'Choose 1 to 15 contacts.');
      const ids = [owner, ...others].sort();
      if (new Set(ids).size !== ids.length)
        throw new ApiError(400, 'Choose each participant once.');
      const id = roomId(networkId, ids);
      return transaction(() => {
        if (ids.some((who) => !user(who)))
          throw new ApiError(404, 'A contact has not joined Time Chat.');
        const blocked = db.prepare(
          'SELECT 1 FROM blocks WHERE owner=? AND peer IN (SELECT value FROM json_each(?)) LIMIT 1'
        );
        if (ids.some((who) => blocked.get(who, JSON.stringify(ids))))
          throw new ApiError(
            403,
            'Conversation unavailable for these participants.'
          );
        if (!db.prepare('SELECT 1 FROM rooms WHERE id=?').get(id)) {
          const now = Date.now();
          const { total } = db.prepare('SELECT count(*) AS total FROM room_creations WHERE creator=? AND createdAt>?').get(owner, now - day);
          if (total >= dailyRoomCreations) throw new ApiError(429, 'Daily new conversation limit reached.');
          requireWriteSpace();
          db.prepare('INSERT INTO rooms VALUES (?,?)').run(id, now);
          db.prepare('INSERT INTO room_creations VALUES (?,?,?)').run(id, owner, now);
          const add = db.prepare('INSERT INTO members(room,user) VALUES (?,?)');
          for (const member of ids) add.run(id, member);
        }
        return chat(id, owner);
      });
    },
    list(owner, cursor = null) {
      let timestamp = Number.MAX_SAFE_INTEGER, room = '';
      if (cursor !== null) {
        const match = typeof cursor === 'string' && /^(0|[1-9][0-9]{0,15})\.([a-f0-9]{64})$/.exec(cursor);
        if (!match || !Number.isSafeInteger(Number(match[1]))) throw new ApiError(400, 'Invalid conversation cursor.');
        timestamp = Number(match[1]);
        room = match[2];
      }
      const rows = db.prepare(`
        SELECT r.id FROM members me JOIN rooms r ON r.id=me.room
        WHERE me.user=? AND (r.updatedAt<? OR (r.updatedAt=? AND r.id>?))
        AND NOT EXISTS (
          SELECT 1 FROM members peer WHERE peer.room=me.room AND (
            EXISTS (SELECT 1 FROM blocks WHERE owner=me.user AND peer=peer.user) OR
            EXISTS (SELECT 1 FROM blocks WHERE owner=peer.user AND peer=me.user)
          )
        )
        ORDER BY r.updatedAt DESC,r.id LIMIT ?
      `).all(owner, timestamp, timestamp, room, roomsPerPage + 1);
      const chats = [];
      let bytes = 128; // Includes JSON object framing and the longest cursor.
      for (const row of rows.slice(0, roomsPerPage)) {
        const value = chat(row.id, owner);
        const size = Buffer.byteLength(JSON.stringify(value)) + 1;
        if (chats.length && bytes + size > pageBytes) break;
        chats.push(value);
        bytes += size;
      }
      const last = chats.at(-1);
      const nextCursor = chats.length < rows.length ? last.updatedAt + '.' + last.id : null;
      return { chats, nextCursor };
    },
    history(id, owner, before) {
      requireMember(id, owner);
      const rows = db
        .prepare(
          `SELECT seq,senderId,messageId,ciphertext,createdAt FROM messages WHERE room=? AND seq<? ORDER BY seq DESC LIMIT 51`
        )
        .iterate(id, before ?? Number.MAX_SAFE_INTEGER);
      const messages = [];
      let bytes = 32, hasMore = false;
      for (const row of rows) {
        const size = Buffer.byteLength(JSON.stringify(row)) + 1;
        if (messages.length === 50 || bytes + size > pageBytes) { hasMore = true; break; }
        messages.push(row);
        bytes += size;
      }
      return { messages: messages.reverse(), hasMore };
    },
    append(id, owner, messageId, ciphertext) {
      return transaction(() => {
        requireMember(id, owner);
        const existing = db
          .prepare(
            'SELECT seq,senderId,ciphertext FROM messages WHERE room=? AND messageId=?'
          )
          .get(id, messageId);
        if (existing) {
          if (existing.senderId !== owner || existing.ciphertext !== ciphertext)
            throw new ApiError(409, 'Message identifier was already used.');
          return { seq: existing.seq, inserted: false };
        }
        const now = Date.now();
        const { used } = db.prepare('SELECT coalesce(sum(octet_length(ciphertext)),0) AS used FROM messages WHERE senderId=? AND createdAt>?').get(owner, now - day);
        if (used + Buffer.byteLength(ciphertext) > dailyMessageBytes) {
          throw new ApiError(429, 'Daily encrypted message allowance reached. Try again later.');
        }
        requireWriteSpace();
        const result = db
          .prepare(
            'INSERT INTO messages(room,senderId,messageId,ciphertext,createdAt) VALUES (?,?,?,?,?)'
          )
          .run(id, owner, messageId, ciphertext, now);
        db.prepare('UPDATE rooms SET updatedAt=? WHERE id=?').run(now, id);
        return { seq: Number(result.lastInsertRowid), inserted: true };
      });
    },
    markRead(id, owner, seq) {
      requireMember(id, owner);
      if (
        !db
          .prepare('SELECT 1 FROM messages WHERE room=? AND seq=?')
          .get(id, seq)
      )
        throw new ApiError(400, 'Unknown message position.');
      db.prepare(
        'UPDATE members SET seen=max(seen,?) WHERE room=? AND user=?'
      ).run(seq, id, owner);
    },
    subscribe(owner, sub) {
      return transaction(() => {
        const existing = db
          .prepare('SELECT owner FROM subscriptions WHERE endpoint=?')
          .get(sub.endpoint);
        if (existing && existing.owner !== owner)
          throw new ApiError(
            409,
            'Unsubscribe this browser from its previous account first.'
          );
        if (
          !existing &&
          db
            .prepare('SELECT count(*) AS n FROM subscriptions WHERE owner=?')
            .get(owner).n >= 8
        )
          throw new ApiError(429, 'Subscription limit reached.');
        db.prepare('INSERT OR REPLACE INTO subscriptions VALUES (?,?,?)').run(
          sub.endpoint,
          owner,
          JSON.stringify(sub)
        );
      });
    },
    unsubscribe(owner, endpoint) {
      db.prepare('DELETE FROM subscriptions WHERE owner=? AND endpoint=?').run(
        owner,
        endpoint
      );
    },
    subscriptions(owner) {
      return db
        .prepare('SELECT subscription FROM subscriptions WHERE owner=?')
        .all(owner)
        .map((row) => JSON.parse(row.subscription));
    },
    close() {
      db.close();
    },
  };
}
