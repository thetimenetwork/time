import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

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

export function openStore(path, networkId) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;
    PRAGMA busy_timeout=3000;
    CREATE TABLE IF NOT EXISTS network(id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, publicKey TEXT NOT NULL, attestation TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS rooms(id TEXT PRIMARY KEY, updatedAt INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS members(room TEXT REFERENCES rooms(id), user TEXT REFERENCES users(id), seen INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(room,user));
    CREATE INDEX IF NOT EXISTS member_rooms ON members(user,room);
    CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY, room TEXT NOT NULL REFERENCES rooms(id), senderId TEXT NOT NULL REFERENCES users(id),
      messageId TEXT NOT NULL, ciphertext TEXT NOT NULL, createdAt INTEGER NOT NULL, UNIQUE(room,messageId));
    CREATE INDEX IF NOT EXISTS room_history ON messages(room,seq);
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
        db.prepare('INSERT OR IGNORE INTO blocks VALUES(?,?)').run(owner, peer);
      else
        db.prepare('DELETE FROM blocks WHERE owner=? AND peer=?').run(
          owner,
          peer
        );
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
          db.prepare('INSERT INTO rooms VALUES (?,?)').run(id, Date.now());
          const add = db.prepare('INSERT INTO members(room,user) VALUES (?,?)');
          for (const member of ids) add.run(id, member);
        }
        return chat(id, owner);
      });
    },
    list(owner) {
      return db
        .prepare(
          'SELECT room FROM members JOIN rooms ON rooms.id=members.room WHERE user=? ORDER BY updatedAt DESC,room'
        )
        .all(owner)
        .filter(({ room }) => !blockedRoom(room, owner))
        .map(({ room }) => chat(room, owner));
    },
    history(id, owner, before) {
      requireMember(id, owner);
      const rows = db
        .prepare(
          `SELECT seq,senderId,messageId,ciphertext,createdAt FROM messages WHERE room=? AND seq<? ORDER BY seq DESC LIMIT 51`
        )
        .all(id, before ?? Number.MAX_SAFE_INTEGER);
      return {
        messages: rows.slice(0, 50).reverse(),
        hasMore: rows.length > 50,
      };
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
