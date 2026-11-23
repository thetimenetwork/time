// The posts of the demo blog on the gateway's second origin (web-v4/merchant, routes in server.mjs).
// Node 26 SQLite, like order-store.mjs: WAL with synchronous=FULL, and each publish or delete is one
// transaction. A crash loses at most the request being written; it never loses or damages an older post.
// A post is plain text. The account number and name come from the server's verified session, never from
// the browser, and the time from the server's clock.
import {DatabaseSync} from 'node:sqlite';

// maxChars: characters (Unicode code points) after trimming. perAccount posts per account in windowMs,
// counted from a record of publishes that deleting a post does not shorten. keep: the journal holds the
// newest posts only. page: posts per answer of the list. maxRawChars: the longest text read at all.
export const POST_LIMITS = Object.freeze({maxChars: 500, perAccount: 20, windowMs: 86400000, keep: 500, page: 50, maxRawChars: 2000});

const refusal = (status, message) => Object.assign(new Error(message), {httpStatus: status});
// Every control character except the line feed (a carriage return before a line feed is read as part of the line break).
const CONTROL = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F]/;
// Embeddings, overrides and isolates of text direction: they could make a post read as something else.
const DIRECTION = /[\u202A-\u202E\u2066-\u2069]/;
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/, POST_ID = /^[1-9][0-9]{0,15}$/, NAME = /^[a-z0-9_]{1,32}$/;

/// The text of a post as it is stored, or a refusal (an Error with httpStatus 400) that says what is wrong.
export function checkPostText(value, limits = POST_LIMITS) {
  if (typeof value !== 'string') throw refusal(400, 'A post is text');
  if (value.length > limits.maxRawChars) throw refusal(400, `A post is at most ${limits.maxChars} characters`);
  if (!value.isWellFormed()) throw refusal(400, 'The text is not valid Unicode');
  const text = value.replace(/\r\n/g, '\n').trim();
  if (!text) throw refusal(400, 'Write something first: a post has at least one character');
  if (CONTROL.test(text)) throw refusal(400, 'Tabs and other control characters are not allowed in a post; line breaks are');
  if (DIRECTION.test(text)) throw refusal(400, 'Characters that change the direction of the text are not allowed in a post');
  const count = [...text].length;
  if (count > limits.maxChars) throw refusal(400, `A post is at most ${limits.maxChars} characters; this one has ${count}`);
  return text;
}

function checkLimits(limits) {
  const value = {...POST_LIMITS, ...limits};
  for (const key of Object.keys(POST_LIMITS)) if (!Number.isSafeInteger(value[key]) || value[key] < 1) throw Error('Blog limits are positive whole numbers');
  if (Object.keys(value).length !== Object.keys(POST_LIMITS).length || value.maxRawChars < value.maxChars) throw Error('Unknown blog limit');
  return Object.freeze(value);
}

export function createBlogStore({filename, networkId, now = Date.now, limits = POST_LIMITS}) {
  if (!filename || !/^[0-9a-f]{64}$/.test(networkId) || typeof now !== 'function') throw Error('Invalid blog store scope');
  limits = checkLimits(limits);
  const db = new DatabaseSync(filename);
  try {
    // secure_delete: the database file overwrites a deleted post instead of only unlinking it. The -wal file can
    // still hold its old page until SQLite next checkpoints and reuses that part of it.
    db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;');
    db.exec('CREATE TABLE IF NOT EXISTS scope (id INTEGER PRIMARY KEY CHECK(id=1), network TEXT NOT NULL);'
      + 'CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, name TEXT, body TEXT NOT NULL, created INTEGER NOT NULL);'
      + 'CREATE TABLE IF NOT EXISTS publishes (account TEXT NOT NULL, at INTEGER NOT NULL);'
      + 'CREATE INDEX IF NOT EXISTS publishes_account ON publishes(account, at);');
    const scope = db.prepare('SELECT network FROM scope WHERE id=1').get();
    if (scope && scope.network !== networkId) throw Error('The blog database belongs to another network');
    if (!scope) db.prepare('INSERT INTO scope VALUES(1,?)').run(networkId);
  } catch (error) { db.close(); throw error; }
  const newest = db.prepare('SELECT id,account,name,body,created FROM posts ORDER BY id DESC LIMIT ?');
  const older = db.prepare('SELECT id,account,name,body,created FROM posts WHERE id<? ORDER BY id DESC LIMIT ?');
  const one = db.prepare('SELECT id,account,name,body,created FROM posts WHERE id=?');
  const insert = db.prepare('INSERT INTO posts(account,name,body,created) VALUES(?,?,?,?)');
  const remove = db.prepare('DELETE FROM posts WHERE id=?');
  const trim = db.prepare('DELETE FROM posts WHERE id NOT IN (SELECT id FROM posts ORDER BY id DESC LIMIT ?)');
  const record = db.prepare('INSERT INTO publishes(account,at) VALUES(?,?)');
  const forget = db.prepare('DELETE FROM publishes WHERE at<=?');
  const recent = db.prepare('SELECT COUNT(*) AS n, MIN(at) AS first FROM publishes WHERE account=? AND at>?');
  const shape = row => ({id: String(row.id), accountId: row.account, name: row.name, text: row.body, createdAt: new Date(row.created).toISOString()});
  function transaction(work) {
    db.exec('BEGIN IMMEDIATE');
    try { const result = work(); db.exec('COMMIT'); return result; } catch (error) { try { db.exec('ROLLBACK'); } catch {} throw error; }
  }
  const clock = () => { const at = now(); if (!Number.isSafeInteger(at) || at < 0 || at > 8640000000000000) throw Error('The server clock is unusable'); return at; };
  return Object.freeze({
    limits,
    /// The newest posts, or the ones before the post `before` (a post id); `more` says whether older ones exist.
    list({before} = {}) {
      if (before !== undefined && (typeof before !== 'string' || !POST_ID.test(before))) throw refusal(400, 'Invalid post id');
      const rows = before === undefined ? newest.all(limits.page + 1) : older.all(Number(before), limits.page + 1);
      return {posts: rows.slice(0, limits.page).map(shape), more: rows.length > limits.page};
    },
    publish({accountId, name, text}) {
      if (typeof accountId !== 'string' || !DECIMAL.test(accountId)) throw Error('Invalid author account');
      const body = checkPostText(text, limits), author = typeof name === 'string' && NAME.test(name) ? name : null;
      return transaction(() => {
        const at = clock(), since = at - limits.windowMs;
        forget.run(since);
        const done = recent.get(accountId, since);
        if (done.n >= limits.perAccount) {
          // The oldest publish of the window leaves it then; rounded up to the minute.
          const again = new Date(Math.ceil((done.first + limits.windowMs + 1) / 60000) * 60000).toISOString().slice(0, 16).replace('T', ' ');
          throw refusal(429, `You have published ${done.n} posts in the last ${limits.windowMs / 3600000} hours, the most this demo allows. You can publish again after ${again} UTC.`);
        }
        const id = insert.run(accountId, author, body, at).lastInsertRowid;
        record.run(accountId, at);
        trim.run(limits.keep);
        return shape(one.get(id));
      });
    },
    /// Deletes a post of the account `accountId`; a post of another account is refused (403), a missing one too (404).
    remove({accountId, id}) {
      if (typeof id !== 'string' || !POST_ID.test(id)) throw refusal(400, 'Invalid post id');
      return transaction(() => {
        const row = one.get(Number(id));
        if (!row) throw refusal(404, 'There is no such post; it may have been deleted already');
        if (row.account !== accountId) throw refusal(403, 'Only the person who wrote a post can delete it');
        remove.run(Number(id));
        return {deleted: id};
      });
    },
    close: () => db.close(),
  });
}
