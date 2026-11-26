import { generateVAPIDKeys, sendNotification } from 'web-push';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ApiError } from './store.mjs';

export function validateSubscription(input) {
  const bad = () => {
    throw new ApiError(400, 'Invalid browser push subscription.');
  };
  if (
    !input ||
    typeof input.endpoint !== 'string' ||
    input.endpoint.length > 2048
  )
    bad();
  let url;
  try {
    url = new URL(input.endpoint);
  } catch {
    bad();
  }
  const exact = [
    'fcm.googleapis.com',
    'updates.push.services.mozilla.com',
    'push.services.mozilla.com',
    'web.push.apple.com',
  ];
  const subdomains = [
    '.push.services.mozilla.com',
    '.push.apple.com',
    '.notify.windows.com',
  ];
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.port ||
    url.hash ||
    (!exact.includes(url.hostname) &&
      !subdomains.some((s) => url.hostname.endsWith(s)))
  )
    bad();
  const { auth, p256dh } = input.keys ?? {};
  if (
    !/^[A-Za-z0-9_-]{22}$/.test(auth ?? '') ||
    !/^[A-Za-z0-9_-]{87}$/.test(p256dh ?? '') ||
    Buffer.from(p256dh, 'base64url')[0] !== 4
  )
    bad();
  return { endpoint: url.href, keys: { auth, p256dh } };
}
export async function openPush(dir, deliver = sendNotification) {
  const file = path.join(dir, 'push-keys.json');
  try {
    await writeFile(file, JSON.stringify(generateVAPIDKeys()), {
      flag: 'wx',
      mode: 0o600,
    });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const keys = JSON.parse(await readFile(file, 'utf8'));
  return {
    publicKey: keys.publicKey,
    async notify(store, owner) {
      const subject =
        process.env.TIME_CHAT_PUSH_SUBJECT ||
        'mailto:postmaster@example.com';
      await Promise.allSettled(
        store.subscriptions(owner).map(async (sub) => {
          try {
            await deliver(sub, undefined, {
              TTL: 900,
              timeout: 8000,
              topic: 'time-chat',
              vapidDetails: { ...keys, subject },
            });
          } catch (error) {
            if ([404, 410].includes(error.statusCode))
              store.unsubscribe(owner, sub.endpoint);
          }
        })
      );
    },
  };
}
