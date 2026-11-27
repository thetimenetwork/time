// The wallet signs a 32-byte nonce for both login and key enrollment. Reserve half of a
// login nonce for its purpose and intended relay. The other half is fresh random input.
// The relay cannot choose an arbitrary enrollment commitment as an ordinary login.
export async function loginNoncePrefix(relayOrigin) {
  if (typeof relayOrigin !== 'string' || new URL(relayOrigin).origin !== relayOrigin) {
    throw new Error('Invalid Time Chat relay origin.');
  }
  const data = new TextEncoder().encode(JSON.stringify(['time-chat/login/v2', relayOrigin]));
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  return Array.from(bytes.subarray(0, 16), value => value.toString(16).padStart(2, '0')).join('');
}

export async function isChatLoginNonce(nonce, relayOrigin) {
  return typeof nonce === 'string' && /^[0-9a-f]{64}$/.test(nonce) &&
    nonce.startsWith(await loginNoncePrefix(relayOrigin));
}
