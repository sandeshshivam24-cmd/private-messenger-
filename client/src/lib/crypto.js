const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * True per-user asymmetric identity keys (ECDH P-256).
 * The private key is generated on-device and NEVER leaves the device
 * (not sent to the server, not visible to the server). Only the public
 * key is published so peers can derive a shared AES key with us.
 * The keypair is persisted in localStorage per-username so the same
 * device keeps the same identity across logins (matches single-device
 * login model). A different device logging into the same account will
 * mint a fresh identity key, same as re-pairing.
 */
export async function getOrCreateIdentity(username) {
  const storageKey = `pm_identity_${username}`;
  const saved = localStorage.getItem(storageKey);

  if (saved) {
    try {
      const { privateJwk, publicJwk } = JSON.parse(saved);
      const privateKey = await crypto.subtle.importKey(
        'jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
      );
      return { privateKey, publicJwk };
    } catch {
      // fall through and regenerate if corrupted
    }
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  localStorage.setItem(storageKey, JSON.stringify({ privateJwk, publicJwk }));
  return { privateKey: keyPair.privateKey, publicJwk };
}

/** Derive the shared AES-GCM key for a conversation with one peer. */
export async function deriveSharedKey(myPrivateKey, peerPublicJwk) {
  const peerPublicKey = await crypto.subtle.importKey(
    'jwk', peerPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []
  );
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPublicKey },
    myPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptWithKey(key, plainText) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(plainText));
  return { encryptedPayload: toBase64(encrypted), iv: toBase64(iv) };
}

export async function decryptWithKey(key, encryptedPayload, iv) {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(iv) },
    key,
    fromBase64(encryptedPayload)
  );
  return decoder.decode(decrypted);
}

export function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}
