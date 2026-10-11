/*
 * Gezeiten Push — Cloudflare Worker
 * Verschickt Web-Push-Nachrichten an die Geräte des Partners.
 *
 * Einstellung in Cloudflare (Settings → Variables and Secrets):
 *   VAPID_PRIVATE_JWK  (Typ "Secret")  — der Schlüssel, den die App unter „Push" erzeugt
 *
 * Sicherheit: Jede Anfrage muss ein gültiges Firebase-Login mitbringen. Der Worker liest
 * die Geräteliste nur MIT diesem Login aus eurer Datenbank — wer nicht berechtigt ist,
 * bekommt dort nichts und kann folglich auch nichts verschicken.
 */
const DB_URL = 'https://gezeiten-2e0f6-default-rtdb.europe-west1.firebasedatabase.app';
const ALLOWED_ORIGINS = ['https://julianmigoe.github.io'];
const CONTACT = 'mailto:julianmittmanngoetsch@gmail.com';
const PEOPLE = ['Julian', 'Clarisse'];

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = {
      'Access-Control-Allow-Origin': ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin'
    };
    const reply = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (request.method === 'GET') return reply({ ok: true, service: 'gezeiten-push', configured: !!env.VAPID_PRIVATE_JWK });
    if (request.method !== 'POST') return reply({ error: 'method' }, 405);
    if (!env.VAPID_PRIVATE_JWK) return reply({ error: 'VAPID_PRIVATE_JWK fehlt in den Worker-Einstellungen' }, 500);

    const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
    if (!token) return reply({ error: 'login' }, 401);

    let msg;
    try { msg = await request.json(); } catch (e) { return reply({ error: 'json' }, 400); }
    const from = String(msg.from || '');
    const targets = msg.toSelf ? [from] : PEOPLE.filter(p => p !== from);
    if (!targets.length || !targets.every(p => PEOPLE.includes(p))) return reply({ error: 'person' }, 400);

    const subsRes = await fetch(`${DB_URL}/push/subs.json?auth=${encodeURIComponent(token)}`);
    if (subsRes.status === 401 || subsRes.status === 403) return reply({ error: 'login' }, 401);
    if (!subsRes.ok) return reply({ error: 'db ' + subsRes.status }, 502);
    const allSubs = (await subsRes.json()) || {};

    let jwk, vapidPublic;
    try {
      jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
      vapidPublic = b64u(concat(new Uint8Array([4]), unb64u(jwk.x), unb64u(jwk.y)));
    } catch (e) { return reply({ error: 'Schlüssel ungültig — bitte VAPID_PRIVATE_JWK prüfen' }, 500); }
    const signingKey = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);

    const payload = new TextEncoder().encode(JSON.stringify({
      title: String(msg.title || 'Gezeiten').slice(0, 80),
      body: String(msg.body || '').slice(0, 300),
      tag: String(msg.tag || 'gezeiten').slice(0, 40),
      tab: String(msg.tab || '').slice(0, 20)
    }));

    const results = { sent: 0, failed: 0, removed: 0, devices: 0 };
    const jobs = [];
    for (const person of targets) {
      const subs = allSubs[person] || {};
      for (const [id, sub] of Object.entries(subs)) {
        if (!sub || !sub.endpoint || !sub.keys) continue;
        results.devices++;
        jobs.push((async () => {
          try {
            const res = await sendPush(sub, payload, signingKey, vapidPublic);
            if (res.status === 404 || res.status === 410) {
              await fetch(`${DB_URL}/push/subs/${encodeURIComponent(person)}/${encodeURIComponent(id)}.json?auth=${encodeURIComponent(token)}`, { method: 'DELETE' });
              results.removed++;
            } else if (res.ok) results.sent++;
            else results.failed++;
          } catch (e) { results.failed++; }
        })());
      }
    }
    await Promise.all(jobs);
    return reply(results);
  }
};

/* ---------- Web Push (RFC 8291 Verschlüsselung + RFC 8292 VAPID) ---------- */
async function sendPush(sub, payload, signingKey, vapidPublic) {
  const endpoint = new URL(sub.endpoint);
  const jwt = await vapidJwt(`${endpoint.protocol}//${endpoint.host}`, signingKey);
  const body = await encryptPayload(payload, unb64u(sub.keys.p256dh), unb64u(sub.keys.auth));
  return fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': `vapid t=${jwt}, k=${vapidPublic}`,
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '86400',
      'Urgency': 'normal'
    },
    body
  });
}

async function vapidJwt(audience, signingKey) {
  const enc = obj => b64u(new TextEncoder().encode(JSON.stringify(obj)));
  const unsigned = `${enc({ typ: 'JWT', alg: 'ES256' })}.${enc({ aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: CONTACT })}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, new TextEncoder().encode(unsigned)));
  return `${unsigned}.${b64u(sig)}`;
}

async function encryptPayload(plaintext, uaPublic, authSecret) {
  const te = new TextEncoder();
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, ephemeral.privateKey, 256));

  const ikm = await hkdf(authSecret, shared, concat(te.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, te.encode('Content-Encoding: nonce\0'), 12);

  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const padded = concat(plaintext, new Uint8Array([2]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, padded));

  const header = new Uint8Array(16 + 4 + 1 + asPublic.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPublic.length;
  header.set(asPublic, 21);
  return concat(header, ciphertext);
}

async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, length * 8));
}
function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let o = 0; for (const a of arrays) { out.set(a, o); o += a.length; }
  return out;
}
function b64u(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function unb64u(str) { const s = String(str).replace(/-/g, '+').replace(/_/g, '/'); const bin = atob(s + '==='.slice((s.length + 3) % 4)); return Uint8Array.from(bin, c => c.charCodeAt(0)); }
