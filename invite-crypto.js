// Short private invite links, shared by index.html (decrypt) and make.html (encrypt).
//
// Link:        https://.../graduation/?to=duc-k3x9pqab
//              "duc" = the guest's line in guests.txt, "k3x9pqab" = the secret key.
// guests.txt:  duc <iv>.<ciphertext>      (one guest per line, # = comment, the last line for a name wins)
//
// The secret is never stored in the repo, only in the link. Without it the line cannot be read.
// AES-GCM encrypts the invite; PBKDF2 turns the short secret into an AES key and is deliberately
// slow (200k rounds), so trying every possible secret against guests.txt would take far too long.
const InviteCrypto = (() => {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"; // 32 chars, no look-alikes (l/1, o/0)
  const SHORT_LINK = /^([a-z0-9]+)-([a-z0-9]{8})$/;

  const toB64 = bytes => {
    let bin = "";
    bytes.forEach(b => bin += String.fromCharCode(b));
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const fromB64 = str => Uint8Array.from(atob(str.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));

  async function keyFrom(secret, slug) {
    const base = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: enc.encode("graduation:" + slug), iterations: 200000, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  // 8 random chars from 32 = 40 bits. 256 % 32 === 0, so "b % 32" keeps every char equally likely.
  function newSecret() {
    return [...crypto.getRandomValues(new Uint8Array(8))].map(b => ALPHABET[b % 32]).join("");
  }

  // "Lương Thành Trúc" -> "luongthanhtruc"
  function slugify(name) {
    return name.normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/đ/gi, "d")
      .toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 24);
  }

  async function encrypt(slug, secret, invite) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await keyFrom(secret, slug), enc.encode(JSON.stringify(invite)));
    return `${slug} ${toB64(iv)}.${toB64(new Uint8Array(ct))}`;
  }

  // Throws if the secret is wrong: AES-GCM checks that the data was not changed or opened with another key.
  async function decrypt(slug, secret, data) {
    const [iv, ct] = data.split(".");
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, await keyFrom(secret, slug), fromB64(ct));
    return JSON.parse(dec.decode(plain));
  }

  async function fetchGuests() {
    // the timestamp skips GitHub's cache, so a line added a minute ago is found
    const res = await fetch(`guests.txt?t=${Date.now()}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`guests.txt: HTTP ${res.status}`);
    const guests = new Map();
    for (const line of (await res.text()).split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const [slug, data] = t.split(/\s+/);
      if (slug && data) guests.set(slug, data);
    }
    return guests;
  }

  async function lookup(slug, secret) {
    const data = (await fetchGuests()).get(slug);
    if (!data) throw new Error(`"${slug}" is not in guests.txt yet`);
    return decrypt(slug, secret, data);
  }

  return { SHORT_LINK, newSecret, slugify, encrypt, decrypt, fetchGuests, lookup };
})();
