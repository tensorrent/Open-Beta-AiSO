// Decrypt a git-crypt checkout in place, for CI runners on any platform (Node's
// own crypto; no git-crypt binary needed). The key comes from the GIT_CRYPT_KEY
// secret: the key file, base64-encoded. This file and the workflows stay plain
// text so GitHub can run them; they hold no product code.
//
// git-crypt's formats (https://github.com/AGWA/git-crypt):
//   key file:  "\0GITCRYPTKEY", u32 version 2, header fields until 0, then key
//              fields (u32 id, u32 length, bytes) until 0: 1 version, 3 AES key
//              (32 bytes), 5 HMAC key (64 bytes)
//   file:      "\0GITCRYPT\0", 12-byte nonce, AES-256-CTR ciphertext; the nonce
//              is the first 12 bytes of HMAC-SHA1(hmac key, plaintext)
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createDecipheriv, createHmac, timingSafeEqual } from 'node:crypto';

const encoded = process.env.GIT_CRYPT_KEY;
if (!encoded) { console.error('GIT_CRYPT_KEY is not set: this checkout stays encrypted. Add the key (base64) as a repository Actions secret.'); process.exit(1); }
const key = Buffer.from(encoded.trim(), 'base64');
if (key.subarray(0, 12).toString('latin1') !== '\0GITCRYPTKEY') { console.error('GIT_CRYPT_KEY is not a git-crypt key file (base64)'); process.exit(1); }
let at = 12; const u32 = () => { const v = key.readUInt32BE(at); at += 4; return v; };
if (u32() !== 2) { console.error('unsupported git-crypt key format'); process.exit(1); }
for (let id = u32(); id !== 0; id = u32()) at += u32();          // header fields (a key name, if any)
let aes = null, hmac = null;
for (let id = u32(); id !== 0; id = u32()) {
  const len = u32(), value = key.subarray(at, at + len); at += len;
  if (id === 3) aes = value; else if (id === 5) hmac = value;
}
if (!aes || aes.length !== 32 || !hmac || hmac.length !== 64) { console.error('the git-crypt key has no AES-256 and HMAC key'); process.exit(1); }

const HEADER = Buffer.from('\0GITCRYPT\0', 'latin1');
const files = execFileSync('git', ['ls-files', '-z'], { maxBuffer: 1 << 28 }).toString('utf8').split('\0').filter(Boolean);
let decrypted = 0;
for (const file of files) {
  let data; try { data = fs.readFileSync(file); } catch { continue; }       // symlinks to missing targets, submodules
  if (data.length < 22 || !data.subarray(0, 10).equals(HEADER)) continue;    // plain text (workflows, .gitattributes)
  const nonce = data.subarray(10, 22);
  const decipher = createDecipheriv('aes-256-ctr', aes, Buffer.concat([nonce, Buffer.alloc(4)]));
  const plain = Buffer.concat([decipher.update(data.subarray(22)), decipher.final()]);
  if (!timingSafeEqual(createHmac('sha1', hmac).update(plain).digest().subarray(0, 12), nonce)) { console.error(`${file}: does not decrypt with this key`); process.exit(1); }
  fs.writeFileSync(file, plain); decrypted++;
}
console.log(`git-crypt: ${decrypted} files decrypted`);
