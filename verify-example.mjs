#!/usr/bin/env node
/**
 * Verify a First Read provenance signature. No dependencies, no First Read code, no network call
 * to First Read. Node 16+.
 *
 *   node verify-example.mjs binding.json document.txt
 *
 * `binding.json` is a record exported from First Read. `document.txt` is the document text it
 * claims to describe. Exit code 0 means the signature holds and the text is unaltered.
 *
 * THE POINT OF THIS FILE: if you can run it, you never have to trust First Read — or ask them for
 * anything — to settle a question about a document's origin.
 */
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const [, , bindingPath, documentPath] = process.argv;
if (!bindingPath || !documentPath) {
  console.error('usage: node verify-example.mjs <binding.json> <document.txt>');
  process.exit(2);
}

const binding = JSON.parse(readFileSync(bindingPath, 'utf8'));
const document = readFileSync(documentPath, 'utf8');
const manifest = JSON.parse(readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'));

/** The published fingerprint rule. CRLF to LF, strip trailing spaces/tabs per line, trim, SHA-256. */
const fingerprint = (text) =>
  createHash('sha256')
    .update(text.replace(/\r\n/g, '\n').replace(/[ \t]+$/gm, '').trim(), 'utf8')
    .digest('hex');

/* 1. Does the text match what was signed? */
const contentOk = fingerprint(document) === binding.contentFingerprint;

/* 2. Which key was signing when this was saved? Never assume the current one. */
const t = Date.parse(binding.savedAt);
const key = manifest.keys.find(
  (k) => Date.parse(k.validFrom) <= t && (k.validUntil === null || t < Date.parse(k.validUntil)),
);

/* 3. Rebuild the exact signed bytes. Field order is fixed and published; do not reorder. */
const payload = JSON.stringify([
  binding.version, binding.docId, binding.showId, binding.ownerId,
  binding.contentFingerprint, binding.profileFingerprint, binding.docType, binding.savedAt,
]);

const sigOk = key
  ? verify(null, Buffer.from(payload, 'utf8'), createPublicKey(key.publicKey),
      Buffer.from(binding.signature, 'base64'))
  : false;

console.log(`document unaltered : ${contentOk ? 'yes' : 'NO — the text differs from what was signed'}`);
console.log(`key found for date : ${key ? key.fingerprint : 'NO — no published key covers ' + binding.savedAt}`);
console.log(`signature valid    : ${sigOk ? 'yes' : 'NO'}`);
console.log(`voice profile hash : ${binding.profileFingerprint ?? '(none recorded)'}`);
console.log('');
/*
  The success line branches on whether a voice profile was actually recorded. The first version
  said "against the recorded voice profile" unconditionally and printed that on a record whose
  profileFingerprint was null -- claiming something the record did not contain, in the one file
  whose whole purpose is letting someone check a claim. Caught by running it on a real document.
*/
if (contentOk && sigOk) {
  console.log(binding.profileFingerprint
    ? 'VERIFIED. First Read produced this document against the recorded voice profile, at the stated time.'
    : 'VERIFIED. First Read produced this document at the stated time. No voice profile was recorded\n'
      + 'for it, so this says nothing about which voice it was written against.');
  console.log('This does NOT by itself prove who the person behind the account is.');
} else {
  console.log('NOT VERIFIED. Do not rely on this record.');
}

process.exit(contentOk && sigOk ? 0 : 1);
