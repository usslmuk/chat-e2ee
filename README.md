# chat.

End to end encrypted chat. The server stores ciphertext and holds no keys.

Rooms are made from a link or an invite code. Messages travel directly between
browsers over WebRTC when a direct connection works, and through the server when it
does not.

Group crypto is MLS (RFC 9420), written from the spec. One Next.js process, one
port, no separate server to run.

> [!IMPORTANT]
> ## One room, two people
>
> A room holds exactly two participants. The server refuses a third join with
> `409`, and the client stops showing the invite code once a room is full, so
> there is nothing left to forward to a third person.
>
> The limit is enforced, not advisory. Cross member key resolution past two is
> unfinished, so the cap is what keeps that limitation out of the product. Do
> not remove it expecting group chat to work.

> [!WARNING]
> ## Read this before you rely on it
>
> - **MLS conformance is verified, interoperability is not.** The implementation passes
>   the working group's published vectors for every part of the protocol it covers,
>   including the tree hash and transcript hashes. It has never been tested against
>   another MLS implementation, so interoperability is unproven. See Cryptography for
>   what is and is not covered.
> - **Single instance only.** Presence, offers, and ICE state live in process
>   memory. Two instances break chat. This also rules out serverless hosts.

> [!NOTE]
> ## Project status
>
> Pre 1.0, version `0.1.0`. No release schedule and no compatibility promise.
> Anything can change or break between commits.
>
> **No licence file yet.** Until one is added the repo is unlicensed, which
> means nobody may legally reuse it. Add one before sharing it as anything other
> than something you run yourself.
>
> **Not audited.** No third party has reviewed this code. It has not been through
> a security review, a penetration test, or a formal cryptographic analysis. Treat
> the security properties as claims made by the author, not verified guarantees.
>
> Room contents are private to the two participants and expire after 24 hours.
> There is no account system and no recovery, so a lost device means lost history.

## What it does

- Rooms from a link or a code, joinable either way. Several sit in the sidebar and
  switch without a reload.
- Text and attachments up to 10 MB. Filename, type, and size all travel inside the
  ciphertext.
- Emoji reactions per message, grouped and counted. One click heart, or the plus
  for the full picker.
- Delete your own messages. The host can delete the whole chat.
- Typing indicators and presence. Both come from the server, so someone going
  offline shows up at once instead of on the next poll.
- Live updates over server sent events, unread counts per room.
- No plaintext in the database. Field names are random codes and the map that
  decodes them is not stored alongside the data. That is obfuscation rather than a
  security boundary, since the map ships in this repo.
- Everything expires. Blobs, messages, and idle rooms go after 24 hours. An invite
  code dies with the room behind it.

## How it works

Each room is an MLS group. The group key rotates whenever membership changes, so
adding someone produces a new key instead of a second copy of the old one.

The founder runs the group. When someone joins it fetches their public KeyPackage,
commits them in as a leaf, and stores a Welcome for that member. The composer stays
locked until the group contains every member of the room, so nobody can seal a
message to a tree that leaves the reader out.

Message bodies are sealed with AES-128-GCM under a sender ratchet. A random guard
value is mixed into the nonce so two messages at the same generation never collide.
The sender's leaf index goes inside the ciphertext and is proved by an Ed25519
signature.

The server sees ciphertext, room membership, sizes, and timing. It cannot see
content, filenames, or keys.

The identity key sits in browser storage, which makes script execution the whole
boundary. Production CSP carries a per response nonce and drops `unsafe-inline`
from `script-src`, so an injected script has to present that nonce to run at all.

## Running it

Node 20 or newer, pnpm, and a MongoDB Atlas cluster.

```
pnpm install
cp .env.example .env
```

Fill in `MONGO`, then generate the two peppers:

```
node -e "console.log('PEPPER=' + require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log('CODE_PEPPER=' + require('crypto').randomBytes(32).toString('hex'))"
```

```
pnpm dev
```

Serves on http://localhost:1337. Use two browsers, or a normal window and a private
one, because two tabs share storage and would end up sharing an identity.

Production is `pnpm build` then `pnpm start`. Generate a fresh pepper per
deployment and never reuse one between environments.

`PEPPER` keys the session token hash. `CODE_PEPPER` keys the invite code hash. Both
are keyed hashes, not signatures. They mean a stolen database cannot be cracked or
forged offline without the pepper. They do not let the server prove who issued a
code, since the server never signs anything.

`TURN_URL` and `TURN_SECRET` are the only optional variables. Leave both out and
the app runs on public STUN alone, which is enough for most people. See Relay.

## Layout

```
chat/
  src/app/          UI, client crypto, transport
  src/app/lib/      primitives, blob packing, fetch layer
  src/app/mls/      RFC 9420 implementation
  src/app/api/      relay routes: auth, db, storage, event stream
  fields.json       scrambled database field names
```

Routes return plain field names. `fields.json` is only there so a database dump
does not read as a schema.

## Cryptography

Written against the specs:

- RFC 9420, MLS. Tree math, key schedule, secret tree, sender ratchets, key
  packages, commits with an update path, Welcome messages, PSK proposals, leaf
  updates, external senders, resumption secrets, exporters, transcript hashes, and
  ratchet tree serialization. Verified against the published vectors for suite
  `0x0001`, covering tree math at ten sizes up to 512 leaves, crypto basics, five
  consecutive key schedule epochs, the secret tree at one, eight, and thirty two
  leaves, transcript hashes, the PSK secret chain, variable length headers, tree
  validation across fourteen trees, and tree operations. Suite `0x0001` only, since
  that is the only cipher suite implemented.
- RFC 9420 sections 6.2, 6.3 and 8.2, message protection. Public messages are
  implemented and both clients read and write them, but the working group's
  `message-protection` vectors use a different framing that has not been matched,
  so this part is written to the spec text and not verified against a vector.
- RFC 9180, HPKE. DHKEM(X25519) base mode. Verified against the official test
  vectors: shared secret, key, base nonce, exporter secret, ciphertext, and secret
  export all match byte for byte.
- RFC 5869, HKDF-SHA256.
- RFC 7748, X25519. RFC 8032, Ed25519.

Suite `0x0001`, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.

Key packages and commits are signed with the member's Ed25519 identity key, so a
package cannot be swapped in transit and nobody gets added under someone else's
leaf.

Sender ratchets are advanced rather than re-walked. The receiver keeps a rolling
window of the last 64 generations per sender and erases the ratchet root once it
fills, which is what gives forward secrecy across membership changes. Anything older
than the window can no longer be derived from a captured device.

## Benchmarks

Node 24 on Windows, one core, no native crypto addons. Measured against this code,
averaged over three runs, in a room where the sender has just started.

| Operation | Time |
|---|---|
| seal message, 32 byte payload | 0.10 ms |
| open message, 32 byte payload | 0.11 ms |
| seal message, 32 KB payload | 1.4 ms |
| open message, 32 KB payload | 1.4 ms |
| commit, add one member | 14.9 ms |
| apply a remote commit | 19.2 ms |
| key package create | 1.3 ms |
| full 2 member handshake | 19.1 ms |

Wire overhead is 65 bytes on a small message, about 4 KB on a 32 KB attachment.

Opening a message stays close to constant as a room gets longer:

```
after   1 message: 0.11 ms
after  10 messages: 0.15 ms
after  50 messages: 0.30 ms
after 100 messages: 0.52 ms
after 300 messages: 1.38 ms
```

The remaining growth is the sender's path secret being re-derived from the MLS tree
on each open, not the ratchet. Caching that derivation would flatten it further.

## Deploying

Put TLS in front of it. HSTS is set and WebRTC needs a secure context.

Port 1337 is fixed by the `dev` and `start` scripts. Change it in
`chat/package.json` if that clashes. Forward the real client IP in
`X-Forwarded-For`, or the per-IP rate limit treats every client as one address.

Live updates come over an event stream at `/api/v1/events`, with signalling posted
back. A join and a stored Welcome both push a wake, so a handshake lands in about
a second. After that the client settles into a 20 to 30 second tick as a backstop.

That stream lives in process memory, so this runs as a single instance. More than
one needs a shared bus such as Redis.

Expiry is Mongo TTL indexes plus a sweeper every ten minutes that clears rooms idle
past `IDLE_TTL_HOURS`, along with their messages, reactions, blobs, invites, and
pending welcomes. No change streams, so any cluster tier works.

## Relay

Messages are relayed as ciphertext, so the server never reads them. But when two
browsers cannot open a direct connection, the bytes travel through it instead of
going straight peer to peer. That is what TURN is for.

Out of the box the app uses public STUN servers only. Most people never notice,
because direct connections work on home broadband and mobile. The ones that fail
are behind symmetric NAT, which is mostly corporate firewalls and some carriers.

If you want it working everywhere, run coturn. On a VPS with a public IP:

```
sudo apt install coturn
openssl rand -hex 32
```

Put the output in `static-auth-secret` in `/etc/turnserver.conf`, alongside
`use-auth-secret` and `realm`, plus `cert` and `pkey` from your TLS certificate so
`turns` works. Add the private ranges to `denied-peer-ip` or the relay gets abused
as an open proxy and your address gets banned. The coturn docs list the full set.

Then set both variables or neither:

```
TURN_URL=turn:your-domain.com:3478,turns:your-domain.com:5349
TURN_SECRET=the generated value
```

Setting one without the other stops the server booting, on purpose.

`use-auth-secret` is what makes this safe to hand out. The browser never receives
your TURN password. It gets a username that is an expiry timestamp an hour out and
a credential that is an HMAC of that timestamp, generated per request at
`/api/v1/ice`. A leaked credential stops working on its own, and the long term
secret never leaves the server.

Two honest caveats. Relayed traffic means the TURN operator sees who connected to
whom, when, and roughly how much, though not the contents. And the cost is
bandwidth, since every relayed byte crosses the VPS twice. For text that is nothing.

## Contributing

Pull requests get reviewed. Expect to be asked about the threat model before anyone
reads the code. Name the algorithm and say where it is applied.

What gets declined: weakening or bypassing encryption, storing anything in
plaintext, server side content filtering, and anything that would raise the two
person cap without fixing the ratchet tree first.

<details>
<summary>Changelog</summary>

## 2026-10-11

Deleted messages now disappear for both people. MLS validated against the official
RFC 9420 test vectors.

**Corrected**

Four encoding defects in the MLS layer, all of the same kind: a value written in
this implementation's own shape rather than the one RFC 9420 specifies. Each one
produced output that two of our own clients agreed on and no third party could read.

- `ExpandWithLabel` length prefixed the label and context with a fixed two byte field
  instead of the variable length integer from RFC 9000 section 16, and ran HKDF extract
  before expand. Every derived secret in the key schedule, the secret tree, and the
  sender ratchets was wrong.
- Every vector on the wire had the same fixed two byte length. Key packages, commits,
  Welcome messages, and group info were all the wrong shape.
- The transcript hashes chained the previous digest through a length prefixed vector,
  and the framed content carried a length prefix inside the hash input. Both are fixed
  and now verified, including the confirmation tag MAC.
- The message layer had four more of the same. `FramedContent` length prefixed the
  proposal or commit as well as the application message, though only the last is a
  vector in the spec. `FramedContentTBS` length prefixed the content and the group
  context, which are bare structs. `SenderData` wrote the reuse guard as a vector when
  the spec fixes it at four bytes. And the nonce was derived by encrypting the guard
  with the message key and XORing the whole result, instead of XORing the guard into
  the first four bytes of the nonce from the key schedule.
- The tree hash covered only the encryption key, signature key, credential, and parent
  hash of a leaf node. RFC 9420 section 7.8 hashes the entire `LeafNode`, including
  capabilities, extensions, and signature. Since the tree hash feeds `GroupContext`,
  this changed every epoch's key schedule.

Also in this release:

- The secret tree descended with a `path` label and a private root derivation. Section
  9 specifies `"tree"` with a `left` or `right` context, rooted at the encryption
  secret. Descent is now a pure function of the encryption secret.
- The handshake and application ratchets expanded with the ratchet label twice, once
  in the caller and once in the constructor. The label belongs once.
- Leaf nodes stored the leaf signature in the field reserved for the signature key,
  so the two were indistinguishable. They are separate fields now, and the leaf
  signature covers the full node.
- Ratchet trees are serialized as the RFC's `optional<Node>` vector and round trip
  byte for byte. `GroupInfo` previously used a private node layout.
- Deleting a message removed it only on the deleting client. The endpoint did not
  notify the room and the message merge never removed anything.
- `GET /api/v1/msgs` reports whether the per room cap truncated the response, so the
  client only treats an absent id as deleted when the response was complete.

**Verification**

Ten vector families from the working group, 74 checks, all passing for suite `0x0001`:
tree math, crypto basics, key schedule, secret tree, transcript hashes, PSK secrets,
variable length headers, tree validation, tree operations, and ratchet tree round trip.

Beyond the vectors, the secret tree is checked at every leaf of one, eight, and
thirty two member trees, across two hundred distinct sender generations, out of order
and skipped access, and across five consecutive key schedule epochs.

**Added**

- Public messages, per RFC 9420 section 6.2. They were not implemented at all before,
  so every proposal and commit travelled as a private message. Written to the spec text
  and covered by the live tests, but not confirmed against the working group's
  `message-protection` vectors, whose framing differs.
- TURN support with coturn shared secret credentials, issued per request and
  expiring in an hour. Optional, and off unless both variables are set.

## 2026-10-10

Initial release.

**Added**

- Content Security Policy carries a per response nonce in production and drops
  `unsafe-inline` from `script-src`.
- Forward secrecy across membership changes. A rolling window of the last 64
  generations per sender is retained and the ratchet root is erased once it fills.
- Invite codes raised to 96 bits.
- Cursor pagination over message history, ordered by document id.
- Per room blob quota of 64 MB, enforced by conditional increment.
- Unique partial index on room and message id, making message send idempotent.

**Fixed**

- Three HPKE defects, all of which changed derived key material. `LabeledExtract`
  and `LabeledExpand` were missing the `HPKE-v1` prefix in the KEM context and the
  `HPKE` suite label in the ciphersuite context, and the AEAD id was absent from
  domain separation. `expand` chained the previous output block into the next HMAC
  input instead of using `info || i`. The exporter secret used the label
  `exporter` rather than `exp`.
- Opening a message no longer re-walks the sender's ratchet from generation 0.
- `CODE_PEPPER` was loaded and length checked but never used. Invite code hashes now
  use it.
- Message history was silently truncated. Every message stored sequence `0`, so the
  sort ran on a content hash and the 300 message limit applied across all rooms at
  once.
- An earlier non partial unique index could not be built against existing documents,
  which took the whole app down with `database unreachable`.
- Connection failures were reduced to a bare `database unreachable` by an empty catch
  block, hiding the underlying cause.
- Commit, welcome, and key publication required the room founder, so closing that
  browser mid handshake froze the group permanently.
- Rate limiting used a fixed window, which let a client double its rate across a
  window boundary. The bucket map also cleared itself when full, which would have
  let one client wipe the rate limit state for every user and IP.
- `slot` in the peer mesh returned the first peer in the map rather than the
  requested one once at capacity.
- Blob uploads accepted 14 MB with no per room quota.
- Deleted `rkSeal` and `rkOpen`, which prepended 12 bytes of their own AES key to
  every ciphertext. No call sites, so no live exposure.
- The quick reaction heart was a double encoded UTF-8 sequence and rendered as
  mojibake.

**Changed**

- Rooms are capped at two participants, enforced server side.
- Build stamp bumped to `11`. The HPKE key schedule and tree hash changes make
  previously stored group state unreadable, so existing rooms are cleared on load.

**Corrected**

- Ed25519 is RFC 8032. X25519 is RFC 7748. An earlier revision credited both to
  RFC 7748 and to NIST.
- `CODE_PEPPER` does not sign invite codes. A keyed hash is not a signature.
- Random database field names are obfuscation, not protection.

</details>