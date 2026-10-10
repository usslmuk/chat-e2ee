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
> The limit is enforced in the atomic update filter in the database, not by a
> read that a concurrent request can invalidate.

> [!NOTE]
> ## Project status
>
> Pre 1.0. No release schedule and no compatibility promise.
>
> **No licence file yet.** Until one is added the repo is unlicensed, which
> means nobody may legally reuse it.
>
> **Not audited.** No third party has reviewed this code. Treat the security
> properties as claims made by the author.
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

It also cannot see who sent what. Every message is sealed as an MLS application
message, which only a group member can produce, so the sender is authenticated by
the encryption itself rather than by a signature the server can read. To delete a
message the sender keeps a random one-time token in its own vault and the server
only ever stores a hash of it. Nothing the server holds links a message to a
person.

What it can still see is that two accounts exchanged a number of messages of given
sizes over a given period. See Cryptography for where that stops.

## Running it

See [INSTALLING.md](INSTALLING.md) for requirements, configuration, and how to run it
locally or in production.

```
pnpm install
cp .env.example .env
pnpm dev
```

## Layout

```
chat/
  src/app/          UI, client crypto, transport
  src/app/lib/      primitives, blob packing, fetch layer
  src/app/mls/      RFC 9420 implementation
  src/app/api/      relay routes: auth, db, storage, event stream
  vectors/          test vector runner, `pnpm vectors`
  fields.json       scrambled database field names
```

Routes return plain field names. `fields.json` is only there so a database dump
does not read as a schema.

## Cryptography

Written against RFC 9420, MLS, and RFC 9180, HPKE. Suite `0x0001`,
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, is what the app runs.

### Cipher suites

The crypto primitives are parameterised by suite rather than hardcoded. Two are
defined, matching RFC 9420:

| id | suite | AEAD | KEM | hash | signature |
|---|---|---|---|---|---|
| 1 | MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 | AES-128-GCM | X25519 | SHA-256 | Ed25519 |
| 2 | MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 | AES-256-GCM | X448 | SHA-512 | Ed448 |

`src/app/mls/suite.ts` holds both. HPKE, the KEM, the AEAD, the hash and the
signature are all selected from it, and `mls/selftest.ts` exercises each suite in
isolation: KEM agreement, AEAD round trip, sign and verify including a wrong key
and a wrong message, and `DeriveKeyPair` consistency.

Suite 1 is what ships and what the test vectors cover. Suite 2 is implemented and
self-tested, and running it means the published vectors no longer describe your
traffic, because they are suite 1 vectors. One family, `tree-operations`, is
published for suite 1 only.

### Identity rotation

Each group holds its own signing key, and rotation replaces it with a fresh one in
a normal commit. The new leaf is signed by the new key and arrives in the commit's
update path. The commit itself is still signed by the outgoing key, which is what
RFC 9420 section 12.4.2 requires, since that is the leaf the receiver still has.

Session keys were already regenerated on every page load, so rotation is about the
group identity, not the transport.

### Conformance testing

`pnpm vectors` runs the working group's published test vectors against this code
and prints a pass count per family. It downloads the vectors on first run and
caches them in `.vectors/`. Name one or more families to run a subset, for
example `pnpm vectors treekem welcome`. It exits non-zero if any check fails, so
it works as a gate.

The runner lives in the repository rather than in scratch scripts, so every number
below is something you can rerun rather than take on trust.

```
treekem                      997 pass    62 update paths: node keys, path secret chain, commit secret, tree hash after
tree-math                   6098 pass    tree math at ten tree sizes up to 512 leaves
tree-validation              468 pass    tree hashes and resolutions across fourteen trees
key-schedule                  50 pass    five chained epochs, every derived secret
deserialization               28 pass    variable length vector headers, encode and decode
passive-client-handling-commit 277 pass  26 commits, 20 update paths, commit secrets and epoch authenticators
passive-client-welcome        16 pass    passive join, epoch authenticator, tree hash
secret-tree                   10 pass    handshake and application ratchets, sender data keys
psk_secret                    10 pass    PSK secret chain, one through ten PSKs
tree-operations               10 pass    tree hashes before and after a proposal
crypto-basics                  7 pass    HPKE, HKDF, signing, labelled expansion
welcome                        6 pass    HPKE open, group secrets, GroupInfo, signature
transcript-hashes              2 pass    confirmed and interim transcript chaining, confirmation tag
```

`passive-client-handling-commit` is the family that drives a client all the way
through a received commit: it parses the commit, verifies the sender's signature
over `FramedContentTBS`, applies the update path, decrypts the path secret with
the client's own leaf key, derives the commit secret from it, mixes it into the
next epoch's joiner with the new group context, and checks the published epoch
authenticator and confirmation tag. 26 epoch transitions are derived end to end
from a Welcome.

`transcript-hashes` confirms `confirmed_transcript_hash_after` and
`interim_transcript_hash_after` for suite `0x0001`. Note that these vectors encode
the 64 byte signature in the confirmed input with a single `0x40` length byte.
RFC 9420 and the vector deserialization family both use the two byte form for a
64 byte value, so the runner reproduces the vectors by hand here rather than
through the production writer. The production writer follows the spec.

### What the harness found

Building the runner paid for itself immediately. Every defect below was invisible
to the two party tests, because two copies of this code both made the same
mistake at once and agreed with each other perfectly.

**Framing and encoding**

- `UpdatePath` was written as two length prefixed vectors with a node type byte in
  front. RFC 9420 section 7.6 defines it as a bare `LeafNode` followed by a
  `nodes<V>` vector.
- The commit body wrote the optional update path before the proposal list.
  RFC 9420 section 12.4 orders them the other way round, proposals first.
- `HPKECiphertext<V>` is a vector of structs, not of vectors. Reading it as
  repeated vectors returned the whole payload as one blob and empty vectors after
  it, so only the first recipient of a path node could ever decrypt a path secret.
- `Add` and `PreSharedKey` proposals were written and read as length prefixed
  vectors. RFC 9420 embeds both inline, so an Add payload was offset by a byte
  and could not be found again.
- A proposal list was written and read as a vector of individually length
  prefixed entries. RFC 9420 section 12.1 makes it one vector of packed
  `ProposalOrRef` structs.
- `proposal_type` is a `uint16` inside a `ProposalOrRef` discriminator. A bare
  `uint8` with no wrapper put every proposal type out by construction.
- `PSKType` is a `uint8` enum. Reading it as a `uint16` put every
  `pre_shared_key` proposal one byte out of position, which swallowed the
  `PSKLabel` and left the resolver's psk empty.
- `FramedContent` length prefixed the proposal or commit as well as the
  application message, though only the last is a vector in the spec.
  `FramedContentTBS` length prefixed the content and the group context, which
  are bare structs. `SenderData` wrote the reuse guard as a vector when the spec
  fixes it at four bytes.
- Every vector on the wire carried the same fixed two byte length. Key packages,
  commits, Welcome messages and GroupInfo were all the wrong shape. The writer
  now uses the variable length integer encoding from RFC 9000 section 16.
- `ExpandWithLabel` length prefixed the label and context with a fixed two byte
  field and ran HKDF extract before expand, so every derived secret in the key
  schedule, the secret tree and the sender ratchets was wrong.
- `GroupContext` was written without its trailing extensions vector, and length
  prefixed the extension list twice. Every group context fed to the key schedule
  was the wrong length.
- `GroupSecrets` was read by taking vectors off the end of the buffer until it
  ran dry, which turns an empty PSK list into one zero length PSK and then fails.
  It is one `PSKLabel` vector holding `PreSharedKeyID` structs.

**Signatures and hashing**

- The commit and public message signature was signed and verified without the
  `FramedContentTBS` label prefix from RFC 9420 section 5.1.2.
- The signed content was taken from just after the group id instead of from the
  start of the `FramedContent`, which includes the group id, epoch, sender and
  content type.
- The tree hash covered only the encryption key, signature key, credential and
  parent hash of a leaf node. RFC 9420 section 7.8 hashes the entire `LeafNode`,
  and since the tree hash feeds `GroupContext`, this changed every epoch's key
  schedule.
- The transcript hashes chained the previous digest through a length prefixed
  vector, and the framed content carried a length prefix inside the hash input.
- `MakeKeyPackageRef` was a bare SHA-256. RFC 9420 section 5.2 defines it as
  `RefHash` over a labelled input.
- Leaf nodes stored the leaf signature in the field reserved for the signature
  key, so the two were indistinguishable.

**Key schedule and tree**

- `joinerFromJoiner` substituted a zero length PSK with zero length input keying
  material. RFC 9420 section 8.4 says an empty PSK list gives an all zero vector,
  so every group without PSKs mixed in the wrong secret.
- The key schedule skipped the `KDF.Extract` between the joiner secret and the
  welcome and epoch secrets, and applied `"derived psk"` once at the end instead
  of once per PSK.
- `DeriveKeyPair` used the HPKE suite identifier instead of the KEM one and
  passed info bytes from an older draft of RFC 9180. Every parent node key in
  every tree was wrong.
- Resolutions ignored a node's unmerged leaves. RFC 9420 section 4.1.1 puts them
  on the parent node. The list was never parsed out of the parent node, the wire
  fields were labelled as a signature key and a parent hash when section 7.1 has
  an encryption key, a parent hash and an unmerged list, and the list was never
  persisted, so a reload dropped it. Filtered direct paths were affected too,
  which is what decides who receives a path secret.
- The resolution used for an update path now excludes leaves added by the same
  Commit, as RFC 9420 section 7.6 requires.
- Update proposals in a commit were parsed and then dropped. A commit carrying an
  update did not update anything.
- The secret tree descended with a `path` label and a private root derivation.
  Section 9 specifies `"tree"` with a `left` or `right` context, rooted at the
  encryption secret.
- The handshake and application ratchets expanded with the ratchet label twice.
- `derivePair` clamped the derived scalar, which RFC 9180 does not.

### Elsewhere

- RFC 9180, HPKE. DHKEM(X25519) base mode, verified through the
  `crypto-basics` family.
- RFC 5869, HKDF-SHA256.
- RFC 7748, X25519. RFC 8032, Ed25519.

Key packages and commits are signed with the member's Ed25519 identity key, so a
package cannot be swapped in transit and nobody gets added under someone else's
leaf.

Sender ratchets are advanced rather than re-walked. The receiver keeps a rolling
window of the last 64 generations per sender and erases the ratchet root once it
fills, which is what gives forward secrecy across membership changes. Anything older
than the window can no longer be derived from a captured device.

Private keys live in IndexedDB rather than `localStorage`, so they are not sitting
in base64 in profile storage where a disk scrape or a casual profile copy picks
them up. The vault is read into memory once at startup.

## Threat model

The honest version, in one place.

**Protected against, by default.** Anyone who can read the database, the network
path, or a backup, including a curious or compelled server operator. Content,
filenames and attachment types are inside the ciphertext. Forward secrecy means a
device seized today does not open last week's messages.

**Protected against, only if the server is honest.** This is the whole boundary.
The server ships the JavaScript that decrypts everything, so a compromised server
can serve code that reads plaintext. The CSP and the attachment type sniffing make
injected script hard, but they cannot help against script the operator chose to
send. For anyone facing that adversary, use a client you can verify instead.

**Not protected.** Who talked to whom, when, how often, and how much. The server
sees message count, ciphertext length, blob size, join times, room lifetime, and
your IP. Content length is not padded. A TURN operator additionally sees the
connection graph. For a 2 person room this is a small set, and it is enough to
identify both parties in many investigations.

**Not protected: harvest now, decrypt later.** X25519 and Ed25519 are both broken
by a quantum computer. Ciphertext recorded today is assumed readable eventually.
Rotating the identity key and moving rooms limits the window, it does not close it.

**Not protected: a hostile peer in the room.** There are no safety numbers and no
key verification, so you cannot tell whether the tree you were given is the tree
your peer is holding.

## Benchmarks

Node 24, one core, no native crypto addons. Best of N, two party room.

| Operation | Time |
|---|---|
| seal message, 32 byte payload | 0.05 ms |
| open message, 32 byte payload | 0.05 ms |
| seal message, 32 KB payload | 1.20 ms |
| commit, add one member | 4.75 ms |
| apply a remote commit | 3.52 ms |
| commit, no proposals | 1.40 ms |
| key package create | 1.17 ms |
| parse a cached key package | 0.003 ms |
| tree hash | 0.007 ms |

Wire overhead is 65 bytes on a small message, about 4 KB on a 32 KB attachment.

Opening a message is flat across the whole history, because the sender seed is
cached per epoch instead of being re-walked from the tree on every open:

```
open at message   1: 0.055 ms
open at message  10: 0.056 ms
open at message 100: 0.056 ms
open at message 300: 0.040 ms
```

### Where the time goes

Elliptic curve operations dominate, and this machine is slow at them. Same box,
same work, two implementations:

| Operation | native | this code |
|---|---|---|
| X25519 key exchange | 0.026 ms | 0.91 ms |
| Ed25519 sign | 0.030 ms | 0.44 ms |

A bigint multiply-and-reduce measures 176 microseconds here, roughly a thousand
times slower than a typical machine. That is the entire gap. The library does the
same work, this box does bigint badly. Expect these numbers an order of magnitude
better on ordinary hardware, and better still in a browser where WebCrypto does it
natively.

So the optimisations worth making are the ones that cut the count of curve
operations and keep them out of hot paths.

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

Relayed traffic means the TURN operator sees who connected to whom, when, and
roughly how much, though not the contents. The cost is bandwidth, since every
relayed byte crosses the VPS twice. For text that is nothing.

## Contributing

Pull requests get reviewed. Expect to be asked about the threat model before anyone
reads the code. Name the algorithm and say where it is applied.

What gets declined: weakening or bypassing encryption, storing anything in
plaintext, server side content filtering, and anything that would raise the two
person cap without fixing the ratchet tree first.

<details>
<summary>Changelog</summary>

## 0.1.2

Caching on the paths that run per message, and honest benchmarks.

**Fixed**

- Opening a message re-walked the secret tree on every single message to
  re-derive the sender's leaf secret, and base64-encoded the group id to build a
  cache key it then threw away. Both are stable for the epoch. The sender seed is
  now cached per group per leaf, so open is flat instead of climbing.
- A key package was re-parsed, with two Ed25519 verifications, every time it was
  referenced. A commit parses the same package two or three times, once in
  prepare and again building each Welcome. Parsed packages are now memoised on
  their ref hash, which drops a commit that adds a member from 9.1 ms to 4.8 ms
  and a parse from 2.0 ms to 0.003 ms.
- The update path encrypted the path secret to the committer's own nodes as well
  as everyone else's. The committer already holds that secret. Skipped, per the
  latitude RFC 9420 section 7.6 allows.

**Corrected**

The benchmark table in this readme was wrong. It claimed opening a message grew
from 0.11 ms to 1.38 ms over 300 messages and that a commit cost 14.9 ms.
Measured, opening is flat at 0.055 ms and a commit costs 4.75 ms. The growth
described was real in an older revision but is not now, and nobody re-measured
after the conformance fixes landed. The numbers above are measured, and the
curve primitives are annotated with a native comparison because this machine's
bigint is pathologically slow and the figures are not representative of the
hardware most people will run.

## 0.1.1

The whole MLS layer checked against the working group's published test vectors by a
runner that lives in the repository, and every defect that found corrected.

**Added**

- `pnpm vectors`. Downloads the published vectors, runs them against this code,
  prints a pass count per family, and exits non-zero on any failure. Source in
  `chat/vectors`, runner in `chat/scripts/vectors.mjs`, `esbuild` as the bundler.
  Thirteen of the sixteen published families now run.
- `treekem` covers node keys, the path secret chain, the commit secret and the
  tree hash after an update path, across 62 update paths in eleven trees.
- `passive-client-handling-commit` drives a passive client through a received
  commit end to end, and `transcript-hashes` confirms the confirmed and interim
  transcript chaining.
- Public messages, per RFC 9420 section 6.2, and a Welcome and GroupInfo codec in
  `mls/rfc.ts` that reads and writes the RFC structures.
- TURN support with coturn shared secret credentials, issued per request and
  expiring in an hour. Optional, and off unless both variables are set.
- Content Security Policy carries a per response nonce in production and drops
  `unsafe-inline` from `script-src`.
- Forward secrecy across membership changes. A rolling window of the last 64
  generations per sender is retained and the ratchet root is erased once it fills.
- Invite codes raised to 96 bits. Cursor pagination over message history, ordered
  by document id. Per room blob quota of 64 MB. Unique partial index on room and
  message id, making message send idempotent.

**Fixed, MLS**

Every item here is listed in full under Cryptography above, with the RFC section
it was measured against. In summary: the update path and commit body ordering, the
group secrets PSK list, the zero PSK substitution, the group context extensions
vector, the missing `FramedContentTBS` label, the proposal list packing and
`proposal_type` width, the update proposal payload, dropped update proposals,
`MakeKeyPackageRef`, unmerged leaf handling in resolutions and filtered direct
paths, unmerged leaf persistence, inline `Add` and `PreSharedKey` proposal framing,
the key package encoding, `HPKECiphertext` iteration, `GroupContextExtensions`
proposals, `PSKType` width, `PreSharedKeyID` splitting, the update path resolution
exclusion, the commit signature input range, and the derived scalar clamp in
`derivePair`.

**Fixed, relay**

- Message history dropped messages. The endpoint fetched 300 rows across every
  requested room, kept at most 60 per room, and advanced the cursor past all 300.
  Every discarded row was skipped forever with no error anywhere. The cursor now
  advances past the last row actually returned, so a busy room hands back its
  backlog over successive pages.
- The room quota for blobs only ever went up. It was incremented before the
  insert, never decremented when the insert failed, and never decremented when the
  TTL index deleted the file. A room that used attachments steadily filled with
  phantom quota and eventually refused every upload forever. Usage is now summed
  from the blobs collection on each upload, so expiry reclaims it by construction.
- The two person cap was checked and then the member was pushed, so two
  simultaneous joins both passed. The size check is now part of the atomic update
  filter and the cap is enforced by the database.
- The rate limiter wiped everyone's counters once it held 20000 keys, and the key
  was the leftmost `X-Forwarded-For` value, which the client chooses. Overflowing
  now rejects new keys instead of clearing the table, and the address comes from
  `X-Real-IP` or the rightmost forwarded entry.
- Message bodies accepted 1.4 million characters. The cap is now 200000. The blob
  cap stays at 1.5 MB.
- Every message stored sequence `0`, so the history sort ran on a content hash and
  the 300 message limit applied across all rooms at once.
- Blob uploads accepted 14 MB with no per room quota.
- Commit, welcome and key publication required the room founder, so closing that
  browser mid handshake froze the group permanently.
- An earlier non partial unique index could not be built against existing
  documents, which took the whole app down with `database unreachable`. Connection
  failures were also reduced to that same bare string by an empty catch block.
- `slot` in the peer mesh returned the first peer in the map rather than the
  requested one once at capacity.
- Rate limiting used a fixed window, which let a client double its rate across a
  window boundary.
- `CODE_PEPPER` was loaded and length checked but never used. Invite code hashes
  now use it.

**Fixed, client**

- Private keys were kept in `localStorage` as base64. The identity key, the
  pending offer key, and every group's seed, epoch secrets, held path secrets and
  ratchet secrets were readable by anything with filesystem or devtools access to
  the profile. All of it moved to IndexedDB, read into memory once at startup.
- The hand maintained `BUILD` constant is gone. The storage stamp is the version
  from `package.json`, injected by `next.config.js`, so bumping the version is the
  only thing needed to invalidate old vaults.
- `pack`, `unpack`, `keyedSeal`, `keyedOpen` and `sizeOf` in `lib/blob.ts` were
  never called by anything. The module is gone.
- `chat..png` was 1.1 MB and referenced by nothing. Removed.
- The layout referenced an `apple-icon.png` that was never in `public`, so every
  page load asked for a file that could only 404. The icon is generated from
  `icon.png` now.
- The quick reaction heart was a double encoded UTF-8 sequence and rendered as
  mojibake.

**Changed**

- Rooms are capped at two participants, enforced server side.
- Deleting a message removed it only on the deleting client. The endpoint now
  notifies the room and the merge removes it on both sides.
- `GET /api/v1/msgs` reports whether the per room cap truncated the response, so
  the client only treats an absent id as deleted when the response was complete.
- Ratchet trees are serialized as the RFC's `optional<Node>` vector and round trip
  byte for byte.
- `GroupInfo` uses the RFC wire layout rather than a private node layout.

**Corrected in the documentation**

- Ed25519 is RFC 8032. X25519 is RFC 7748. An earlier revision credited both to
  RFC 7748 and to NIST.
- `CODE_PEPPER` does not sign invite codes. A keyed hash is not a signature.
- Random database field names are obfuscation, not protection.

</details>