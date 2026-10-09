# chat.

End to end encrypted chat that a server cannot read. Rooms are made from a link or a
code. Messages travel directly between browsers over WebRTC when they can and fall
back to the relay when they cannot.

MLS (RFC 9420) written from the specification, so membership changes are real key
changes rather than bookkeeping. One Next.js process, one port, no custom server.

## How it works

Every room is an MLS group. Members share a group key that rotates on every membership
change, so joining and leaving changes what you can read rather than handing the same
key to one more person.

The founder holds the group. When someone joins, it pulls their public KeyPackage,
runs a Commit adding them as a leaf, stores a Welcome for that member, and publishes
the commit for everyone already present. Members apply commits in order, each verified
against the committer's leaf credential. The composer stays locked until the group
holds every member of the room, so nobody seals to a tree that excludes the reader.

Bodies are sealed with AES-128-GCM under a sender ratchet, mixed with a random guard
so two messages at one generation never share a nonce. Sender identity is the leaf
index inside the ciphertext, proved by an Ed25519 signature.

The server stores ciphertext and routing metadata. It holds no keys. Field names are
random codes so a database dump is not a readable schema, and browser storage keys are
random strings.

Presence is real rather than inferred: the server knows who holds an open event
stream, so going offline shows immediately instead of after a poll.

## Running

Node 20+, pnpm, and a MongoDB Atlas cluster.

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

Runs on http://localhost:1337. Open two browsers, or one window and one private
window, since two tabs share storage and would share an identity.

Production is `pnpm build` then `pnpm start`. Every variable in `.env.example` is
required and the server refuses to boot without them. Generate a fresh pepper per
deployment and never reuse one across environments. `PEPPER` hashes session tokens and
`CODE_PEPPER` signs invite codes, so a database dump without them cannot forge a
session or a link.

## Layout

```
chat/
  src/app/          UI, client crypto, transport
  src/app/lib/      primitives, blob packing, fetch layer
  src/app/mls/      RFC 9420 implementation
  src/app/api/      relay routes: auth, db, storage, event stream
  fields.json       scrambled database field names
```

API routes return plain field names. `fields.json` exists so the database itself is
unreadable in a dump, not to complicate the JSON.

## Cryptography

Written against the specifications rather than a library:

- RFC 9420, MLS. Tree math, key schedule, secret tree, sender ratchets, key
  packages, commits with an update path, welcome messages, remote commit application,
  PSK proposals, leaf updates, external senders, resumption secrets, exporters.
- RFC 9180, HPKE. DHKEM(X25519) base mode.
- RFC 5869, HKDF-SHA256.
- NIST curves, X25519 and Ed25519.

Suite `0x0001`, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. Key packages and
commits are signed by the member's Ed25519 identity key, so a KeyPackage cannot be
swapped in transit, a commit cannot be forged, and nobody can be added under someone
else's leaf.

## Benchmarks

Node 24 on Windows, single core, no native crypto addons. Measured against the real
implementation.

| Operation | Time |
|---|---|
| seal message, 32 byte payload | 0.10 ms |
| open message, 32 byte payload | 18.7 ms |
| seal message, 32 KB payload | 1.5 ms |
| open message, 32 KB payload | 26.6 ms |
| commit, add one member | 10.7 ms |
| apply a remote commit | 37.6 ms |
| key package create | 1.4 ms |
| full 2 member handshake | 22.6 ms |
| full 10 member bootstrap | 601 ms |

Wire overhead is 40 bytes on a small message and about 4 KB on a 32 KB attachment.

Sealing runs near 10,000 messages a second. Opening is far slower and that asymmetry
is worth understanding before optimising it: the sender already holds its ratchet
key, while the receiver re-derives the sender's ratchet from a path secret by walking
the tree, which costs one HMAC per level. The 10 member bootstrap is dominated by
commit application, since every member processes every commit.

## Deploying

Terminate TLS in front of it. HSTS is set and P2P needs a secure context for WebRTC.

The port is fixed at 1337 by the `dev` and `start` scripts; change it in
`chat/package.json` if that clashes. Pass the real client IP in `X-Forwarded-For` or
the per-IP rate limit counts every client as one.

Live updates ride a server-sent event stream at `/api/v1/events`, with signalling sent
back as POSTs. A join and a stored Welcome both push a wake, so a handshake lands in
about a second. Once everyone is in, the client backs off to a 20 to 30 second tick as
a safety net.

The stream lives in process memory, so this is a single instance deployment. Past one
instance you need a shared bus such as Redis. That also rules out serverless hosts,
which freeze idle connections.

Expiry is Mongo TTL indexes plus a sweeper every ten minutes that clears rooms idle
past `IDLE_TTL_HOURS` along with their messages, reactions, blobs, invites, and pending
welcomes. No change streams, so any cluster tier works.

## Design notes

Metadata leaks. Whoever watches the network sees who connected to whom and roughly how
much they sent. P2P hides contents from the relay, not the fact that two people are
talking.

Anyone in a room can read every message, screenshot them, or forward them. MLS gives
forward secrecy across membership changes, not recall.

The server serves the JavaScript that holds your keys, so a compromised server can
serve code that steals everything. Self hosting is the meaningful mitigation.

## Status

Working end to end: rooms, invite codes, key packages, commits, welcomes, sender
ratchets both directions, history, attachments, reactions, per member deletion, host
deletion, P2P with relay fallback, live push, presence, and 24 hour expiry.

**Two member rooms are the supported configuration.** Larger rooms are partial.
Membership changes commit and propagate correctly: every member applies every commit,
and a ten member room converges on one epoch and one tree shape. Message visibility
inside those rooms is not yet correct, so treat anything past two people as unfinished.
The group state agrees, per sender key resolution does not.

Follow ups in order: correct cross member sender key resolution past two people,
official RFC 9420 test vectors, leave and kick in the UI, non extractable key storage,
multi device, onion transport.

## Contributing

Pull requests get reviewed. Expect questions about the threat model before anyone
reads the code. Name the algorithm and say where it gets applied.

Worth opening a PR for the items in Status. Will get declined: weakening or bypassing
encryption, storing anything in plaintext, server side content filtering.