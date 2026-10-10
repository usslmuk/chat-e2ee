# Installing

Everything needed to run chat. locally.

## Requirements

Node 20 or newer, pnpm, and a MongoDB Atlas cluster. A free tier cluster is enough.

## Install

```
pnpm install
cp .env.example .env
```

## Configure

Fill in `MONGO` in `.env` with your Atlas connection string. Then generate the two
peppers and paste each into `.env`:

```
node -e "console.log('PEPPER=' + require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log('CODE_PEPPER=' + require('crypto').randomBytes(32).toString('hex'))"
```

`PEPPER` keys the session token hash. `CODE_PEPPER` keys the invite code hash. Both
are keyed hashes, not signatures. They mean a stolen database cannot be cracked or
forged offline without the pepper. They do not let the server prove who issued a
code, since the server never signs anything.

Generate a fresh pepper per deployment and never reuse one between environments.

`.env` is gitignored. It holds the only secrets the server has. Do not commit it and
do not paste it into an issue.

`TURN_URL` and `TURN_SECRET` are the only optional variables. Leave both out and the
app runs on public STUN alone, which is enough for most people. See Relay in the
README for what TURN is and when you need it.

## Run

Development, with hot reload:

```
pnpm dev
```

Serves on http://localhost:1337.

Open two browsers, or one normal window and one private window. Two tabs in the same
browser share local storage and would share an identity, which makes for a confusing
test.

Production:

```
pnpm build
pnpm start
```

## Verify

There is no test suite. The MLS layer is checked against the published vectors from
the working group at
`github.com/mlswg/mls-implementations/tree/main/test-vectors`, suite `0x0001` only,
since that is the only cipher suite implemented.

If you are running a fork and want to confirm the crypto still matches, that is the
check that matters. A test that only proves the code agrees with itself proves
nothing here, and has passed several times while the implementation was wrong.

## Troubleshooting

**The page loads but connecting does nothing.** Check `MONGO` is reachable from your
machine. Atlas IP access lists will block you by default.

**Two tabs behave like one person.** Expected. See Run above.

**Media or peer connections fail behind a strict NAT.** You need TURN. See Relay in
the README.

**Everything worked yesterday and saved rooms are broken today.** The group state is
versioned and old state is unreadable after an upgrade. Clients clear local storage
and re-handshake. Messages sent before the upgrade are not recoverable.

**Build fails on `next-env.d.ts` after running the build.** Restore it with
`git checkout -- chat/next-env.d.ts`. The build rewrites it for development paths.