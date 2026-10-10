# Contributing

Thanks for looking at this. The bar for changes here is higher than average, and it
should be. This is end-to-end encrypted software, so a bug is a security bug even when
it looks like a convenience bug.

## Before you start

Open an issue first for anything larger than a bug fix. A pull request that rewrites
the crypto layer is much easier to shape in a discussion than to salvage afterwards.

## Setup

See [INSTALLING.md](INSTALLING.md). Get the app running there first, then come back.

## The one rule

The server must never learn a message body, a filename, or a key. If a change makes
plaintext reachable from an API route, it does not belong here, no matter how it is
justified.

The relay stores ciphertext under database field names that are random four character
codes generated in `chat/fields.json`. Do not rename them casually. Renaming a field
makes every existing row unreadable, which is the intended failure mode if the names
ever leak.

## Style

Plain names, no comments unless the code genuinely cannot be read without them, and
about four files per folder. There is no linter and no formatter config, so match the
surrounding code instead.

## Tests

There is no test suite in the repo. Verification happens against the MLS working
group's published test vectors, which is the only thing that has ever caught a real
defect in this codebase. If you touch `chat/src/app/mls/`, run them and make sure the
count does not drop.

The vectors live at
`github.com/mlswg/mls-implementations/tree/main/test-vectors`. Suite `0x0001` is the
only one implemented.

Do not add a passing test that only proves the code agrees with itself. Both clients
running the same wrong implementation produce passing tests and a broken protocol,
and that has happened four times in this repository. A test is only worth having if
it checks against bytes someone else produced.

## Commits

One logical change per commit. Write the subject as a plain statement of what changed,
in the imperative, under about seventy characters. Explain why in the body when the why
is not obvious.

Do not push to `main` yourself unless asked. Branch and open a pull request.

## Security

Report vulnerabilities privately to the maintainers rather than through a public
issue. Include the affected version, what an attacker can do, and a reproduction if
you have one.

Assume nobody outside this repository has read the MLS code. The vectors cover a lot
but not all of it, there has never been an interoperability test against another MLS
implementation, and no independent audit has happened. Anything touching key handling,
the tree hash, the secret tree, or message framing deserves extra scrutiny and extra
patience.