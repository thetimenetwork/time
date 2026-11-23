# Security policy

## Do not use this software with real value

- The network has not launched.
- The node accepts development chains only (`time-devnet-v4-` chain ids) and every binary reports `publicLaunchAllowed=false`.
- The code has had internal reviews (`AUDIT-2026-11.md`). It has had **no external audit**.
- Nothing in this repository holds real value, and nothing built from it should.

The open points that must be closed before any launch with real value are listed at the end of `AUDIT-2026-11.md`.

## Reporting a vulnerability

Report it privately. Do not open a public issue, pull request or discussion for it, and do not post it in a chat room.

Send the report through the repository's private vulnerability reporting form (on GitHub: the Security tab, then Report a vulnerability). Only the maintainers can read it.

### What to include

- The component: engine (`v5/`), staking (`pos/`), verifier (`verifier-v4/`), SDK or gateway (`client-v4/`), wallet (`web-v4/`), deployment kit (`deploy/`), tools.
- The commit you tested.
- What an attacker can do: take or create currency, forge a proof or a balance, halt or slow a network, read a key, pass as someone else.
- The steps to reproduce it. A failing test or a short script is best.
- What the attacker needs: a validator key, a share of the stake, a place on the network path, a user's click.
- Whether anyone else knows about it.

Do not test against a network or a machine you do not run yourself. A local network is enough to show almost every problem (see `README.md`).

### What to expect

- An acknowledgement within **3 working days**.
- A first assessment within **10 working days**: whether we can reproduce it, and how serious we think it is.
- We keep you informed while we work on a fix, and we tell you before we publish it.
- We name you in the published note if you want that.
- No reward is promised.

Please give us time to fix the problem before you publish it. We suggest 90 days from the acknowledgement, or sooner if we both agree.

## Scope

In scope: everything in this repository that takes part in a network or handles keys.

Out of scope:

- Third-party software. Report it to its authors; tell us too if it affects this project. The dependencies are listed in `THIRD-PARTY-LICENSES.md`.
- The limits already written down in `AUDIT-2026-11.md`, `v5/README.md` ("Known limits") and `deploy/README.md`. A new way to exploit one of them is in scope.
- Networks run by other people.

## Supported versions

There are no supported releases yet. Reports are judged against the newest commit of the main branch.
