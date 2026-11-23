# Governance

This describes how the project is run today. It is a small project and the rules are short. They will change when more people maintain it; a change to this file is made the same way as any other change.

## Who decides today

One maintainer decides what is merged and what is released: the maintainer of the `thetimenetwork` organization on GitHub.

The maintainer:

- merges changes, after the review described in `CONTRIBUTING.md`;
- accepts or declines protocol changes;
- makes releases;
- handles security reports (`SECURITY.md`);
- owns the project name and logo, which are trademarks and are not covered by the software licence (`NOTICE`).

The software is under the Apache License 2.0. Anyone may fork it and run a network with it under another name. Nobody needs the maintainer's permission for that.

## What the maintainer does not decide

No network has launched. When one does, its rules are the rules of the software its validators run. The maintainer cannot change a running network: every validator of a network must run the same engine, and each operator chooses what it runs.

## How a protocol change is proposed

A protocol change is any change to what a node accepts or computes: ledger rules, staking, fees, issuance, the genesis format, the encoding of state or of proofs, and what the light client accepts.

1. **Write the design first.** Open an issue with a written design before writing the code. It says:
   - what problem it solves, and for whom;
   - the exact new rule, precise enough to implement twice and get the same bytes;
   - what happens to existing networks: whether the change needs a new network or an activation height, and what a node that does not have it does;
   - what an attacker gains or loses, and what was considered and rejected;
   - how it will be tested.
2. **Independent review.** Someone other than the author reviews the design, and later the code, and writes down what they found. The author does not review their own change.
3. **Decision.** The maintainer accepts or declines in the issue, with the reasons.
4. **Implementation.** Code and tests follow the accepted design. If the code has to differ from the design, the design is updated first.
5. **Release.** A change of consensus rules ships in a new engine version. The deployment kit never upgrades a running network in place (`deploy/README.md`).

Changes that are not protocol changes (documentation, tools, tests, wallet screens, performance work that leaves every result byte for byte the same) follow the ordinary review in `CONTRIBUTING.md`.

## Maintainers

- A maintainer is added after at least three months of reviewed contributions, by the decision of the maintainers, and is named in this file.
- A maintainer is removed after a year without activity, or for a breach of the code of conduct, the same way.

## The name

The name "Time" and its logo are held by the Time Network maintainers (`NOTICE`). Anyone may use them to say where the software comes from. A modified version, or a network run with this software, must not present itself as the original project.
