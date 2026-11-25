# Publishing the source

The public repository is a copy of the development repository's `main`, made by `tools/export-public.mjs` from exactly the files that `public-manifest.json` names. Each publication is one commit of the public repository, and `CHANGELOG.md` says what each one brings. The development history is never published.

This is what the maintainer does for each publication. The examples use the date 25 November 2026.

## 1. The changelog section first

Before anything is exported, add the new section at the top of `CHANGELOG.md` and merge it into `main` by the ordinary review (`CONTRIBUTING.md`).

- Its heading is `## 25 November 2026: <one line>`: the UTC date of the public commit, and what the publication brings.
- Build it from `git log --first-parent publication-<last date>..HEAD` and `git log --stat publication-<last date>..HEAD` (step 5 sets that tag).
- Only what is published goes in: leave out a change whose files the manifest withholds or does not name.
- Group the entries as the earlier sections do. Each says what changed for a user or an operator, names the file to read, carries **Stored format** or **Rule change** where one applies, and says so where something ran only in tests.
- It names no commit of the development repository, no person, branch, machine, cloud resource or run, no address, and no cost.

## 2. Export

From a clean checkout of `main` at the commit to publish, once `node tools/ci-checks.mjs --all` passes:

```sh
node tools/export-public.mjs --out ../publication-2026-11-25 --forbid-file ../forbid.txt
```

`--out` is a new or empty directory outside the repository. `--forbid-file` is a file kept outside every repository, one string per line, that no published file may contain in any letter case: the names, handles and email addresses of the people who work on the project, the names of their companies, the user names and host names of their machines, cloud account numbers, and any other name that must stay private.

The export copies nothing unless every file passes, and exits with 0 only then. It refuses:

- a file the manifest names that is missing, is a symbolic link or has more than one link;
- a file git tracks that the manifest neither publishes nor withholds;
- a private key or another PEM block (unless the manifest lists the file as a key fixture), an AWS access key or secret key;
- twelve digits standing alone, which could be a cloud account number, unless the manifest allowlists the value with a reason;
- an email address, except the names reserved for examples and the third-party licence text whose hash the manifest records;
- a path inside someone's user folder (`C:\Users\<name>`, `/Users/<name>/`, `/home/<name>/`);
- a blank left for the owner to fill in;
- a JSON field named like a credential that holds a value, and a file name that looks secret (`.env`, `*.pem`, `*.key`, names with `private`, `secret` or `seed`);
- any string of the forbid file.

Fix the file or the manifest, never the scan, and export again into a new directory. `--skip-refused` makes a copy marked `EXPORT-INCOMPLETE.txt`: it is for looking at, never for publishing. The scan does not know everything: read the new changelog section and the changes of step 3 once more for names, machines, addresses, commits of the development repository and costs.

## 3. The public commit

In a fresh clone of the public repository, replace the whole tree with the export, so that a file the manifest no longer names is deleted too:

```sh
git clone <public repository> public && cd public
git config core.autocrlf false
git rm -r -q .
cp -R ../publication-2026-11-25/. .
git add -A
git status --short    # every change must be one the changelog section explains
```

The message, in a file outside the clone (`../message.txt`):

```text
Publication of 25 November 2026: <the one line of the changelog heading>

<A group heading of the changelog section>
- <its main items, one per line>

<The next group heading>
- ...
```

Nothing else: no commit of the development repository, no name of a person, a branch, a machine or a tool, and no trailer line (`Co-authored-by:`, `Signed-off-by:`).

The author and the committer are "The Time Network authors", whose address is `noreply` at `thetimenetwork.org`, and both dates are in UTC. Do not sign the commit with a personal key.

```sh
domain=thetimenetwork.org    # the address is put together here: the export refuses an email address written out
when="$(date -u +%s) +0000"
GIT_AUTHOR_NAME='The Time Network authors' GIT_AUTHOR_EMAIL="noreply@$domain" GIT_AUTHOR_DATE="$when" \
GIT_COMMITTER_NAME='The Time Network authors' GIT_COMMITTER_EMAIL="noreply@$domain" GIT_COMMITTER_DATE="$when" \
git -c commit.gpgsign=false commit -q -F ../message.txt
git log -1 --format='%an <%ae> %ad%n%cn <%ce> %cd' --date=iso-strict
```

## 4. Push

```sh
git log --oneline    # the earlier publications and this one, nothing else
git push origin main
```

Push only from the clone of the public repository. Never add the public repository as a remote of the development repository, and never push a branch or a tag of the development repository to it: its history holds what this procedure keeps out. The host shows which account pushed; the commit itself names nobody. Then watch the public repository's continuous integration, which builds and tests the published tree alone.

## 5. Afterwards

- Tag the exported commit in the development repository, and only there: `git tag -a publication-2026-11-25 -m "Published on 25 November 2026"`. The next changelog section starts from it.
- Delete the export and the clone. Keep the forbid file outside every repository.
