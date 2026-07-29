# Install and updates

## The honest state

There is a published release channel for Skarbiec now, and it holds a lineage:
`0.1.0`, `0.1.1` and `0.1.2` for `darwin-arm64`, immutable, retrievable without a
credential, each naming its own coordinate when run. What it does not hold yet is a
copy that is not on one machine, or a second platform. Building from a checkout is
still supported and is what a contributor does.

During the July incident the binary serving the fleet was replaced twice in one
afternoon by different actors, and the only way to tell which build was live was to
ask it for its command list. That is unacceptable for the component every other
component authenticates against, and this document says both what to do now and
what is still missing.

## Installing now, from source

```sh
git clone https://github.com/wisent-ai/skarbiec
cd skarbiec
sh scripts/install.sh
```

`scripts/install.sh` builds a release binary, stages it inside the destination
directory, and moves it into place by rename, so a concurrent process sees the
old binary or the new one and never a half-written file. It then runs the
installed binary and prints the version and provenance it reports, because a stale
install otherwise looks exactly like a fresh one — and because counting the
commands a build answers is the identification this channel exists to replace.

Destination is `$HOME/.stado/bin`, overridable with `SKARBIEC_INSTALL_DIR`. That
prefix is where Stado installs its own binaries and where the fleet's launchers
look.

Requirements at runtime, all invoked as subprocesses: `gpg`, `openssl`, `shasum`.
`oathtool` is optional and only needed for one-time codes.

After installing, two commands, in this order:

```sh
skarbiec key-doctor        # does anything on this machine open the vault
skarbiec recovery-status   # is the recovery secret still sitting next to the owner
```

`key-doctor` is the install check. If it reports `unreadable`, the binary is fine
and the key material is not, and it names the exact key files a restore needs.

## What the release channel has to be

Stado already had the mechanism, correctly shaped. This is the shape Skarbiec now
publishes into.

Objects live at a canonical, immutable coordinate:

```
stado://releases/<product>/<exact-version>/<platform>/<name>
```

served over HTTPS through `/api/release/object`, which is the one publicly
readable route — no bearer, because a released binary is not a secret and an
installer that needs a credential to fetch the credential broker is a
bootstrapping loop. Platforms are `darwin-arm64` and `linux-amd64`. Every
directory carries a `SHA256SUMS` manifest beside the binaries. Writes are
create-if-absent: a coordinate that already holds different bytes is an error,
never an overwrite, so a version means exactly one artifact forever.

The install shape is already written for Stado itself, in
`stado-rs/src/deploy/bootstrap.rs`: detect the platform, fetch each named object
plus the manifest, verify the digests, `chmod`, move into `$HOME/.stado/bin`. The
version and the API origin are bound in by the caller and validated again by the
script; the installer never resolves a "latest" pointer, because an install that
discovers its own version cannot be reproduced.

The product slot already exists. Stado's configuration, both the local and the
Azure deployment, registers Skarbiec in the release publisher map:

```json
"skarbiec": {"item": "skarbiec-release-publisher", "prefix": "skarbiec/"}
```

beside `oko`, `stado`, `trading-autonomy` and `wisent-backend`, and the
authorization model around it is already specified: a dedicated
`stado-release-api-verifier` consumer checks publisher bearers, `PUT` is
create-only with `if_absent`, delete is forbidden, authenticated reads and lists
stay inside the product prefix, and public downloads remain a tokenless `GET`.

So nothing needed designing. The prefix is allocated, the publisher item is named,
the route is built, and three versions are published into it. What the channel
still lacks is durability and a second platform, both listed at the end of this
document.

## What updates have to be

Stado updates itself in `stado-rs/src/self_update.rs`: fetch the manifest for a
pinned version, verify, replace only names that are both published and already
installed, then re-exec so the running process is the new binary rather than the
old one in memory.

Two things block reusing it directly:

**It is hardcoded to one product.** The release URI is built as
`stado://releases/stado/{object_path}`, so the module updates Stado and nothing
else. It needs the product as a parameter before Skarbiec can share it.

**Skarbiec must not update itself while it is the thing being authenticated
against.** A broker that swaps its own binary mid-request changes the answer to
"who am I talking to" without telling anyone. Updates belong to the supervisor
that owns the service: stop the launch agent, replace, start, and confirm with
`key-doctor` before declaring success. `stado service restart` already exists for
exactly this.

## How to publish

```sh
STADO_RELEASE_PLATFORM=darwin-arm64 sh scripts/publish.sh --dry-run
STADO_RELEASE_PLATFORM=darwin-arm64 sh scripts/publish.sh --against <version> --bump
STADO_RELEASE_PLATFORM=darwin-arm64 sh scripts/publish.sh --against <version>
```

`scripts/publish.sh` holds the procedure. What it deliberately does **not** hold is
the rule that decides the version. That rule lives once for the whole fleet, in
[AutoVersion](https://github.com/lbartoszcze/AutoVersion):

```sh
pip install "git+https://github.com/lbartoszcze/AutoVersion@v0.1.0"
```

and is called as `autoversion decide`. The script supplies only the two things this
repository alone knows — the surface of the build already on the channel and the
surface of the candidate — and obeys the answer. A copy of the rule inside this
repository would be a second policy, free to drift from every other product's.

The platform string is not invented; it reads
`STADO_RELEASE_PLATFORM`, the same key Stado publishes its own releases under, so
the two can never disagree about what a platform is called.

`--dry-run` publishes nothing. It prints the coordinate it would write and *every*
guard that would refuse a real run, not merely the first, so what blocks a publish
is learned in one invocation rather than one refusal at a time.

What the publish guarantees, in order:

- The release coordinate is compiled into the binary, so `skarbiec version`
  reports it afterwards. This is the answer to identifying builds by counting
  their commands.
- `SHA256SUMS` is written next to the binary and covers the exact bytes uploaded.
- The build is **refused** if it cannot report the coordinate it was built for. A
  released artifact with no provenance is the defect this path removes, so the
  script would rather publish nothing.
- Both objects go up create-only. The `releases` namespace enforces that with or
  without `--if-absent`, so re-publishing a version fails instead of quietly
  replacing what the fleet already installed.

A version is therefore one artifact, forever, and every installed copy can name
its own origin.

## Versioning

A version is not a label on a moving target. It is the middle segment of the
coordinate, and it selects exactly one set of bytes for as long as the store
exists.

**Where the number comes from.** `Cargo.toml`, read once by the publish script.
There is one place to change it, and the binary's own `version` output cannot
disagree with the coordinate it was published at, because both are derived from
that read.

**Which number, decided rather than remembered.** `autoversion decide` compares the
published build's advertised commands with the candidate's and derives the only
version the release may carry. Both sides are surface documents — exactly
`{"surface": ["name", ...]}`, sorted and unique — reshaped from what each binary's
`help` prints:

```sh
./target/release/skarbiec help | jq '{surface: (.commands | unique)}' > candidate.json

autoversion decide --current <published> \
  --published-surface released-surface.json \
  --candidate-surface candidate.json --json
```

Anything removed is `breaking`, anything added is `additive`, an identical surface
is `internal`. `--breaking` declares breakage the command list cannot show — a
field dropped from a payload, a stored format changed — and can only escalate the
classification, never lower it. The mapping onto slots depends on the current
version, because while major is zero Cargo puts the compatibility boundary in the
minor slot: against the published `0.1.2`, `breaking` gives `0.2.0`, while
`additive` and `internal` both give `0.1.3`, since a `0.x` crate has no third slot
to separate them.

**Nobody types a version.** `sh scripts/publish.sh --against <published-version>
--bump` runs the comparison, writes the derived number into `Cargo.toml`, and
stops:

```
change:   internal against 0.1.2
Cargo.toml: 0.1.2 -> 0.1.3
```

The commit is left to the operator deliberately, not as a missing feature: a
published coordinate has to resolve to a revision that is already pushed, which is
the same guard that refuses a dirty tree. So the number is derived mechanically and
the decision to release stays deliberate.

Without `--bump`, the same comparison runs as a check and refuses to publish under
any other number. Without `--against` the classification is skipped and says so,
rather than passing quietly. The predecessor is fetched off the channel, which
works because release downloads need no credentials.

**The baseline is recovered, not remembered.** `released-surface.json` records the
surface of the version the channel currently serves, beside a marker naming where
that record came from — `stado:releases/skarbiec/<version>/<platform>/skarbiec` —
and it is regenerated by downloading that artifact and asking it for its own
command list, never written by hand. The publish script checks all of it: that the
marker names a coordinate the channel actually lists, that the version recorded is
the newest published one, and that the recorded surface equals what the artifact
advertises. A baseline that lags the channel, or that was typed in, would make
every later comparison measure against something nobody installed.

**Only advertised commands count.** The surface is what `help` lists. A command
that dispatches but is unlisted is private, and nothing may be told to depend on
it. That is not a technicality: `version` shipped dispatchable but unadvertised,
the docs pointed at it anyway, and the classifier is what noticed.

**Nothing resolves "newest" for you.** Stado deliberately has no mutable channel
pointer: `self_update` documents "no mutable channel pointer, bucket fallback, or
provider credential path", and the `latest.json` machinery survives only under
`#[cfg(test)]`. Production consumers configure an exact version and platform,
validated as coordinates that are non-empty, free of surrounding whitespace, and
restricted in charset. An install
that discovers its own version cannot be reproduced, so it is not offered.

**Ordering exists, but only for comparison.** `version_tuple` splits on `.` and
`-`, parses numeric tokens as integers, and compares as a tuple, so a prefix sorts
before its extension. That is used to answer "is the configured version newer than
the installed one", never to pick a version on the operator's behalf.

**A version cannot be reused.** Attempting to republish one fails:

```
Error: stado://releases/skarbiec/<version>/<platform>/skarbiec already exists;
release objects are immutable
```

Changed code therefore requires a new version. This is not a convention that can
be forgotten under pressure; it is the store refusing.

**A version identifies code, not just bytes.** `skarbiec version` reports the
source commit beside the coordinate, and publishing refuses a tree with
uncommitted changes or a `HEAD` that is not an ancestor of `origin/main`. Without
those two refusals a coordinate would be permanently bound to a working copy that
stopped existing when the shell exited.

One exception, stated rather than hidden: `0.1.0` predates the commit stamp and
reports `"commit": null`, reproducible only through the repository history around
its publish time. `0.1.1` was the first version derived and stamped mechanically,
and every version after it carries its revision — `0.1.2`, the version the channel
currently serves, reports its own commit when asked.

## The bootstrapping loop, and where it does not apply

Publishing through the **remote** release route requires a create-only publisher
bearer. That credential is the vault item `skarbiec-release-publisher`, so
publishing Skarbiec that way requires Skarbiec.

That loop does not bind here, and it is worth being exact about why, because the
earlier draft of this document was wrong: `storage put` only consults
`RemoteObjectApi` when a remote origin is configured. Nothing configures one on
this host — `release.api_url` is unset — so the write goes to the configured
backend, which is the local store. No bearer is read, and the vault is never
opened. Immutability is not lost in that fallback: create-only is enforced by
`upload_file_if_absent`, so a version is still one artifact forever.

So the first publish needed neither the cloud nor the credential, and it has
happened. What the loop still governs:

- Publishing through a remote origin, once one is configured, needs the bearer
  recoverable **without** the vault — its own offline copy, held the way recovery
  material is supposed to be held and currently is not.
- The install route stays bearer-free either way, so a machine with no credentials
  at all can still fetch a verified binary.

`sh scripts/publish.sh` performs the publish. It is a script an operator runs
rather than a workflow because CI has no store to write to and no bearer to write
with; the operator's host has the store.

## What is missing, concretely

The channel holds a lineage now, not a single artifact. `0.1.0`, `0.1.1` and
`0.1.2` for `darwin-arm64` are published, listed, immutable, retrievable without a
bearer, and each reports its own coordinate when run. `0.1.1` and `0.1.2` also
report the commit they were built from, and their numbers were derived from the
surface change rather than chosen; `0.1.2` is the version the channel currently
serves. That settles which of the three candidates is canonical:

| Candidate | Standing |
| --- | --- |
| `stado://releases/skarbiec/<version>/darwin-arm64/` | **Canonical.** Immutable coordinates, a checksum manifest beside each, bearer-free download, and the binary names its own coordinate and revision when asked. |
| `skarbiec-bin-latest` on `lbartoszcze/entitlements-rotator` | Superseded. A **rolling** tag, so the coordinate is mutable and a version means nothing; built from the vendored lineage that no longer exists; asset named `skarbiec-entitlements-router`; download count zero. |
| `~/.stado/bin/skarbiec` | Superseded. A hand build on one laptop, replaced twice in one afternoon by different actors during the July incident. It can now be checked against the channel instead of guessed at. |

What is still missing:

- **A published copy that is not on one machine.** The local store is the
  operator's disk. The coordinate is right and the immutability is real, but the
  durability is one laptop until the store is mirrored — `storage backup` and
  `storage copy` exist for exactly that, and the backup backend is unset.
- **A second platform.** Only `darwin-arm64` exists. `linux-amd64` needs a build
  on that platform; the script takes the platform from configuration rather than
  guessing, so it is one invocation there.
- **CI wiring.** Nothing calls the publish on a push. A runner would need a store
  it can write to, which today means the remote route and therefore the bearer
  from the bootstrapping loop above.
- `self_update` taking a product parameter instead of a hardcoded one. It builds
  `stado://releases/stado/...` today, so it cannot update this product at all.
- Install verification in `stado doctor`, so a stale broker binary is a failed
  probe rather than a discovery made during an outage.
