# Install and updates

## The honest state

There is no published release channel for Skarbiec. Installation today means
building from a checkout and replacing a file by hand, and updates mean somebody
remembering to do it again. During the July incident the binary serving the fleet
was replaced twice in one afternoon by different actors, and the only way to tell
which build was live was to ask it for its command list.

That is unacceptable for the component every other component authenticates
against, and this document says both what to do now and what has to be built.

## Installing now, from source

```sh
git clone https://github.com/wisent-ai/skarbiec
cd skarbiec
sh scripts/install.sh
```

`scripts/install.sh` builds a release binary, stages it inside the destination
directory, and moves it into place by rename, so a concurrent process sees the
old binary or the new one and never a half-written file. It then runs the
installed binary and prints how many commands it answers, because a stale
install otherwise looks exactly like a fresh one.

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

Stado already has the mechanism, correctly shaped, and Skarbiec is not using it.

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

So nothing needs designing. The prefix is allocated, the publisher item is named,
the route is built. What is missing is that **nothing has ever been published
into it**, and the grant that would authorize the publish is an item in the
vault.

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
STADO_RELEASE_PLATFORM=darwin-arm64 sh scripts/publish.sh --dry-run   # coordinates only
STADO_RELEASE_PLATFORM=darwin-arm64 sh scripts/publish.sh             # build and publish
```

The platform string is not invented by the script; it reads
`STADO_RELEASE_PLATFORM`, the same key Stado publishes its own releases under, so
the two can never disagree about what a platform is called.

What the script guarantees, in order:

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

## The bootstrapping loop, stated plainly

Publishing a release requires a create-only publisher credential. That credential
lives in Skarbiec. So publishing Skarbiec requires Skarbiec.

This is survivable but it has to be deliberate:

- The publisher credential must be recoverable **without** the vault — its own
  offline copy, held the way recovery material is supposed to be held and is
  currently not.
- The install route stays bearer-free, so a machine with no credentials at all
  can still fetch a verified binary.
- The first publish after a vault loss is therefore a manual, documented
  ceremony, not an automated pipeline.

`scripts/publish.sh` performs that ceremony. It is a script and not a workflow
precisely because the first publish cannot be automated: the credential it needs
is in the vault it is publishing.

## What is missing, concretely

- **A publish. Any publish.** The `skarbiec/` prefix is allocated and empty. No
  version of this binary has ever reached the channel the fleet is supposed to
  install from, which is why three impostors currently compete to be the
  canonical build:

  | Candidate | Why it is not canonical |
  | --- | --- |
  | `skarbiec-bin-latest` on `lbartoszcze/entitlements-rotator` | A **rolling** tag, so the coordinate is mutable and a version means nothing. Built from the vendored lineage that no longer exists, its asset is named `skarbiec-entitlements-router`, and its download count is zero — nothing ever consumed it. |
  | `stado://releases/skarbiec/...` | Correct in every respect and **empty**. |
  | `~/.stado/bin/skarbiec` | A hand build on one laptop, replaced twice in one afternoon by different actors during the July incident, identifiable only by asking it for its command list. |

- **CI wiring.** `scripts/publish.sh` is the mechanism and it is exercised, but
  nothing calls it on a push. A runner would need `stado` installed and holding
  the `skarbiec-release-publisher` grant — which is the bootstrapping loop above,
  not a missing script. Wire it once the grant has an offline copy.
- `self_update` taking a product parameter instead of a hardcoded one. It builds
  `stado://releases/stado/...` today, so it cannot update this product at all.
- Install verification in `stado doctor`, so a stale broker binary is a failed
  probe rather than a discovery made during an outage.
