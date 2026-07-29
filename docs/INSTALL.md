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

Skarbiec needs the same thing under product `skarbiec`, publishing `skarbiec` and
`SHA256SUMS`.

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

Until that credential is arranged, `scripts/install.sh` is the supported path and
this document should not pretend otherwise.

## What is missing, concretely

- A publish workflow in this repository, targeting
  `stado://releases/skarbiec/<version>/<platform>/`, emitting `skarbiec` and
  `SHA256SUMS`. Not added yet: the repository's CI cannot start at all right now,
  and the publisher credential is inside the vault it would publish.
- `self_update` taking a product parameter instead of a hardcoded one.
- A version the fleet can compare. `skarbiec help` lists commands, which is why
  the installer counts them, but a build carries no version string a supervisor
  can check. `--version` reporting the crate version and the release coordinate
  it came from would end the guessing that this incident ran on.
- Install verification in `stado doctor`, so a stale broker binary is a failed
  probe rather than a discovery made during an outage.
