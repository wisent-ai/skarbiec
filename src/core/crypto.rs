// Cryptographic operations for the skarbiec vault, delegated to vetted local
// tools — never hand-rolled:
//   gpg     : per-recipient public-key authenticated encryption + key material
//   openssl : entropy (random tokens)
//   shasum  : hashing (audit chain, breach k-anonymity)
//   oathtool: optional time-based one-time codes
// The per-recipient model (encrypt to each recipient's public key) is the same
// shape 1Password/Bitwarden use for sharing.

use anyhow::{bail, Context, Result};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Condvar, LazyLock, Mutex};
use std::time::Duration;
use wait_timeout::ChildExt;

const DEFAULT_CRYPTO_LIMIT: usize = 8;
const DEFAULT_GPG_LIMIT: usize = 2;
const DEFAULT_CRYPTO_TIMEOUT_SECONDS: u64 = 30;

struct ExecutionLimit {
    active: Mutex<usize>,
    available: Condvar,
    maximum: usize,
}

impl ExecutionLimit {
    fn acquire(&self) -> ExecutionPermit<'_> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active >= self.maximum {
            active = self
                .available
                .wait(active)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *active += 1;
        ExecutionPermit { limit: self }
    }

    /// Take the whole limit, so that nothing holding it can be running while
    /// this permit lives.
    ///
    /// Recovering the GnuPG daemons is not an operation on this process: it
    /// kills and relaunches host daemons that every concurrent `gpg` child is
    /// already talking to over a socket. Doing that beside a live decryption
    /// takes that child's agent away mid-operation, and the child reports the
    /// lost socket -- `gpg: public key decryption failed: Broken pipe` -- to a
    /// caller that asked for nothing but a credential read. That is how one
    /// slow read turned into `503 infra_down` for a release publisher, a
    /// capability broker and an agent reading the same vault at once. The
    /// recovery now waits for the gpg capacity to drain instead.
    fn acquire_exclusive(&self) -> ExclusivePermit<'_> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active > 0 {
            active = self
                .available
                .wait(active)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *active = self.maximum;
        ExclusivePermit { limit: self }
    }

    fn in_use(&self) -> usize {
        *self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct ExecutionPermit<'a> {
    limit: &'a ExecutionLimit,
}

impl Drop for ExecutionPermit<'_> {
    fn drop(&mut self) {
        let mut active = self
            .limit
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = active.saturating_sub(1);
        // Every waiter, not one: an exclusive waiter only proceeds once the
        // count reaches zero, and waking a single ordinary waiter instead can
        // leave it parked behind capacity it would never be told about.
        self.limit.available.notify_all();
    }
}

struct ExclusivePermit<'a> {
    limit: &'a ExecutionLimit,
}

impl Drop for ExclusivePermit<'_> {
    fn drop(&mut self) {
        let mut active = self
            .limit
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = 0;
        self.limit.available.notify_all();
    }
}

static CRYPTO_LIMIT: LazyLock<ExecutionLimit> = LazyLock::new(|| ExecutionLimit {
    active: Mutex::new(0),
    available: Condvar::new(),
    maximum: configured_limit("SKARBIEC_CRYPTO_CONCURRENCY", DEFAULT_CRYPTO_LIMIT),
});
static GPG_LIMIT: LazyLock<ExecutionLimit> = LazyLock::new(|| ExecutionLimit {
    active: Mutex::new(0),
    available: Condvar::new(),
    maximum: configured_limit("SKARBIEC_GPG_CONCURRENCY", DEFAULT_GPG_LIMIT),
});
static GPG_RECOVERY_GENERATION: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));
static CRYPTO_PROGRAMS: LazyLock<HashMap<&'static str, PathBuf>> = LazyLock::new(|| {
    ["gpg", "gpgconf", "openssl", "shasum", "oathtool", "pkill"]
        .into_iter()
        .map(|program| (program, resolve_program_path(program)))
        .collect()
});

fn resolve_program_path(program: &str) -> PathBuf {
    let from_environment = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default();
    let home_local = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".local/bin"));
    let fallbacks = [
        Some(PathBuf::from("/opt/homebrew/bin")),
        Some(PathBuf::from("/usr/local/MacGPG2/bin")),
        Some(PathBuf::from("/home/linuxbrew/.linuxbrew/bin")),
        Some(PathBuf::from("/usr/local/bin")),
        home_local,
        Some(PathBuf::from("/usr/bin")),
        Some(PathBuf::from("/bin")),
    ];
    from_environment
        .into_iter()
        .chain(fallbacks.into_iter().flatten())
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| PathBuf::from(program))
}

fn crypto_program(program: &str) -> Cow<'_, Path> {
    CRYPTO_PROGRAMS
        .get(program)
        .map(|path| Cow::Borrowed(path.as_path()))
        .unwrap_or_else(|| Cow::Borrowed(Path::new(program)))
}

fn configured_limit(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn execution_timeout() -> Duration {
    let seconds = std::env::var("SKARBIEC_CRYPTO_TIMEOUT_SECONDS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_CRYPTO_TIMEOUT_SECONDS);
    Duration::from_secs(seconds)
}

// One bounded subprocess seam for every cryptographic tool. Output pipes are
// drained concurrently, every child has a deadline, and timed-out children are
// killed and reaped before capacity is returned to another request. A recoverable
// gpg daemon failure gets one serialized daemon recovery and one retry.
fn run(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let recovery_generation = (program == "gpg").then(|| {
        *GPG_RECOVERY_GENERATION
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    });
    let first = run_once(program, args, input);
    let Err(first_error) = first else {
        return first;
    };
    if program != "gpg" || !recoverable_gpg_failure(&first_error.to_string()) {
        return Err(first_error);
    }

    let mut current_generation = GPG_RECOVERY_GENERATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if recovery_generation == Some(*current_generation) {
        // Drain the gpg capacity first. `recover_gpg_daemons` kills daemons
        // that any concurrent `gpg` child holds an open socket to, so running
        // it beside a live decryption is what produced the reported
        // `gpg: public key decryption failed: Broken pipe`.
        //
        // The generation then advances because recovery was ATTEMPTED, not
        // because it reported success. On 2026-09-03 a wedged keyboxd on the
        // always-on Mac made `gpgconf --launch` time out, this call returned
        // the error, and `?` propagated it without retrying — so every later
        // read repeated the identical failing sequence and a 641-item vault
        // answered 503 until a person intervened. A recovery that cannot
        // complete must still let the next request try something else.
        let recovery = {
            let _exclusive = GPG_LIMIT.acquire_exclusive();
            recover_gpg_daemons()
        };
        *current_generation = current_generation.wrapping_add(1);
        drop(current_generation);
        if let Err(error) = recovery {
            return run_once(program, args, input).with_context(|| {
                format!(
                    "gpg retry after incomplete daemon recovery ({error:#}); initial error: \
                     {first_error}"
                )
            });
        }
    } else {
        drop(current_generation);
    }
    run_once(program, args, input).with_context(|| {
        format!("gpg retry failed after daemon recovery; initial error: {first_error}")
    })
}

/// Failures where killing and relaunching the GnuPG daemons is worth one retry.
///
/// The daemon-lost shapes matter as much as the daemon-missing ones. When
/// `gpg-agent` or `keyboxd` goes away while a child is mid-operation, the
/// child does not report a key problem: it reports the socket it lost, as
/// `Broken pipe`, `End of file` or `IPC connect call failed`. Those were not
/// listed, so the one failure this recovery exists for -- a daemon that died
/// under a live read -- was the one failure that never got recovered, and left
/// instead as `503 infra_down` for the caller to read as unreachable
/// infrastructure.
fn recoverable_gpg_failure(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    [
        "gpg timed out",
        "keyboxd",
        "keybox daemon",
        "no keybox daemon running",
        "resource temporarily unavailable",
        "too many open files",
        "broken pipe",
        "end of file",
        "ipc connect call failed",
    ]
    .iter()
    .any(|needle| detail.contains(needle))
}

/// Put the gpg daemons back into a state a fresh `gpg` can use.
///
/// `gpgconf` is asked first because it is the supported control surface, and
/// it is not trusted to answer: a keyboxd stuck mid-request makes both
/// `--kill` and `--launch` hit this seam's deadline, which is how one wedged
/// daemon took a vault of 641 items offline. So every `gpgconf` call is
/// best-effort and the escalation below signals the daemons directly.
///
/// Nothing is launched at the end on purpose. `gpg` starts `gpg-agent` and
/// `keyboxd` on demand, so a kill is a complete repair, while waiting on
/// `--launch` reintroduces exactly the timeout this escalation exists to get
/// past. The error case is narrow by design: it means neither control surface
/// could even be spawned.
fn recover_gpg_daemons() -> Result<()> {
    let _ = run_once("gpgconf", &["--kill", "keyboxd"], None);
    let _ = run_once("gpgconf", &["--kill", "gpg-agent"], None);
    let mut escalation_errors = Vec::new();
    let mut signalled = false;
    for signal in ["-TERM", "-KILL"] {
        for daemon in ["keyboxd", "gpg-agent", "scdaemon"] {
            // `pkill` exits 1 when nothing matched, which is the common case
            // and not a failure: the daemon this call was meant to remove is
            // already gone. No `-u` filter is needed and none is passed —
            // an unprivileged process cannot signal another account's
            // daemons, so the kernel is the filter.
            match run_once("pkill", &[signal, "-x", daemon], None) {
                Ok(_) => signalled = true,
                Err(error) => {
                    let detail = error.to_string();
                    if detail.contains("spawn pkill") || detail.contains("timed out") {
                        escalation_errors.push(format!("{daemon} {signal}: {detail}"));
                    } else {
                        signalled = true;
                    }
                }
            }
        }
    }
    let _ = run_once("gpgconf", &["--launch", "keyboxd"], None);
    if signalled || escalation_errors.is_empty() {
        return Ok(());
    }
    bail!(
        "no gpg daemon control surface answered ({})",
        escalation_errors.join("; ")
    )
}

fn run_once(program: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let _capacity = CRYPTO_LIMIT.acquire();
    let _gpg_capacity = (program == "gpg").then(|| GPG_LIMIT.acquire());
    let mut child = Command::new(crypto_program(program).as_ref())
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {program}"))?;

    let input = input.map(str::as_bytes).map(Vec::from);
    let stdin = child.stdin.take();
    let input_writer = std::thread::spawn(move || -> std::io::Result<()> {
        if let (Some(mut stdin), Some(input)) = (stdin, input) {
            stdin.write_all(&input)?;
        }
        Ok(())
    });
    let mut stdout = child.stdout.take().context("child stdout unavailable")?;
    let stdout_reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    let mut stderr = child.stderr.take().context("child stderr unavailable")?;
    let stderr_reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes)?;
        Ok(bytes)
    });

    let status = match child.wait_timeout(execution_timeout())? {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} timed out");
        }
    };
    let written = input_writer
        .join()
        .map_err(|_| anyhow::anyhow!("{program} stdin writer panicked"))?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{program} stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{program} stderr reader panicked"))??;
    // A child that failed explains itself; the broken stdin pipe is only the
    // consequence of it having stopped reading. Reporting the write error
    // first replaced every such diagnosis with a bare `Broken pipe`, which
    // told the operator nothing and hid the very text
    // `recoverable_gpg_failure` classifies on -- so the retry could not fire
    // either.
    if !status.success() {
        let said = String::from_utf8_lossy(&stderr).trim().to_owned();
        if said.is_empty() {
            return match written {
                Err(error) => Err(anyhow::anyhow!(
                    "{program} failed ({status}) and stopped reading stdin: {error}"
                )),
                Ok(()) => Err(anyhow::anyhow!(
                    "{program} failed ({status}) without output"
                )),
            };
        }
        bail!("{program} failed: {said}");
    }
    written.with_context(|| format!("write {program} stdin"))?;
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

fn run_opt(program: &str, args: &[&str], input: Option<&str>) -> Option<String> {
    run(program, args, input).ok()
}

/// Put the GnuPG daemons back into a usable state on demand.
///
/// The same repair [`run`] performs after a recoverable failure, reachable
/// without one. A long-lived reader — the HTTP server, a browser host, an
/// agent — holds no gpg state of its own, so a keyboxd that wedges under it
/// is repaired for every one of them by the next `gpg` finding fresh daemons.
/// Before this existed the only way to clear that was an inline `gpgconf`
/// nobody could re-run or audit, or restarting the service and its keychain
/// unlock with it.
///
/// The gpg capacity is drained first for the reason
/// [`ExecutionLimit::acquire_exclusive`] gives: killing daemons beside a live
/// decryption is what reports `Broken pipe` to a caller that asked for a
/// credential.
pub fn recover_daemons() -> Result<()> {
    let _exclusive = GPG_LIMIT.acquire_exclusive();
    recover_gpg_daemons()
}

pub fn executor_status() -> (usize, usize, usize, usize) {
    (
        CRYPTO_LIMIT.in_use(),
        CRYPTO_LIMIT.maximum,
        GPG_LIMIT.in_use(),
        GPG_LIMIT.maximum,
    )
}
pub fn clearsign(signer: &str, payload: &str) -> Result<String> {
    run(
        "gpg",
        &[
            "--batch",
            "--yes",
            "--armor",
            "--local-user",
            signer,
            "--clearsign",
        ],
        Some(payload),
    )
}

pub fn verify_clearsigned(signed: &str) -> Result<String> {
    run("gpg", &["--batch", "--yes", "--decrypt"], Some(signed))
}

/// High-entropy random token (hex). Used for consumer service tokens.
pub fn random_token() -> Result<String> {
    Ok(run("openssl", &["rand", "-hex", "32"], None)?
        .trim()
        .to_string())
}

/// Hex SHA-256 of the input. Used by the tamper-evident audit chain and the
/// breach k-anonymity check.
pub fn sha256_hex(input: &str) -> Result<String> {
    let out = run("shasum", &["-a", "256", "-"], Some(input))?;
    out.split_whitespace()
        .next()
        .map(str::to_string)
        .context("empty sha256 output")
}

/// SHA-1 (uppercase hex) — required only for the HaveIBeenPwned range API, which
/// is defined over SHA-1 password hashes. Not used for any security decision.
pub fn sha1_hex_upper(input: &str) -> Result<String> {
    let out = run("shasum", &["-a", "1", "-"], Some(input))?;
    out.split_whitespace()
        .next()
        .map(|h| h.to_uppercase())
        .context("empty sha1 output")
}

/// Encrypt plaintext to every recipient's public key (armored). Any recipient
/// (or the recovery key) can later decrypt. This is how sharing works: add a
/// recipient and the item re-encrypts to include them.
pub fn encrypt_to(recipients: &[String], plaintext: &str) -> Result<String> {
    if recipients.is_empty() {
        bail!("refusing to encrypt with no recipients");
    }
    let mut args: Vec<String> = vec![
        "--batch".into(),
        "--yes".into(),
        "--armor".into(),
        "--trust-model".into(),
        "always".into(),
        "--encrypt".into(),
    ];
    for recipient in recipients {
        args.push("--recipient".into());
        args.push(recipient.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run("gpg", &refs, Some(plaintext))
}

/// Decrypt using whatever private key in the local keyring applies (gpg-agent).
/// A protected vault can receive its unlock phrase through `SKARBIEC_UNLOCK`
/// for a single invocation, an owner-only file named by
/// `SKARBIEC_UNLOCK_FILE`, or the persistent service default
/// `$HOME/.stado/skarbiec-unlock`. The phrase is handed to gpg over stdin,
/// never argv. With no phrase, an unprotected key decrypts normally while a
/// protected key fails without opening an interactive prompt.
fn unlock_phrase() -> Result<Option<String>> {
    if let Ok(phrase) = std::env::var("SKARBIEC_UNLOCK") {
        if !phrase.is_empty() {
            return Ok(Some(phrase));
        }
    }
    let path = match std::env::var("SKARBIEC_UNLOCK_FILE") {
        Ok(path) if !path.trim().is_empty() => std::path::PathBuf::from(path),
        _ => {
            let Some(home) = std::env::var_os("HOME") else {
                return Ok(None);
            };
            let candidate = std::path::PathBuf::from(home)
                .join(".stado")
                .join("skarbiec-unlock");
            if !candidate.is_file() {
                return Ok(None);
            }
            candidate
        }
    };
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("inspect Skarbiec unlock file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!(
                "Skarbiec unlock file {} must be a regular file",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("Skarbiec unlock file {} must be mode 0600", path.display());
        }
    }
    let phrase = std::fs::read_to_string(&path)
        .with_context(|| format!("read Skarbiec unlock file {}", path.display()))?;
    let phrase = phrase.trim_end().to_string();
    Ok((!phrase.is_empty()).then_some(phrase))
}

pub fn decrypt(ciphertext: &str) -> Result<String> {
    match unlock_phrase()? {
        Some(phrase) => decrypt_protected(ciphertext, &phrase),
        _ => run(
            "gpg",
            &[
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--decrypt",
            ],
            Some(ciphertext),
        ),
    }
}

// Protected-key path: stage the ciphertext to a temp file and feed the phrase
// to gpg over stdin. The temp name gets a per-call sequence: a pid-only name
// let threaded decrypts swap each other's input file.
static TEMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MIN);

fn decrypt_protected(ciphertext: &str, phrase: &str) -> Result<String> {
    let mut path = std::env::temp_dir();
    let one = std::iter::once(()).count() as u64;
    path.push(format!(
        "skarbiec-ct-{}-{}.asc",
        std::process::id(),
        TEMP_SEQ.fetch_add(one, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, ciphertext).context("stage ciphertext")?;
    let file = path.to_string_lossy().into_owned();
    let out = run(
        "gpg",
        &[
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
            "--decrypt",
            &file,
        ],
        Some(phrase),
    );
    let _ = std::fs::remove_file(&path);
    out
}

#[allow(dead_code)] // public API surface consumed by the HTTP layer / clients
/// True when the local keyring (plus any SKARBIEC_UNLOCK) opens this
/// ciphertext. Used to gate reads by possession.
pub fn can_decrypt(ciphertext: &str) -> bool {
    decrypt(ciphertext).is_ok()
}

/// Generate a new key pair for a user id, returning its fingerprint.
pub fn generate_key(uid: &str) -> Result<String> {
    run(
        "gpg",
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            uid,
            "default",
            "default",
            "never",
        ],
        None,
    )?;
    fingerprint_for(uid)?.with_context(|| format!("key not found after generating for {uid}"))
}

/// Fingerprint of a key already in the local keyring for this user id, if any.
pub fn fingerprint_for(uid: &str) -> Result<Option<String>> {
    let listing = match run_opt("gpg", &["--list-keys", "--with-colons", uid], None) {
        Some(text) => text,
        None => return Ok(None),
    };
    for line in listing.lines() {
        if let Some(rest) = line.strip_prefix("fpr") {
            if let Some(fpr) = rest
                .split(':')
                .find(|field| !field.is_empty() && field.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Ok(Some(fpr.to_string()));
            }
        }
    }
    Ok(None)
}

/// Whether the private half for this fingerprint is in the local keyring. The
/// public half proves nothing: stored ciphertext opens only for whoever holds a
/// secret key, and a vault can list a recipient whose secret half is long gone.
pub fn secret_key_present(fingerprint: &str) -> bool {
    let listing = match run_opt(
        "gpg",
        &["--list-secret-keys", "--with-colons", fingerprint],
        None,
    ) {
        Some(text) => text,
        None => return false,
    };
    listing
        .lines()
        .any(|line| line.starts_with("sec:") || line.starts_with("ssb:"))
}

/// Keygrips of a key and its subkeys. `gpg-agent` stores each secret half as
/// `private-keys-v1.d/<KEYGRIP>.key`, so these are the exact filenames a restore
/// from backup has to produce: the fingerprint names the key, the keygrip names
/// the file on disk.
pub fn keygrips_for(fingerprint: &str) -> Vec<String> {
    let listing = match run_opt(
        "gpg",
        &[
            "--list-keys",
            "--with-colons",
            "--with-keygrip",
            fingerprint,
        ],
        None,
    ) {
        Some(text) => text,
        None => return Vec::new(),
    };
    let mut grips: Vec<String> = Vec::new();
    for line in listing.lines() {
        if let Some(rest) = line.strip_prefix("grp") {
            if let Some(found) = rest
                .split(':')
                .find(|field| !field.is_empty() && field.chars().all(|c| c.is_ascii_hexdigit()))
            {
                let grip = found.to_string();
                if !grips.contains(&grip) {
                    grips.push(grip);
                }
            }
        }
    }
    grips
}

/// Import an armored public (or private) key, returning nothing on success.
pub fn import_key(armored: &str) -> Result<()> {
    run("gpg", &["--batch", "--import"], Some(armored))?;
    Ok(())
}

/// Export a recipient's armored public key for sharing the vault.
pub fn export_public_key(fingerprint: &str) -> Result<String> {
    run("gpg", &["--armor", "--export", fingerprint], None)
}

/// Current six-digit time-based one-time code for a Base32 seed, when the
/// standard oath toolkit accepts the seed. Tool absence, malformed Base32 and
/// output that is not exactly the six digits a TOTP consumer accepts all return
/// `None`; callers must not describe any of those states as a usable seed.
pub fn totp_code(secret_base32: &str) -> Option<String> {
    run_opt("oathtool", &["--totp", "--base32", secret_base32], None)
        .map(|code| code.trim().to_string())
        .filter(|code| code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()))
}
