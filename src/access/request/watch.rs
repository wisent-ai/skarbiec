// `request watch --local`: the decider's channel on the vault host until they
// have an Oko account (docs/design/access-requests.md, decision 4).
//
// Each pending request this decider may answer is shown in a native macOS
// dialog — what, why, who, in Polish and English — with approve and deny.
// Approving asks the lifetime the same way: once, until revoked, or a number
// of hours the decider types. The watcher waits for the person without a
// timeout, and between requests it blocks on a FIFO every register writer
// pokes, so a new request appears the moment it is filed.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

use super::register::{self, text};
use super::{decide, Lifetime};

const TITLE: &str = "Skarbiec";
const APPROVE: &str = "Zatwierdź / Approve";
const DENY: &str = "Odmów / Deny";
const ONCE: &str = "Raz / Once";
const UNTIL_REVOKED: &str = "Do odwołania / Until revoked";
const HOURS: &str = "Godziny / Hours";
/// What "once" means: a single use.
const ONE_USE: u64 = 1;
const OK: &str = "OK";

/// One AppleScript dialog. The text travels as an argument to `on run`, never
/// spliced into the script, so nothing a requester wrote can become script.
fn dialog(
    message: &str,
    buttons: &[&str],
    default_answer: Option<&str>,
) -> Result<(String, String)> {
    let quoted: Vec<String> = buttons
        .iter()
        .map(|button| format!("\"{button}\""))
        .collect();
    let answer = if default_answer.is_some() {
        " default answer (item 2 of argv)"
    } else {
        ""
    };
    let script = format!(
        "on run argv\nset r to display dialog (item 1 of argv){answer} buttons {{{}}} \
         default button {} with title \"{TITLE}\"\nset t to \"\"\ntry\nset t to text returned of r\n\
         end try\nreturn (button returned of r) & linefeed & t\nend run",
        quoted.join(", "),
        quoted.last().context("a dialog needs a button")?,
    );
    let mut command = Command::new("osascript");
    command.arg("-e").arg(script).arg("--").arg(message);
    if let Some(default_answer) = default_answer {
        command.arg(default_answer);
    }
    let output = stado_wait::output(&mut command).context("run osascript")?;
    if !output.status.success() {
        bail!(
            "the dialog was not answered: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let reply = String::from_utf8(output.stdout).context("osascript answer is not text")?;
    let (button, typed) = reply
        .trim_end_matches('\n')
        .split_once('\n')
        .unwrap_or((&reply, ""));
    Ok((button.trim().to_string(), typed.trim().to_string()))
}

fn describe(record: &Value) -> String {
    let requester = &record["requester"];
    let who = ["agent", "harness", "host", "person"]
        .iter()
        .filter_map(|key| {
            requester[*key]
                .as_str()
                .map(|value| format!("{key}: {value}"))
        })
        .collect::<Vec<_>>()
        .join(", ");
    let grant = &record["grant"];
    let bounds = match text(grant, "form") {
        "capability" => format!(
            "\nProsi o / Asks for: {} s, {} użyć / uses (cel / purpose {}, dla / for {})",
            grant["ttl_seconds"],
            grant["max_uses"],
            text(grant, "purpose"),
            text(grant, "target")
        ),
        "consumer" => format!(
            "\nStały dostęp dla / Standing grant for: {}",
            text(grant, "consumer")
        ),
        _ => String::new(),
    };
    let dual = if record["dual_control"] == json!(true) {
        "\nWymaga dwóch osób / Needs two deciders."
    } else {
        ""
    };
    format!(
        "Prośba o dostęp / Access request {}\n\nCo / What: {} {} ({}){bounds}\n\
         Dlaczego / Why: {}\nKto / Who: {who}{dual}",
        text(record, "id"),
        text(record, "action"),
        text(record, "resource"),
        text(record, "kind"),
        text(record, "reason"),
    )
}

/// A whole number the decider types, asked again until it is one.
fn typed_number(question: &str, default_answer: &str) -> Result<u64> {
    let mut prompt = question.to_string();
    loop {
        let (_, typed) = dialog(&prompt, &[OK], Some(default_answer))?;
        match typed.parse::<u64>() {
            Ok(value) if value > u64::MIN => return Ok(value),
            _ => prompt = format!("{question}\n\n„{typed}” nie jest liczbą dodatnią / is not a positive whole number."),
        }
    }
}

/// The lifetime and uses the decider states for one approval.
fn bounds(record: &Value) -> Result<(Lifetime, Option<u64>)> {
    let grant = &record["grant"];
    let form = text(grant, "form");
    let mut buttons = Vec::new();
    if form == "capability" || text(record, "kind") == "device" {
        buttons.push(ONCE);
    }
    if form != "capability" {
        buttons.push(UNTIL_REVOKED);
    }
    buttons.push(HOURS);
    let question = format!("{}\n\nNa jak długo? / For how long?", describe(record));
    let (choice, _) = dialog(&question, &buttons, None)?;
    let hour = time::Duration::HOUR.whole_seconds().unsigned_abs();
    match choice.as_str() {
        ONCE if form == "capability" => {
            let asked = grant["ttl_seconds"]
                .as_u64()
                .context("capability request has no asked ttl")?;
            Ok((Lifetime::Seconds(asked), Some(ONE_USE)))
        }
        ONCE => Ok((Lifetime::UntilRevoked, Some(ONE_USE))),
        UNTIL_REVOKED => Ok((Lifetime::UntilRevoked, None)),
        _ => {
            let hours = typed_number("Ile godzin? / How many hours?", "")?;
            let seconds = hours.checked_mul(hour).context("too many hours")?;
            let uses = if form == "capability" {
                let asked = grant["max_uses"].to_string();
                Some(typed_number("Ile użyć? / How many uses?", &asked)?)
            } else {
                None
            };
            Ok((Lifetime::Seconds(seconds), uses))
        }
    }
}

/// Ask about one request and apply the answer; a refusal is shown, not fatal.
fn ask(record: &Value, by: &str) -> Result<()> {
    let id = text(record, "id");
    let (choice, _) = dialog(&describe(record), &[DENY, APPROVE], None)?;
    let applied = if choice == APPROVE {
        let (lifetime, uses) = bounds(record)?;
        decide::approve(id, by, lifetime, uses)
    } else {
        decide::close(id, by, "deny", None)
    };
    let shown = match applied {
        Ok(answer) => format!(
            "{id}: {}",
            answer["status"]
                .as_str()
                .or(answer["state"].as_str())
                .unwrap_or_default()
        ),
        Err(error) => format!("{id}: nie zastosowano / not applied: {error:#}"),
    };
    eprintln!("{shown}");
    dialog(&shown, &[OK], None)?;
    Ok(())
}

pub(super) fn watch(by: &str) -> Result<()> {
    let wake = register::wake_path();
    if !wake.exists() {
        let path = CString::new(wake.as_os_str().as_bytes())?;
        // POSIX mkfifo(3); owner read and write only (mode 0600).
        if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error()).context("create the request wake FIFO");
        }
    }
    // Read and write, so the FIFO always has a reader while this watcher
    // lives (a filer never blocks) and a read waits for the next poke
    // instead of returning end-of-file.
    let mut fifo = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&wake)
        .with_context(|| format!("open {}", wake.display()))?;
    let mut asked: HashSet<String> = HashSet::new();
    eprintln!("skarbiec request watch: deciding as {by}; waiting for requests");
    loop {
        let doc = register::load()?;
        let pending: Vec<Value> = register::requests(&doc)
            .filter(|record| text(record, "state") == "pending")
            .filter(|record| !asked.contains(text(record, "id")))
            .cloned()
            .collect();
        for record in pending {
            asked.insert(text(&record, "id").to_string());
            let already = record["decisions"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|decision| text(decision, "by") == by);
            if !already {
                ask(&record, by)?;
            }
        }
        let mut poke = [u8::MIN];
        stado_wait::blocking(
            stado_wait::Kind::Process,
            "the next access request",
            wake.display(),
            || fifo.read_exact(&mut poke),
        )?;
    }
}
