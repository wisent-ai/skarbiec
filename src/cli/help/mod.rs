// What `--help` answers. One table names every advertised top-level command
// with its usage line and one sentence saying what it does: `skarbiec help`
// publishes it as the machine-readable inventory, `skarbiec --help` prints it
// for a person, and `skarbiec <command> --help` prints one row of it without
// running the command. Before this table `--help` printed a JSON array of bare
// names, and `<command> --help` printed only where the docs were.

use anyhow::Result;
use serde_json::{json, Map, Value};

pub(crate) struct CommandHelp {
    pub(crate) name: &'static str,
    pub(crate) usage: &'static str,
    pub(crate) summary: &'static str,
    /// A group owns its own inventory, `skarbiec <group> help`, which
    /// `skarbiec <group> --help` prints instead of this row.
    pub(crate) group: bool,
}

const fn row(name: &'static str, usage: &'static str, summary: &'static str) -> CommandHelp {
    CommandHelp {
        name,
        usage,
        summary,
        group: false,
    }
}

const fn group(name: &'static str, usage: &'static str, summary: &'static str) -> CommandHelp {
    CommandHelp {
        name,
        usage,
        summary,
        group: true,
    }
}

pub(crate) const COMMANDS: &[CommandHelp] = &[
    row("status", "skarbiec status", "Report the configured vault path and non-sensitive vault counts."),
    row("doctor", "skarbiec doctor [--tail N]", "Diagnose the vault file, audit chain, GnuPG daemons, canonical endpoint, WORM evidence and consumer grants without depending on the API. Audit digests are recomputed for every entry, or for the newest N with --tail."),
    row("recover-daemons", "skarbiec recover-daemons", "Replace the account's keyboxd, gpg-agent and scdaemon through gpgconf and report what each held before."),
    row("vaults", "skarbiec vaults", "Inventory the Skarbiec vault files in this host's conventional locations without decrypting them."),
    row("init", "skarbiec init <owner-uid>", "Create a new vault with an owner recipient and a separate recovery recipient."),
    row("set-json", "skarbiec set-json <id> [--type <canonical-kind>] [--recipients <uid,...>] [--tags <tag,...>] [--if-absent]  (payload on stdin)", "Write one canonical item payload read from stdin, so no value appears in argv."),
    row("get", "skarbiec get <id|role:<role>> [--field <field>]", "Decrypt one item for its owner, or return one exact text field; role:<role> reads the one live item tagged stado:role:<role>."),
    row("list", "skarbiec list [--all]", "List item metadata without credential values; --all includes trashed items."),
    row("duplicates", "skarbiec duplicates", "Report which live items hold exactly the same payload."),
    row("retag", "skarbiec retag <id> --tags <tag[,tag...]>", "Replace one item's tags without rewriting its payload or recipients."),
    row("rename", "skarbiec rename <id> <new-id>", "Change one item's id and keep its revision, history, tags and recipients."),
    row("delete", "skarbiec delete <id>", "Move an owner-controlled item to recoverable trash."),
    row("reclaim", "skarbiec reclaim <id>", "Return an item from external writer control to owner control."),
    row("restore", "skarbiec restore <id>", "Restore a trashed owner-controlled item to the live inventory."),
    row("purge", "skarbiec purge <id> --yes", "Permanently remove a trashed owner-controlled item and every saved version; without --yes nothing is removed."),
    row("restore-version", "skarbiec restore-version <id> <at>", "Make the historical revision recorded at <at> the item's new current revision."),
    row("generate", "skarbiec generate --length <N> [--lower] [--upper] [--digits] [--symbols] | --passphrase --words <N> [--separator <text>]", "Generate a password or a word-list passphrase locally."),
    row("import", "skarbiec import <export-file> [--format auto|canonical|1password|bitwarden|browser-csv] [--conflict keep|replace|error]", "Seed the vault from a password-manager, browser or canonical Skarbiec export."),
    row("migrate", "skarbiec migrate --from <source-vault> --to <target-vault> [--force]", "Copy live items between vaults, re-encrypting them to the target's recipients."),
    row("upgrade", "skarbiec upgrade [--apply] [--snapshot <path>]", "Bring the vault to the current schema: v2 envelope, item_uid on every item, payload fingerprint on every active item, owner control of items a former owner still controls; without --apply it only reports."),
    row("add-user", "skarbiec add-user <uid> [--import <public-key-file>] [--role <member-role>]", "Register a recipient identity without sharing any existing item."),
    row("rotate-owner", "skarbiec rotate-owner <new-owner-uid>", "Replace the vault owner, rewrap every current and historical ciphertext to the new owner, and move the outgoing owner's items under the new owner's control."),
    row("share", "skarbiec share <item-id> <uid>", "Give a registered recipient cryptographic access to one item."),
    row("revoke", "skarbiec revoke <item-id> <uid>", "Remove one recipient from one item's recipient set."),
    row("remove-user", "skarbiec remove-user <uid> --yes", "Remove one person from every item, every historical revision and the recipient registry; without --yes nothing changes."),
    row("users", "skarbiec users", "List the vault's registered recipients."),
    row("export-key", "skarbiec export-key <uid>", "Export one registered recipient's public key."),
    group("grant", "skarbiec grant help", "Issue, bound, widen, narrow, list, check and withdraw consumer grants; `skarbiec grant help` lists the subcommands."),
    row("acquisition-request", "skarbiec acquisition-request <consumer> <item> <field> --workload-id <id> --workload-timestamp <epoch> --workload-nonce <nonce> --workload-signature <hex>", "Verify a workload's signed proof and issue a short-lived one-use capability for one field."),
    row("acquisition-read", "skarbiec acquisition-read <consumer> <item> <field> --token-file <path>", "Consume one acquisition token, read from an owner-only file, and return only its bound field."),
    row("key-doctor", "skarbiec key-doctor", "Report whether any key on this host can still open the vault, reading vault and keyring directly."),
    row("recovery-status", "skarbiec recovery-status", "Report the vault's recovery recipient and whether its secret key is in this keyring."),
    row("recovery-drill", "skarbiec recovery-drill <recipient-uid|recovery>", "Prove that one expected recovery identity in an isolated keyring can open the vault."),
    row("emergency-grant", "skarbiec emergency-grant <grantee> --activate-after <iso8601>", "Create a pending time-delayed emergency access record for one recipient."),
    row("emergency-cancel", "skarbiec emergency-cancel <grantee>", "Cancel a pending emergency grant before it activates."),
    row("emergency-list", "skarbiec emergency-list", "List pending and activated emergency grants."),
    row("emergency-activate", "skarbiec emergency-activate <grantee>", "Activate a due emergency grant by sharing every live item with its grantee."),
    row("policy-set", "skarbiec policy-set <key> <value>", "Set one administrative policy rule the binary enforces (min_generated_length)."),
    row("policy-unset", "skarbiec policy-unset <key>", "Withdraw one administrative policy rule; a key that is not set is reported, not refused."),
    row("policy-get", "skarbiec policy-get", "Read the administrative policy."),
    row("policy-check-length", "skarbiec policy-check-length <candidate>", "Check a candidate's length against min_generated_length without storing it."),
    row("audit", "skarbiec audit [--limit <N>]", "Read the append-only audit journal, oldest first."),
    row("audit-query", "skarbiec audit-query [--op <operation>] [--consumer <name>] [--item <id>] [--since <iso>] [--until <iso>] [--limit <N>]", "Filter the audit journal by operation, consumer, item and time: every match, or with --limit the newest N; matched counts them all."),
    row("audit-epoch-start", "skarbiec audit-epoch-start --reason <text>", "Start a signed audit epoch after acknowledging an already-broken chain."),
    row("verify-chain", "skarbiec verify-chain [--tail <N>]", "Verify the audit journal's linkage and entry digests and report every fault."),
    group("route", "skarbiec route help", "Resolve resource names to vault fields, declare the routes an item cannot, and verify them; `skarbiec route help` lists the subcommands."),
    row("totp", "skarbiec totp <item-id>", "Compute the current TOTP code from a stored seed without returning the seed."),
    row("totp-seed-state", "skarbiec totp-seed-state [<item-id>]", "Report whether one item, or every login and identity item, holds a seed that computes a TOTP code, without returning the code or the seed."),
    row("breach-check", "skarbiec breach-check <item-id> [--field <field>]", "Check a stored field against Have I Been Pwned through its k-anonymous range API."),
    row("sync-init", "skarbiec sync-init <remote-url>", "Initialize the Git ciphertext mirror and set its origin."),
    row("sync-push", "skarbiec sync-push [--branch <name>] [--message <text>]", "Commit the encrypted vault to the Git mirror and push one branch."),
    row("sync-pull", "skarbiec sync-pull [--branch <name>] [--force]", "Pull the Git ciphertext mirror and replace the live vault after protecting local state."),
    row("pull", "skarbiec pull --from <base-url> --token-file <path> [--bond <name>] [--consumer <name>] [--force]", "Fetch a complete ciphertext vault from a serve channel and install it as a replica."),
    row("donate", "skarbiec donate <item-id> --to <base-url> --consumer <name> --token-file <path> [--from <writer>]", "Seal one item to a remote vault owner's key and submit it to that vault's donation inbox."),
    row("donations", "skarbiec donations", "List pending donations without decrypting them."),
    row("donation-accept", "skarbiec donation-accept <donation-id>", "Accept one pending donation after rechecking its writer-admission rule."),
    row("donation-reject", "skarbiec donation-reject <donation-id>", "Discard one pending donation without decrypting it."),
    row("enroll", "skarbiec enroll --as <uid> --to <base-url> --token-file <path> [--items <id,...>] [--consumer <name>]", "Register this vault owner's key with a source and request selected items for this replica."),
    row("sync-status", "skarbiec sync-status [--bond <name>] [--consumer <name>] [--token-file <path>]", "Report each bond's state, whether serve pulls it, and the remote's health and item counts."),
    row("maintain", "skarbiec maintain", "Run one maintenance pass: the GnuPG daemon ceiling, the readiness proof and one pull of every pulled bond; it fails naming every step that failed."),
    row("bond-add", "skarbiec bond-add <name> --mode <replica|hub|p2p|git> --role <source|replica|consumer|peer> --channel <serve|git|file>:<address> [--peers <fpr,...>] [--interval <seconds>] [--token-file <path> [--consumer <name>]]", "Create or replace one bond configuration."),
    row("bond-list", "skarbiec bond-list", "List every stored bond configuration."),
    row("bond-remove", "skarbiec bond-remove <name>", "Remove one stored bond configuration."),
    row("capability-status", "skarbiec capability-status [--socket <unix-socket-path>]", "Check that the running capability broker reads the same vault, state and routes as this client."),
    group("credential", "skarbiec credential help", "Run the persisted credential lifecycle (acquire, adopt, rotate, reset, verify, remove, reauth, resume, status); `skarbiec credential help` lists the subcommands."),
    group("rotation", "skarbiec rotation help", "Declare, list and withdraw per-item rotation policies and start every due rotation; `skarbiec rotation help` lists the subcommands."),
    row("challenge-put", "skarbiec challenge-put <challenge:resource>  (digits on stdin)", "Store the digits a trusted device received for an authorized one-use challenge; the resource names the provider."),
    row("version", "skarbiec version", "Print the binary version and, for published artifacts, its release and source provenance."),
];

fn docs_url(name: &str) -> String {
    format!("https://skarbiec.wisent.com/docs/cli/{name}")
}

/// Whether `name` is a group that answers `help` with its own inventory.
pub(crate) fn is_group(name: &str) -> bool {
    COMMANDS
        .iter()
        .any(|command| command.group && command.name == name)
}

/// The machine-readable inventory `skarbiec help` prints: the group and
/// command names consumers already read, and each command's usage, summary
/// and page beside them.
pub(crate) fn listing() -> Value {
    let mut described = Map::new();
    for command in COMMANDS {
        described.insert(
            command.name.to_string(),
            json!({"usage": command.usage, "summary": command.summary, "docs": docs_url(command.name)}),
        );
    }
    json!({
        "groups": COMMANDS.iter().filter(|command| command.group).map(|command| command.name).collect::<Vec<_>>(),
        "commands": COMMANDS.iter().map(|command| command.name).collect::<Vec<_>>(),
        "described": described,
    })
}

/// `skarbiec --help`: every command and what it does, for a person.
pub(crate) fn print_overview() {
    let width = COMMANDS
        .iter()
        .map(|command| command.name.len())
        .max()
        .unwrap_or_default();
    println!("usage: skarbiec <command> [arguments]\n");
    println!("commands:");
    for command in COMMANDS {
        println!("  {:width$}  {}", command.name, command.summary);
    }
    println!(
        "\n`skarbiec <command> --help` prints one command's usage without running it.\n\
         `skarbiec help` prints this inventory as JSON. Every command has a page under {}.",
        docs_url("")
    );
}

/// `skarbiec <command> --help`: one command's usage, never its effect.
pub(crate) fn print_command(name: &str) -> Result<()> {
    let Some(command) = COMMANDS.iter().find(|command| command.name == name) else {
        return Err(super::args::Usage(format!(
            "unknown command: {name}; `skarbiec --help` lists every command"
        ))
        .into());
    };
    println!(
        "usage: {}\n\n{}\n\n{}",
        command.usage,
        command.summary,
        docs_url(command.name)
    );
    Ok(())
}
