// `skarbiec completion [--shell fish]`: a bash completion script — or with
// --shell fish a fish one — built from the help table, so the names it
// completes and the flags it offers after each are the ones `--help`
// advertises and never drift from them. zsh loads the bash one through its
// bash compatibility layer.

use super::COMMANDS;

/// The script, ready for `source <(skarbiec completion)` or a file under
/// bash-completion's directory.
pub(crate) fn bash_script() -> String {
    let names: Vec<&str> = COMMANDS.iter().map(|command| command.name).collect();
    let cases: String = COMMANDS
        .iter()
        .filter_map(|command| {
            let flags = flags_of(command.usage);
            (!flags.is_empty())
                .then(|| format!("    {}) flags=\"{}\" ;;\n", command.name, flags.join(" ")))
        })
        .collect();
    format!(
        r#"# skarbiec completion for bash. In zsh, run `autoload -U bashcompinit && bashcompinit` first.
_skarbiec() {{
  local current="${{COMP_WORDS[COMP_CWORD]}}"
  if [ "$COMP_CWORD" -le 1 ]; then
    COMPREPLY=($(compgen -W "{names}" -- "$current"))
    return
  fi
  local flags=""
  case "${{COMP_WORDS[1]}}" in
{cases}  esac
  COMPREPLY=($(compgen -W "$flags" -- "$current"))
}}
complete -F _skarbiec skarbiec
"#,
        names = names.join(" "),
    )
}

/// The fish script, ready for `skarbiec completion --shell fish >
/// ~/.config/fish/completions/skarbiec.fish`: each command with its summary's
/// first clause as the description fish shows, and after it the flags its
/// usage names.
pub(crate) fn fish_script() -> String {
    let quoted = |text: &str| format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"));
    let mut script = String::from("# skarbiec completion for fish.\ncomplete -c skarbiec -f\n");
    for command in COMMANDS {
        let clause = command
            .summary
            .split([';', ':'])
            .next()
            .map(str::trim)
            .filter(|text| !text.is_empty());
        let description = match clause {
            Some(text) => format!(" -d {}", quoted(text)),
            None => String::new(),
        };
        script.push_str(&format!(
            "complete -c skarbiec -n __fish_use_subcommand -a {}{description}\n",
            quoted(command.name)
        ));
        for flag in flags_of(command.usage) {
            script.push_str(&format!(
                "complete -c skarbiec -n {} -l {}\n",
                quoted(&format!("__fish_seen_subcommand_from {}", command.name)),
                flag.trim_start_matches('-')
            ));
        }
    }
    script
}

/// Every `--flag` a usage line names, once each, sorted.
pub(super) fn flags_of(usage: &str) -> Vec<String> {
    let mut flags: Vec<String> = usage
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '-'))
        .filter(|word| {
            word.strip_prefix("--")
                .is_some_and(|name| !name.is_empty() && !name.starts_with('-'))
        })
        .map(str::to_string)
        .collect();
    flags.sort();
    flags.dedup();
    flags
}
