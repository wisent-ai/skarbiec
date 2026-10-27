// The database servers rotate --with database changes a password on, each through its own
// command-line client. Which one is the address's scheme: postgresql:// (or
// postgres://) runs psql, mysql:// runs mysql. Both change the password of
// the account that signed in — ALTER ROLE CURRENT_USER and ALTER USER
// CURRENT_USER() — so no host part or quoting of the account's name is
// needed, and both take the password only through their environment and the
// statement on standard input.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

use crate::cli::args::Usage;

pub(crate) const USAGE: &str =
    "usage: rotate <id> --with database --url <postgresql://host[:port]/dbname | mysql://host[:port]/dbname> --length <N>";

pub(super) enum Engine {
    Postgres { url: String },
    Mysql { host: String, port: Option<String>, database: String },
}

impl Engine {
    /// The engine an address names, refusing one that carries a user or a
    /// password: those come from the item, never the address.
    pub(super) fn parse(url: &str, id: &str) -> Result<Engine> {
        if url.contains('@') {
            return Err(Usage(format!("--url {url} names a user; the account and its password come from {id}, never the address. {USAGE}")).into());
        }
        if url.starts_with("postgresql://") || url.starts_with("postgres://") {
            return Ok(Engine::Postgres { url: url.to_string() });
        }
        let Some(rest) = url.strip_prefix("mysql://") else {
            return Err(Usage(format!("--url {url} is neither postgresql:// nor mysql://. {USAGE}")).into());
        };
        let Some((address, database)) = rest.split_once('/') else {
            return Err(Usage(format!("--url {url} names no database after the host. {USAGE}")).into());
        };
        let (host, port) = match address.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port.to_string())),
            None => (address.to_string(), None),
        };
        if host.is_empty() || database.is_empty() {
            return Err(Usage(format!("--url {url} names no host or no database. {USAGE}")).into());
        }
        Ok(Engine::Mysql { host, port, database: database.to_string() })
    }

    pub(super) fn client(&self) -> &'static str {
        match self {
            Engine::Postgres { .. } => "psql",
            Engine::Mysql { .. } => "mysql",
        }
    }

    /// The statement that sets the signed-in account's password.
    pub(super) fn alter(&self, password: &str) -> String {
        match self {
            Engine::Postgres { .. } => format!("ALTER ROLE CURRENT_USER PASSWORD '{}';\n", password.replace('\'', "''")),
            Engine::Mysql { .. } => format!(
                "ALTER USER CURRENT_USER() IDENTIFIED BY '{}';\n",
                password.replace('\\', "\\\\").replace('\'', "\\'")
            ),
        }
    }

    /// The statement a sign-in runs to prove it: who signed in.
    pub(super) fn proof(&self) -> &'static str {
        match self {
            Engine::Postgres { .. } => "SELECT current_user;\n",
            Engine::Mysql { .. } => "SELECT CURRENT_USER();\n",
        }
    }

    /// Sign in as `user` with `password` and run `sql`.
    pub(super) fn run(&self, user: &str, password: &str, sql: &str) -> Result<()> {
        let mut command = match self {
            Engine::Postgres { url } => {
                let mut command = Command::new("psql");
                command.args(["-X", "-q", "-v", "ON_ERROR_STOP=on", "-U", user, "-d", url]).env("PGPASSWORD", password);
                command
            }
            Engine::Mysql { host, port, database } => {
                let mut command = Command::new("mysql");
                command.args(["--batch", "--no-defaults", "-h", host, "-u", user, "-D", database]).env("MYSQL_PWD", password);
                if let Some(port) = port {
                    command.args(["-P", port]);
                }
                command
            }
        };
        let client = self.client();
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("start {client}, which changes the account's password"))?;
        child
            .stdin
            .take()
            .with_context(|| format!("{client} was started without a standard input"))?
            .write_all(sql.as_bytes())
            .with_context(|| format!("hand the statement to {client}"))?;
        let output = stado_wait::blocking(stado_wait::Kind::Process, "a database client talking to the server", client, || child.wait_with_output())
            .with_context(|| format!("wait for {client}"))?;
        if !output.status.success() {
            bail!("{client} as {user} ({}): {}", output.status, String::from_utf8_lossy(&output.stderr).trim());
        }
        Ok(())
    }
}
