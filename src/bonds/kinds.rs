// The modes, roles and channel types a bond may declare, from
// docs/design/bond.md, declared once: `bond add`/`bond edit` refuse any other,
// the pull and status report read the channel type, and the replica write
// guard reads the mode and role.

/// How two vaults relate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Replica,
    Hub,
    P2p,
    Git,
}

/// What this vault is within its bond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Source,
    Replica,
    Consumer,
    Peer,
}

/// How a bond's data travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Channel {
    /// Pulled from a source's `serve` endpoint; the only kind that is pulled.
    Serve,
    Git,
    File,
}

impl Mode {
    const ALL: &'static [Mode] = &[Mode::Replica, Mode::Hub, Mode::P2p, Mode::Git];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Mode::Replica => "replica",
            Mode::Hub => "hub",
            Mode::P2p => "p2p",
            Mode::Git => "git",
        }
    }

    pub(crate) fn parse(name: &str) -> Option<Mode> {
        Self::ALL.iter().copied().find(|mode| mode.as_str() == name)
    }

    pub(crate) fn names() -> String {
        Self::ALL
            .iter()
            .map(|mode| mode.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Role {
    const ALL: &'static [Role] = &[Role::Source, Role::Replica, Role::Consumer, Role::Peer];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Role::Source => "source",
            Role::Replica => "replica",
            Role::Consumer => "consumer",
            Role::Peer => "peer",
        }
    }

    pub(crate) fn parse(name: &str) -> Option<Role> {
        Self::ALL.iter().copied().find(|role| role.as_str() == name)
    }

    pub(crate) fn names() -> String {
        Self::ALL
            .iter()
            .map(|role| role.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Who a pull presents itself as: the consumer the caller or the bond
    /// names, and the replica role itself when neither names one. This is the
    /// documented default of `pull`, `bond add` and `bond status`, read here
    /// so they cannot drift apart.
    pub(crate) fn pull_consumer(named: Option<&str>) -> &str {
        match named {
            Some(named) => named,
            None => Role::Replica.as_str(),
        }
    }
}

impl Channel {
    const ALL: &'static [Channel] = &[Channel::Serve, Channel::Git, Channel::File];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Channel::Serve => "serve",
            Channel::Git => "git",
            Channel::File => "file",
        }
    }

    pub(crate) fn parse(name: &str) -> Option<Channel> {
        Self::ALL
            .iter()
            .copied()
            .find(|channel| channel.as_str() == name)
    }

    pub(crate) fn names() -> String {
        Self::ALL
            .iter()
            .map(|channel| channel.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}
