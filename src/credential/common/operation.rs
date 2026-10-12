// The credential operations, each with where it may run and what it acts on,
// declared once. The CLI dispatch, the canonical endpoint, the provider
// contract, the receipt check, the preflight, the managed-write authority and
// the commit all ask the operation, so an operation the CLI sends to the
// canonical endpoint is one the endpoint accepts.

/// One credential lifecycle operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Acquire,
    /// Take over a credential whose current password the operator types on
    /// stdin; that password never travels, so adopt runs only with `--local`.
    Adopt,
    Rotate,
    /// Rotate without knowing the current provider password.
    Reset,
    Verify,
    Remove,
    /// Sign a subscription's human login in again through Weles.
    Reauth,
}

const ALL: &[Operation] = &[
    Operation::Acquire,
    Operation::Adopt,
    Operation::Rotate,
    Operation::Reset,
    Operation::Verify,
    Operation::Remove,
    Operation::Reauth,
];

impl Operation {
    /// The operation's name, as the CLI, the wire and a receipt spell it.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Operation::Acquire => "acquire",
            Operation::Adopt => "adopt",
            Operation::Rotate => "rotate",
            Operation::Reset => "reset",
            Operation::Verify => "verify",
            Operation::Remove => "remove",
            Operation::Reauth => "reauth",
        }
    }

    /// The operation a name spells, read back through [`Operation::as_str`];
    /// nothing for a name the lifecycle has no operation for.
    pub(crate) fn parse(name: &str) -> Option<Operation> {
        ALL.iter()
            .copied()
            .find(|operation| operation.as_str() == name)
    }

    /// Every operation's name, in the order a lifecycle uses them.
    pub(crate) fn names() -> Vec<&'static str> {
        ALL.iter().map(|operation| operation.as_str()).collect()
    }

    /// The canonical endpoint runs it for a remote caller: everything but
    /// adopt, whose input is the operator's own password.
    pub(crate) fn remote(self) -> bool {
        self != Operation::Adopt
    }

    /// Runs against a credential already under Weles management.
    pub(crate) fn on_managed_item(self) -> bool {
        matches!(
            self,
            Operation::Rotate | Operation::Reset | Operation::Verify | Operation::Remove
        )
    }

    /// Stages a candidate revision of the live managed item through a Weles
    /// write; remove trashes the item instead.
    pub(crate) fn stages_revision(self) -> bool {
        self.on_managed_item() && self != Operation::Remove
    }

    /// A provider bound to one sealed directory identity runs it: the
    /// password operations on an existing principal, never its creation,
    /// removal or a subscription login.
    pub(crate) fn directory_bound(self) -> bool {
        matches!(
            self,
            Operation::Adopt | Operation::Rotate | Operation::Verify | Operation::Reset
        )
    }
}
