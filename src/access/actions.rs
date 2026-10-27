// The actions a capability may name, each with what it may target, declared
// once: which actions write one field, which act on a whole item, which
// resolve a role, which name no vault item at all. `grant issue`, the v2 vault
// validation, the migration of legacy grants, `grant --help` and the doctor
// all ask the action, so a vault holding any grant `grant issue` accepts also
// passes the v2 validation.

/// One action a capability names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Acquire,
    Read,
    Stage,
    Rotate,
    Verify,
    Revoke,
    Share,
    Trash,
    Purge,
    Admin,
    Sync,
    Enroll,
    Donate,
    /// Credential lifecycle: drive operations on one exact item. Reads no value.
    Lifecycle,
    /// Reseal one item's directory contract. Reads no value.
    Reseal,
    /// Ask what an inbound bearer is: held by a gateway that has to decide
    /// whether to serve a request, so that deciding does not require keeping
    /// a copy of every credential in the fleet. Reads no value.
    Introspect,
    /// Be called: the right to reach a service, and with `#field` the exact
    /// route within it, so a client's reach is a grant here rather than a
    /// list compiled into the service it calls.
    Call,
    /// Offer a new login to the owner: it waits, sealed to the owner's key,
    /// in the donation inbox until the owner accepts it. Names `logins`, not
    /// an item, and reads nothing.
    Offer,
    /// File an access request of one kind (`request:secret`,
    /// `request:device`, `request:membership`) into this vault's register
    /// from another host. Names the request kind, not an item, and reads and
    /// grants nothing: a person still decides.
    Request,
}

const ALL: &[Action] = &[
    Action::Acquire,
    Action::Read,
    Action::Stage,
    Action::Rotate,
    Action::Verify,
    Action::Revoke,
    Action::Share,
    Action::Trash,
    Action::Purge,
    Action::Admin,
    Action::Sync,
    Action::Enroll,
    Action::Donate,
    Action::Lifecycle,
    Action::Reseal,
    Action::Introspect,
    Action::Call,
    Action::Offer,
    Action::Request,
];

impl Action {
    /// The action's name, as a capability spells it (`action:item[#field]`).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Action::Acquire => "acquire",
            Action::Read => "read",
            Action::Stage => "stage",
            Action::Rotate => "rotate",
            Action::Verify => "verify",
            Action::Revoke => "revoke",
            Action::Share => "share",
            Action::Trash => "trash",
            Action::Purge => "purge",
            Action::Admin => "admin",
            Action::Sync => "sync",
            Action::Enroll => "enroll",
            Action::Donate => "donate",
            Action::Lifecycle => "lifecycle",
            Action::Reseal => "reseal",
            Action::Introspect => "introspect",
            Action::Call => "call",
            Action::Offer => "offer",
            Action::Request => "request",
        }
    }

    /// The action a capability names, read back through [`Action::as_str`];
    /// nothing for a name this vault has no action for.
    pub(crate) fn parse(name: &str) -> Option<Action> {
        ALL.iter().copied().find(|action| action.as_str() == name)
    }

    /// The action a stored capability record names in its `action` field;
    /// nothing when the field is absent, not text, or names no action.
    pub(crate) fn of(capability: &serde_json::Value) -> Option<Action> {
        capability
            .get("action")
            .and_then(serde_json::Value::as_str)
            .and_then(Action::parse)
    }

    /// Every action's name, in declaration order, as `grant --help` lists them.
    pub(crate) fn names() -> Vec<&'static str> {
        ALL.iter().map(|action| action.as_str()).collect()
    }

    /// Its resource slot names a vault item. The rest name something else
    /// there: `call` a service and a route inside it, `sync` the replication
    /// channel as `sync:pull`, `enroll` a recipient uid, `introspect` the
    /// token table and `offer` the logins a consumer may offer, as
    /// `offer:logins`.
    pub(crate) fn names_vault_item(self) -> bool {
        !matches!(
            self,
            Action::Call
                | Action::Sync
                | Action::Enroll
                | Action::Introspect
                | Action::Offer
                | Action::Request
        )
    }

    /// Writes or acquires one value, so it names exactly one field.
    pub(crate) fn needs_field(self) -> bool {
        matches!(
            self,
            Action::Acquire | Action::Stage | Action::Rotate | Action::Verify
        )
    }

    /// Acts on a whole item, or names a request kind, so it names no field.
    pub(crate) fn forbids_field(self) -> bool {
        matches!(self, Action::Lifecycle | Action::Reseal | Action::Request)
    }

    /// Resolves a `role:<role>` coordinate to the item playing that role.
    pub(crate) fn names_role(self) -> bool {
        matches!(self, Action::Acquire | Action::Read | Action::Stage)
    }

    /// May name an item or field its own write creates.
    pub(crate) fn may_create(self) -> bool {
        matches!(self, Action::Acquire | Action::Stage)
    }

    /// Acts on an existing item as a whole, so the item must exist.
    pub(crate) fn needs_item(self) -> bool {
        matches!(
            self,
            Action::Share | Action::Trash | Action::Purge | Action::Admin | Action::Reseal
        )
    }

    /// Reaches a service rather than a vault item: its target names a
    /// service and a route, not an item and a field.
    pub(crate) fn reaches_service(self) -> bool {
        matches!(self, Action::Call)
    }

    /// Names a kind of access request rather than a vault item.
    pub(crate) fn files_request(self) -> bool {
        matches!(self, Action::Request)
    }

    /// Was grantable before the v2 vault: a legacy grant names only these.
    pub(crate) fn legacy(self) -> bool {
        !matches!(
            self,
            Action::Lifecycle
                | Action::Reseal
                | Action::Introspect
                | Action::Call
                | Action::Offer
                | Action::Request
        )
    }

    /// Covers every field of an item when a legacy grant names none.
    pub(crate) fn per_field(self) -> bool {
        self.needs_field() || matches!(self, Action::Read)
    }

    /// May name an item's context metadata.
    pub(crate) fn reads_context(self) -> bool {
        matches!(self, Action::Read)
    }
}
