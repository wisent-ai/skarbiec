// Which item kinds exist and what each declares about its fields: which
// names it takes, which it requires, of which it needs at least one, and the
// value each holds. A reader can answer all of it from the cleartext
// envelope, without opening the item, and the payload check reads the same
// declaration, so a kind's fields are stated once.

/// The value a field holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Shape {
    Text,
    /// Text, or a list of values (ports, recovery codes, a certificate chain).
    TextOrList,
    /// Text, or an object (a service account's credential document).
    TextOrObject,
    /// Any value: the kind keeps what it was given as it was given.
    Any,
}

/// What a kind declares about one of its fields.
#[derive(Clone, Copy, Debug)]
pub(super) struct Field {
    pub(super) name: &'static str,
    pub(super) required: bool,
    /// The set of fields of which a payload needs at least one, by what the
    /// set stands for.
    pub(super) one_of: Option<&'static str>,
    pub(super) shape: Shape,
}

const fn required(name: &'static str, shape: Shape) -> Field {
    Field {
        name,
        required: true,
        one_of: None,
        shape,
    }
}

const fn optional(name: &'static str, shape: Shape) -> Field {
    Field {
        name,
        required: false,
        one_of: None,
        shape,
    }
}

const fn one_of(name: &'static str, set: &'static str, shape: Shape) -> Field {
    Field {
        name,
        required: false,
        one_of: Some(set),
        shape,
    }
}

/// What a login authenticates with; it needs at least one.
const FACTOR: &str = "authentication factor";
/// What names an identity; it needs at least one.
const NAME: &str = "address or phone number";

const NOTE: &[Field] = &[required("value", Shape::Text)];
const LOGIN: &[Field] = &[
    required("username", Shape::Text),
    one_of("password", FACTOR, Shape::Text),
    one_of("totp_secret", FACTOR, Shape::Text),
    one_of("recovery_codes", FACTOR, Shape::TextOrList),
];
// The person or robot an account belongs to, as its own item. A second factor
// belongs to an identity and not to a platform: one account carries the
// authenticator and the phone that answers it, while the logins performed AS
// that identity only name it, so a re-enrolment changes one item. An identity
// has to be nameable, by an address, a phone number, or both; its factors are
// optional, because an identity is worth recording before its authenticator
// is enrolled.
const IDENTITY: &[Field] = &[
    one_of("email", NAME, Shape::Text),
    one_of("phone", NAME, Shape::Text),
    optional("password", Shape::Text),
    optional("totp_secret", Shape::Text),
    optional("recovery_codes", Shape::TextOrList),
];
// A fleet host's operating-system account is not a web login: it is consumed by
// the host-placement and host-repair readers, never by a login trajectory. Those
// readers iterate `login` items, so overloading `login` would hand a machine
// root account to a browser flow; `host-account` keeps the two sets disjoint.
// Both fields are required: a host account with only a username is not a
// credential, and one with only a password cannot say who it is.
const HOST_ACCOUNT: &[Field] = &[
    required("username", Shape::Text),
    required("password", Shape::Text),
];
const API_KEY: &[Field] = &[
    required("api_key", Shape::Text),
    optional("api_user", Shape::Text),
    optional("username", Shape::Text),
    optional("client_ip", Shape::Text),
];
const ACCESS_KEY: &[Field] = &[
    required("access_key_id", Shape::Text),
    required("secret_access_key", Shape::Text),
    optional("session_token", Shape::Text),
];
const TOKEN: &[Field] = &[required("token", Shape::Text)];
const OAUTH_CLIENT: &[Field] = &[
    required("client_id", Shape::Text),
    required("client_secret", Shape::Text),
];
const PROXY: &[Field] = &[
    required("username", Shape::Text),
    required("password", Shape::Text),
    optional("host", Shape::Text),
    optional("ports", Shape::TextOrList),
    optional("zone", Shape::Text),
];
const KEY_PAIR: &[Field] = &[
    required("private_key", Shape::Text),
    optional("public_key", Shape::Text),
    optional("passphrase", Shape::Text),
    optional("key_id", Shape::Text),
    optional("issuer_id", Shape::Text),
    optional("team_id", Shape::Text),
];
const CERTIFICATE: &[Field] = &[
    required("certificate", Shape::Text),
    required("private_key", Shape::Text),
    optional("chain", Shape::TextOrList),
    optional("passphrase", Shape::Text),
];
const SERVICE_ACCOUNT: &[Field] = &[required("credential_json", Shape::TextOrObject)];
const RECORD: &[Field] = &[required("value", Shape::Any)];

/// What a kind declares about its fields.
#[derive(Clone, Copy, Debug)]
pub(super) enum Declared {
    /// No such kind.
    Unknown,
    /// A kind that keeps whatever fields it was given, each named by one
    /// exact component and holding any value.
    Open,
    /// A kind that takes exactly these fields.
    Fields(&'static [Field]),
}

pub(super) fn declared(kind: &str) -> Declared {
    match kind {
        "note" => Declared::Fields(NOTE),
        "login" => Declared::Fields(LOGIN),
        "identity" => Declared::Fields(IDENTITY),
        "host-account" => Declared::Fields(HOST_ACCOUNT),
        "api-key" => Declared::Fields(API_KEY),
        "access-key" => Declared::Fields(ACCESS_KEY),
        "token" => Declared::Fields(TOKEN),
        "oauth-client" => Declared::Fields(OAUTH_CLIENT),
        "proxy" => Declared::Fields(PROXY),
        "key-pair" => Declared::Fields(KEY_PAIR),
        "certificate" => Declared::Fields(CERTIFICATE),
        "service-account" => Declared::Fields(SERVICE_ACCOUNT),
        // An operation record is one request and its outcome; a directory
        // seal is the standing statement of which principal an item speaks
        // for. They are separate kinds because they are separate families,
        // written by the credential lifecycle under the same managed
        // authority: an id is a mutable name, not evidence of which one an
        // item is, so a reader that wants seals asks for the kind.
        "credential-operation" | "credential-directory-seal" => Declared::Fields(RECORD),
        "bundle" | "stado-secret" | "internal-authority" => Declared::Open,
        _ => Declared::Unknown,
    }
}

pub fn supported_kind(kind: &str) -> bool {
    !matches!(declared(kind), Declared::Unknown)
}

/// The names of the fields `kind` declares, in the order it declares them;
/// none for a kind that declares no fields of its own.
pub(super) fn names(kind: &str) -> Vec<&'static str> {
    match declared(kind) {
        Declared::Fields(fields) => fields.iter().map(|field| field.name).collect(),
        Declared::Open | Declared::Unknown => Vec::new(),
    }
}
