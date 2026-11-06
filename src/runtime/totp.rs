// One-time-code helper. For a canonical login item that stores a base32 seed,
// emit the CURRENT time-based code in process, like a built-in authenticator.
// Only the short-lived code is emitted; the seed remains inside Skarbiec.
//
// This module also answers the vault's half of "is the stored authenticator
// seed still the one the account has enrolled". The vault cannot answer the
// whole question: whether a seed still MATCHES an enrolment is only observable
// where codes are submitted, which is the Weles reauth run history that
// `stado host weles-seed-freshness` reads. What the vault alone can prove is
// which of three states a login row is in, and those three have three
// different repairs, so they are never collapsed here.

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::core::{schema, vault::Vault};

mod seed;

pub(crate) use seed::base32_seed_shape;
use seed::{inspect_seed, load, seed_of};

mod dispatch;
mod recovery_codes;
mod seed_repair_command;
mod set_seed;

pub use dispatch::*;
pub use recovery_codes::{recovery_code_dispatch, replace as replace_recovery_codes};
pub use seed_repair_command::*;
pub(crate) use set_seed::given_seed;
pub use set_seed::store as store_seed;
