// The lifecycle state of one credential item: where its record lives, whether
// it is frozen, and the authority that decides whether a managed write lands.

mod lifecycle;
mod records;
mod writes;

pub(crate) use lifecycle::lifecycle_state;
pub(crate) use records::{lifecycle_owned_item, seal_item_id};
pub(crate) use writes::authorize_managed_write;

pub(super) use lifecycle::{quarantine_active, refuse_quarantined};
pub(super) use records::{
    context_block, context_string, item_revision, live_item_exists, request_item_id, save_request,
    save_seal, update_request,
};
pub(super) use writes::{item_matches_request, pending_matches_request, store_context};
