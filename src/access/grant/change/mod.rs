// Changes to a grant a consumer already holds: one exact field read taken out
// (`grant narrow`), its lifetime made to last until revoked (`grant keep`)
// and its capabilities moved from one item to another (`grant retarget`),
// none of which rotates the bearer, and the grant withdrawn (`grant
// revoke`), one consumer's or every expired one.

mod keep;
mod narrow;
mod retarget;
mod revoke;

pub(in crate::access::grant) use keep::keep_once;
pub(in crate::access::grant) use narrow::narrow_read_once;
pub(in crate::access::grant) use retarget::retarget_once;
pub(in crate::access::grant) use revoke::revoke;
