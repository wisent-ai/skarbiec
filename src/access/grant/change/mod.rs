// Changes to a grant a consumer already holds that keep its bearer: one exact
// field read taken out (`grant narrow`), and its lifetime made to last until
// revoked (`grant keep`). Neither rotates the bearer, so the machine holding
// it needs nothing delivered.

mod keep;
mod narrow;

pub(in crate::access::grant) use keep::keep_once;
pub(in crate::access::grant) use narrow::narrow_read_once;
