// The handlers behind the local HTTP API. The listener and route table live
// in net::http; each module here answers one family of requests.

pub(crate) mod donation;
pub(crate) mod identity;
pub(crate) mod items;
pub(crate) mod lifecycle;
