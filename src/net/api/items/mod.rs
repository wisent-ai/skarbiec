// One item, one field, one direction at a time.

mod read;
mod write;

pub(crate) use read::handle_items_read;
pub(crate) use write::handle_items_put;
