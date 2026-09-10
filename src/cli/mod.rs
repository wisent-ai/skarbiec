// The commands this binary owns itself, as opposed to the ones the access,
// credential, net and runtime layers dispatch. `args` reads the command line
// the same way for all of them.

pub(crate) mod args;
pub(crate) mod items;
pub(crate) mod reads;
pub(crate) mod tools;
