// The commands this binary owns itself, as opposed to the ones the access,
// credential, net and runtime layers dispatch. `args` reads the command line
// the same way for all of them.

pub(crate) mod args;
pub(crate) mod bulk;
pub(crate) mod copy;
pub(crate) mod generate;
pub(crate) mod help;
pub(crate) mod items;
pub(crate) mod list;
pub(crate) mod merge;
pub(crate) mod prune;
pub(crate) mod reads;
pub(crate) mod rename;
pub(crate) mod retag;
pub(crate) mod tools;
