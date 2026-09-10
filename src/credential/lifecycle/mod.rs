// The two ways a credential operation reaches Weles: `start_operation`
// submits a fresh one, `resume` answers an approval the provider is waiting
// on. What each reads before submitting lives beside them: the flags and the
// item contract in `inputs`, the vault's own answer in `preflight`.

mod inputs;
mod preflight;
mod resume;
mod start;

pub(super) use resume::resume;
pub(super) use start::start_operation;
