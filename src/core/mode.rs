// POSIX permission bits as the `u32` that `PermissionsExt::mode`,
// `OpenOptionsExt::mode` and `DirBuilderExt::mode` take and answer.
//
// The C library's `S_I*` constants are `u32` on Linux and `u16` on macOS, so
// converting them to `u32` is required on one platform and refused by clippy
// as a useless conversion on the other. The bits are the same on both, so
// every mode Skarbiec writes or checks is stated once here.

/// Owner read and write (`S_IRUSR | S_IWUSR`): every private file.
pub const OWNER_READ_WRITE: u32 = 0o600;
/// Owner read, write and search (`S_IRWXU`): every private directory.
pub const OWNER_ALL: u32 = 0o700;
/// Every group and other bit (`S_IRWXG | S_IRWXO`): an owner-only file holds
/// none of them.
pub const GROUP_AND_OTHER: u32 = 0o077;
/// Group and other write (`S_IWGRP | S_IWOTH`).
pub const GROUP_AND_OTHER_WRITE: u32 = 0o022;
/// Every permission bit (`S_IRWXU | S_IRWXG | S_IRWXO`).
pub const ALL: u32 = 0o777;
