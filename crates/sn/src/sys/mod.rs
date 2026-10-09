//! Thin, read-mostly wrappers over Linux `/proc`, `/sys` and `nft`. No external
//! binaries except `nft` (a documented dependency of watch/enforce).

pub mod cgroup;
pub mod fw;
pub mod netstat;
pub mod proc;
