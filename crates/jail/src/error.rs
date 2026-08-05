use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JailError {
    #[error("Path escape attempt detected: '{requested}' is outside jail root '{jail_root}'")]
    PathOutsideJail {
        requested: PathBuf,
        jail_root: PathBuf,
    },

    #[error("Invalid path specification: {0}")]
    InvalidPath(String),

    #[error("I/O error during path canonicalization: {0}")]
    Io(#[from] std::io::Error),
}
