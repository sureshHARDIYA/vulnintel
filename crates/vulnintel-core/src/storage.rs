//! Simple crash-resistant JSON snapshot storage for offline consumers.
//! This is not a concurrent multi-process database or a scheduled sync engine.
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, io, path::Path};

pub fn load_json<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

pub fn save_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
}
