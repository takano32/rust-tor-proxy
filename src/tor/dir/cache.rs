//! On-disk cache of directory documents.
//!
//! Starting from a warm cache is the difference between a few seconds and a
//! full bootstrap, and it keeps repeated restarts from hammering the
//! fallback mirrors.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::util::hex_encode;

pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn ensure_dir(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    pub fn load(&self, name: &str) -> Option<Vec<u8>> {
        fs::read(self.dir.join(name)).ok()
    }

    pub fn store(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let path = self.dir.join(name);
        self.ensure_dir(&path)?;
        // Write beside the target and rename, so a crash cannot leave a
        // half-written consensus that would fail verification on next start.
        let temp = path.with_extension("tmp");
        fs::write(&temp, data)?;
        fs::rename(&temp, &path)
    }

    fn microdesc_path(&self, digest: &[u8; 32]) -> PathBuf {
        self.dir.join("microdescs").join(hex_encode(digest))
    }

    pub fn load_microdesc(&self, digest: &[u8; 32]) -> Option<Vec<u8>> {
        fs::read(self.microdesc_path(digest)).ok()
    }

    pub fn store_microdesc(&self, digest: &[u8; 32], data: &[u8]) -> io::Result<()> {
        let path = self.microdesc_path(digest);
        self.ensure_dir(&path)?;
        fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_documents_and_microdescriptors() {
        let dir = std::env::temp_dir().join(format!("tor-cache-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cache = Cache::new(&dir);

        assert!(cache.load("consensus").is_none());
        cache.store("consensus", b"hello").unwrap();
        assert_eq!(cache.load("consensus").unwrap(), b"hello");

        let digest = [0xabu8; 32];
        assert!(cache.load_microdesc(&digest).is_none());
        cache.store_microdesc(&digest, b"onion-key\n").unwrap();
        assert_eq!(cache.load_microdesc(&digest).unwrap(), b"onion-key\n");
        // No stray temporary file survives a successful store.
        assert!(!dir.join("consensus.tmp").exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
