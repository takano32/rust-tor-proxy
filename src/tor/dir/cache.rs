//! On-disk cache of directory documents.
//!
//! Starting from a warm cache is the difference between a few seconds and a
//! full bootstrap, and it keeps repeated restarts from hammering the
//! fallback mirrors.

use std::collections::HashSet;
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

    /// Delete every cached microdescriptor whose digest is not in `keep`, and
    /// any temporary file left behind by an interrupted write.
    ///
    /// Without this the cache only ever grows: one `.onion` lookup fetches a
    /// microdescriptor for every HSDir in the network, and the next consensus
    /// replaces most of the digests rather than reusing them.
    pub fn prune_microdescs(&self, keep: &HashSet<[u8; 32]>) -> io::Result<PruneReport> {
        let dir = self.dir.join("microdescs");
        let mut report = PruneReport::default();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            // Nothing has been cached yet, which is not a failure.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(report),
            Err(e) => return Err(e),
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let wanted = crate::util::hex_decode(name)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .is_some_and(|digest| keep.contains(&digest));
            if wanted {
                report.kept += 1;
                continue;
            }
            // Anything whose name is not a digest we want -- including a
            // leftover *.tmp -- has no reader left.
            match fs::remove_file(entry.path()) {
                Ok(()) => report.removed += 1,
                Err(e) => crate::debug!("could not remove {}: {e}", entry.path().display()),
            }
        }
        Ok(report)
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct PruneReport {
    pub kept: usize,
    pub removed: usize,
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

    /// Pruning keeps exactly the digests the caller names and sweeps away
    /// everything else, temporary files included.
    #[test]
    fn pruning_keeps_only_the_wanted_digests() {
        let dir = std::env::temp_dir().join(format!("tor-prune-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cache = Cache::new(&dir);

        // Nothing cached yet: pruning is a no-op rather than an error.
        assert_eq!(
            cache.prune_microdescs(&HashSet::new()).unwrap(),
            PruneReport {
                kept: 0,
                removed: 0
            }
        );

        let keep_digest = [0x11u8; 32];
        let drop_digest = [0x22u8; 32];
        cache.store_microdesc(&keep_digest, b"onion-key\n").unwrap();
        cache.store_microdesc(&drop_digest, b"onion-key\n").unwrap();
        fs::write(dir.join("microdescs").join("half-written.tmp"), b"x").unwrap();

        let keep: HashSet<[u8; 32]> = [keep_digest].into_iter().collect();
        let report = cache.prune_microdescs(&keep).unwrap();
        assert_eq!(
            report,
            PruneReport {
                kept: 1,
                removed: 2
            }
        );
        assert!(cache.load_microdesc(&keep_digest).is_some());
        assert!(cache.load_microdesc(&drop_digest).is_none());
        assert!(!dir.join("microdescs").join("half-written.tmp").exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
