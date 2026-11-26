use std::os::unix::ffi::OsStrExt;

use sha2::{Digest, Sha256};

use super::application::{
    MAX_BUNDLE_ENTRIES, MAX_CACHE_ENTRIES, MAX_DEPTH, Tree, feed_bundle_plist, feed_tree_entry,
};
use super::*;
const DIGEST_HEX_LENGTH: usize = 64;
const SCHEMA: u8 = 1;
const ROOT_PATH: &[u8; 32] = &[0; 32];
// Additional BSD file flags from the Darwin SDK's sys/stat.h.
const SF_RESTRICTED: u32 = 0x0008_0000;
const SF_NOUNLINK: u32 = 0x0010_0000;
const PROTECTED_FLAGS: u32 = libc::UF_IMMUTABLE
    | libc::UF_APPEND
    | libc::SF_IMMUTABLE
    | libc::SF_APPEND
    | SF_RESTRICTED
    | SF_NOUNLINK;

/// Identifies every approved object in one isolated macOS directory.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryExpiryTree {
    schema: u8,
    root: StableDirectory,
    entries: Vec<String>,
}

/// The previously approved digest and its file-store directory kind.
pub(crate) enum DirectoryExpiryFingerprint {
    Bundle([u8; 32]),
    Cache([u8; 32]),
}

// Removing an approved child changes a directory's size, links and times.
// Bind its identity, ownership, permissions and flags instead.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StableDirectory {
    id: NodeId,
    born: [i64; 2],
    owner: u32,
    group: u32,
    permissions: u32,
    flags: u32,
}

impl From<&Stat> for StableDirectory {
    fn from(stat: &Stat) -> Self {
        Self::from_entry(&EntryStamp::from_stat(stat), stat.st_flags)
    }
}

impl StableDirectory {
    fn from_entry(stamp: &EntryStamp, flags: u32) -> Self {
        Self {
            id: stamp.id,
            born: stamp.born,
            owner: stamp.owner,
            group: stamp.group,
            permissions: stamp.permissions,
            flags,
        }
    }

    fn matches_entry(&self, stamp: &EntryStamp) -> bool {
        *self == Self::from_entry(stamp, self.flags)
    }
}

impl DirectoryExpiryTree {
    /// Captures exact approved members below a guarded quarantine slot.
    pub(crate) fn capture(
        parent: &OwnedFd,
        name: &OsStr,
        uid: u32,
        fingerprint: DirectoryExpiryFingerprint,
        protected: &[NodeId],
    ) -> io::Result<Self> {
        let (directory, stat) = open_root(parent, name, uid, protected)?;
        let root = StableDirectory::from(&stat);
        let frame = Frame {
            parent,
            name,
            directory: &directory,
            stamp: &root,
            ancestor: None,
        };
        let mut digest = Sha256::new();
        let (expected, tree, limit) = match fingerprint {
            DirectoryExpiryFingerprint::Bundle(expected) => {
                feed_bundle_plist(&directory, &mut digest, uid)?;
                (expected, Tree::Bundle, MAX_BUNDLE_ENTRIES)
            }
            DirectoryExpiryFingerprint::Cache(expected) => {
                (expected, Tree::Cache, MAX_CACHE_ENTRIES)
            }
        };
        let mut entries = Vec::new();
        Walker::new(
            uid,
            protected,
            limit,
            Walk::Capture {
                entries: &mut entries,
                digest: &mut digest,
                tree,
            },
        )
        .contents(&frame, ROOT_PATH, 0)?;
        let captured: [u8; 32] = digest.finalize().into();
        if captured != expected {
            return Err(deny(
                "the directory changed while capturing its expiry inventory",
            ));
        }
        entries.sort_unstable();
        if entries.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(deny("the expiry inventory contains a duplicated entry"));
        }
        Ok(Self {
            schema: SCHEMA,
            root,
            entries,
        })
    }

    /// Binds the captured root to the backup's original directory identity.
    pub(crate) fn matches_root(&self, stamp: &EntryStamp) -> bool {
        self.root.matches_entry(stamp)
    }

    /// Verifies that each surviving member is still one of the approved ones.
    pub(crate) fn verify_remaining(
        &self,
        parent: &OwnedFd,
        name: &OsStr,
        uid: u32,
        protected: &[NodeId],
    ) -> io::Result<()> {
        self.validate()?;
        let (directory, stat) = open_root(parent, name, uid, protected)?;
        let frame = self.verified_root(parent, name, &directory, &stat)?;
        Walker::new(
            uid,
            protected,
            self.entries.len(),
            Walk::Verify(&self.entries),
        )
        .contents(&frame, ROOT_PATH, 0)
    }

    /// Removes surviving approved members and then their empty slot directory.
    pub(crate) fn remove_remaining(
        &self,
        parent: &OwnedFd,
        name: &OsStr,
        uid: u32,
        protected: &[NodeId],
    ) -> io::Result<()> {
        self.verify_remaining(parent, name, uid, protected)?;
        let (directory, stat) = open_root(parent, name, uid, protected)?;
        let frame = self.verified_root(parent, name, &directory, &stat)?;
        Walker::new(
            uid,
            protected,
            self.entries.len(),
            Walk::Remove(&self.entries),
        )
        .contents(&frame, ROOT_PATH, 0)?;
        frame.unlink_directory()?;
        fs::fsync(parent)?;
        Ok(())
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema != SCHEMA || self.entries.len() > MAX_BUNDLE_ENTRIES {
            return Err(invalid("unsupported directory expiry inventory"));
        }
        if self.entries.iter().any(|entry| {
            entry.len() != DIGEST_HEX_LENGTH
                || !entry
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        }) || self.entries.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid("invalid directory expiry entry list"));
        }
        Ok(())
    }

    fn verified_root<'a>(
        &'a self,
        parent: &'a OwnedFd,
        name: &'a OsStr,
        directory: &'a OwnedFd,
        stat: &Stat,
    ) -> io::Result<Frame<'a>> {
        if self.root != StableDirectory::from(stat) {
            return Err(deny(
                "the isolated directory does not match the approved root",
            ));
        }
        Ok(Frame {
            parent,
            name,
            directory,
            stamp: &self.root,
            ancestor: None,
        })
    }
}

struct Frame<'a> {
    parent: &'a OwnedFd,
    name: &'a OsStr,
    directory: &'a OwnedFd,
    stamp: &'a StableDirectory,
    ancestor: Option<&'a Frame<'a>>,
}

impl Frame<'_> {
    fn recheck(&self) -> io::Result<()> {
        if let Some(ancestor) = self.ancestor {
            ancestor.recheck()?;
        }
        if *self.stamp != StableDirectory::from(&entry_stat(self.parent, self.name)?) {
            return Err(deny("an expiry directory moved or changed"));
        }
        Ok(())
    }

    fn unlink_directory(&self) -> io::Result<()> {
        self.recheck()?;
        // The kernel rejects nonempty directories, including late arrivals.
        Ok(fs::unlinkat(self.parent, self.name, AtFlags::REMOVEDIR)?)
    }
}

enum Walk<'a> {
    Capture {
        entries: &'a mut Vec<String>,
        digest: &'a mut Sha256,
        tree: Tree,
    },
    Verify(&'a [String]),
    Remove(&'a [String]),
}

struct Walker<'a> {
    uid: u32,
    protected: &'a [NodeId],
    remaining_entries: usize,
    action: Walk<'a>,
}

impl<'a> Walker<'a> {
    fn new(uid: u32, protected: &'a [NodeId], remaining_entries: usize, action: Walk<'a>) -> Self {
        Self {
            uid,
            protected,
            remaining_entries,
            action,
        }
    }

    fn contents(&mut self, frame: &Frame<'_>, path: &[u8; 32], depth: usize) -> io::Result<()> {
        if depth >= MAX_DEPTH {
            return Err(deny(
                "the isolated directory exceeds the expiry depth limit",
            ));
        }
        let original = EntryStamp::from_stat(&fs::fstat(frame.directory)?);
        let names = self.names(frame.directory)?;
        for name in names {
            self.entry(frame, &name, &child_path(path, &name), depth)?;
        }
        frame.recheck()?;
        if self.is_removing() {
            fs::fsync(frame.directory)?;
        } else if original != EntryStamp::from_stat(&fs::fstat(frame.directory)?) {
            return Err(deny("an expiry directory changed during traversal"));
        }
        Ok(())
    }

    fn names(&mut self, directory: &OwnedFd) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        for entry in fs::Dir::read_from(directory)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            self.remaining_entries = self
                .remaining_entries
                .checked_sub(1)
                .ok_or_else(|| deny("the isolated directory contains unexpected entries"))?;
            names.push(OsString::from_vec(name.to_vec()));
        }
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(deny("the isolated directory returned a duplicate name"));
        }
        Ok(names)
    }

    fn entry(
        &mut self,
        parent: &Frame<'_>,
        name: &OsStr,
        path: &[u8; 32],
        depth: usize,
    ) -> io::Result<()> {
        let stat = entry_stat(parent.directory, name)?;
        check_entry(parent.directory, &stat, self.uid, self.protected)?;
        let kind = FileType::from_raw_mode(stat.st_mode);
        let entry = EntryStamp::from_stat(&stat);
        if let Walk::Capture { digest, tree, .. } = &mut self.action {
            if *tree == Tree::Cache
                && (kind == FileType::Symlink
                    || kind == FileType::Directory && crate::is_bundle_name(Path::new(name)))
            {
                return Err(deny(
                    "a cache contains a link or an independent application bundle",
                ));
            }
            feed_tree_entry(digest, name, depth, &entry)?;
        }
        if kind == FileType::Directory {
            let directory = checked_directory(parent.directory, name, &stat, self.uid)?;
            let stamp = StableDirectory::from_entry(&entry, stat.st_flags);
            self.accept(token(path, b'd', &stamp, &[])?)?;
            let frame = Frame {
                parent: parent.directory,
                name,
                directory: &directory,
                stamp: &stamp,
                ancestor: Some(parent),
            };
            self.contents(&frame, path, depth + 1)?;
            if self.is_removing() {
                frame.unlink_directory()?;
            }
            return Ok(());
        }
        self.accept(leaf_token(
            parent.directory,
            name,
            path,
            &stat,
            &entry,
            self.uid,
        )?)?;
        if self.is_removing() {
            parent.recheck()?;
            check_unchanged(&stat, &entry_stat(parent.directory, name)?)?;
            // An ordinary symlink is unlinked as a leaf. Never open its target.
            fs::unlinkat(parent.directory, name, AtFlags::empty())?;
        }
        Ok(())
    }

    fn accept(&mut self, digest: String) -> io::Result<()> {
        match &mut self.action {
            Walk::Capture { entries, .. } => entries.push(digest),
            Walk::Verify(entries) | Walk::Remove(entries) => {
                if entries.binary_search(&digest).is_err() {
                    return Err(deny(
                        "the isolated directory contains a new or changed entry",
                    ));
                }
            }
        }
        Ok(())
    }

    fn is_removing(&self) -> bool {
        matches!(self.action, Walk::Remove(_))
    }
}

fn open_root(
    parent: &OwnedFd,
    name: &OsStr,
    uid: u32,
    protected: &[NodeId],
) -> io::Result<(OwnedFd, Stat)> {
    let component = name.as_bytes();
    if matches!(component, b"" | b"." | b"..")
        || component.contains(&b'/')
        || component.contains(&0)
    {
        return Err(invalid("directory expiry requires a single slot name"));
    }
    require_private(parent, uid)?;
    require_apfs(parent)?;
    let stat = entry_stat(parent, name)?;
    check_entry(parent, &stat, uid, protected)?;
    Ok((checked_directory(parent, name, &stat, uid)?, stat))
}

/// Checks the volume constraints for descriptor-based expiry traversal.
pub(crate) fn require_apfs(parent: &OwnedFd) -> io::Result<()> {
    require_local(parent)?;
    let info = fs::fstatfs(parent)?;
    let fs_type = info.f_fstypename.map(|byte| byte as u8);
    // APFS excludes directory hard links. On HFS+ a same-device directory
    // alias could otherwise expose children outside the isolated tree.
    if !CStr::from_bytes_until_nul(&fs_type).is_ok_and(|kind| kind.to_bytes() == b"apfs")
        || info.f_flags & libc::MNT_RDONLY as u32 != 0
    {
        return Err(deny(
            "directory expiry requires a writable APFS quarantine volume",
        ));
    }
    Ok(())
}

fn checked_directory(parent: &OwnedFd, name: &OsStr, stat: &Stat, uid: u32) -> io::Result<OwnedFd> {
    let directory = open_subdirectory(parent, name)?;
    require_current_user_directory(&directory, uid)?;
    fs::accessat(
        &directory,
        ".",
        fs::Access::WRITE_OK | fs::Access::EXEC_OK,
        AtFlags::EACCESS,
    )?;
    check_unchanged(stat, &fs::fstat(&directory)?)?;
    Ok(directory)
}

fn check_entry(parent: &OwnedFd, stat: &Stat, uid: u32, protected: &[NodeId]) -> io::Result<()> {
    reject_protected_entry(stat, protected)?;
    if directory_id(parent)?.device != NodeId::from_stat(stat).device {
        return Err(deny("an expiry entry is on an unexpected mounted volume"));
    }
    if stat.st_uid != uid || stat.st_flags & PROTECTED_FLAGS != 0 {
        return Err(deny(
            "an expiry entry is protected or belongs to another account",
        ));
    }
    Ok(())
}

fn check_unchanged(expected: &Stat, observed: &Stat) -> io::Result<()> {
    if EntryStamp::from_stat(expected) != EntryStamp::from_stat(observed)
        || expected.st_flags != observed.st_flags
    {
        return Err(deny("an expiry entry changed during verification"));
    }
    Ok(())
}

fn leaf_token(
    parent: &OwnedFd,
    name: &OsStr,
    path: &[u8; 32],
    stat: &Stat,
    entry: &EntryStamp,
    uid: u32,
) -> io::Result<String> {
    let stamp = (entry, stat.st_flags);
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile if safe_user_entry(stat, uid) => {
            let file = checked_file(parent, name)?;
            check_unchanged(stat, &fs::fstat(&file)?)?;
            if acl_allows_mutation(&file)? {
                return Err(deny("an expiry file permits shared writes"));
            }
            token(path, b'f', &stamp, &[])
        }
        FileType::Symlink if stat.st_nlink == 1 => {
            let mut target = [0; libc::PATH_MAX as usize + 1];
            let length = fs::readlinkat_raw(parent, name, &mut target[..])?;
            if length >= target.len() {
                return Err(deny("an expiry symbolic link exceeds its target limit"));
            }
            check_unchanged(stat, &entry_stat(parent, name)?)?;
            token(path, b'l', &stamp, &target[..length])
        }
        _ => Err(deny(
            "the isolated directory contains a shared or unsupported object",
        )),
    }
}

fn child_path(parent: &[u8; 32], name: &OsStr) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(parent);
    hash.update(name.as_bytes());
    hash.finalize().into()
}

fn token(path: &[u8; 32], kind: u8, stamp: &impl Serialize, extra: &[u8]) -> io::Result<String> {
    let mut hash = Sha256::new();
    hash.update(path);
    hash.update([kind]);
    hash.update(serde_json::to_vec(stamp).map_err(io::Error::other)?);
    hash.update(extra);
    Ok(format!("{:x}", hash.finalize()))
}
