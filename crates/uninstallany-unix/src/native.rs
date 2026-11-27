use std::ffi::{CStr, OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RenameFlags, Stat};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
mod directory_expiry;
#[cfg(target_os = "macos")]
pub(super) use directory_expiry::{DirectoryExpiryFingerprint, DirectoryExpiryTree, require_apfs};
#[cfg(target_os = "linux")]
mod flatpak_tree;
#[cfg(target_os = "linux")]
pub(super) use flatpak_tree::stamp as flatpak_tree_stamp;

const MIN_PW_BUFFER: usize = 1024;
const MAX_PW_BUFFER: usize = 1024 * 1024;
const FOREIGN_WRITE_BITS: u32 = 0o022;
const FOREIGN_PERMISSIONS: u32 = 0o077;

pub(super) const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::DIRECTORY);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(super) struct NodeId {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) mount: u64,
}

impl NodeId {
    #[allow(
        clippy::unnecessary_cast,
        reason = "native stat field widths differ between targets"
    )]
    pub(super) fn from_stat(stat: &Stat) -> Self {
        Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            mount: 0,
        }
    }

    pub(super) fn same_inode(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct EntryStamp {
    id: NodeId,
    owner: u32,
    group: u32,
    permissions: u32,
    links: u64,
    size: i64,
    modified: [i64; 2],
    changed: [i64; 2],
    #[cfg(target_os = "macos")]
    born: [i64; 2],
}

impl EntryStamp {
    #[allow(
        clippy::unnecessary_cast,
        reason = "native stat field widths differ between targets"
    )]
    pub(super) fn from_stat(stat: &Stat) -> Self {
        Self {
            id: NodeId::from_stat(stat),
            owner: stat.st_uid,
            group: stat.st_gid,
            permissions: stat.st_mode as u32,
            links: stat.st_nlink as u64,
            size: stat.st_size as i64,
            modified: [stat.st_mtime as i64, stat.st_mtime_nsec as i64],
            changed: [stat.st_ctime as i64, stat.st_ctime_nsec as i64],
            #[cfg(target_os = "macos")]
            born: [stat.st_birthtime as i64, stat.st_birthtime_nsec as i64],
        }
    }

    pub(super) fn matches_moved(&self, other: &Self) -> bool {
        #[cfg(target_os = "macos")]
        if self.born != other.born {
            return false;
        }
        // A rename itself can change ctime. The remaining fields still describe the same inode.
        self.id == other.id
            && self.owner == other.owner
            && self.group == other.group
            && self.permissions == other.permissions
            && self.links == other.links
            && self.size == other.size
            && self.modified == other.modified
    }
}

pub(super) fn open_absolute(path: &Path) -> io::Result<OwnedFd> {
    let mut fd = fs::open("/", DIRECTORY_FLAGS, Mode::empty())?;
    for part in path.components().skip(1) {
        fd = fs::openat(&fd, part.as_os_str(), DIRECTORY_FLAGS, Mode::empty())?;
    }
    Ok(fd)
}

pub(super) fn open_trusted_path(
    path: &Path,
    uid: u32,
    blocked: &[NodeId],
    state: Option<NodeId>,
) -> io::Result<(OwnedFd, bool)> {
    let mut fd = fs::open("/", DIRECTORY_FLAGS, Mode::empty())?;
    let mut trusted = trusted_directory(&fd, uid)?;
    for part in path.components().skip(1) {
        fd = fs::openat(&fd, part.as_os_str(), DIRECTORY_FLAGS, Mode::empty())?;
        reject_protected(&fd, blocked)?;
        if let Some(state) = state {
            reject_protected(&fd, std::slice::from_ref(&state))?;
        }
        trusted &= trusted_directory(&fd, uid)?;
    }
    Ok((fd, trusted))
}

pub(super) fn protected_id(path: &Path) -> io::Result<NodeId> {
    if path == Path::new("/") {
        return Ok(NodeId::from_stat(&fs::fstat(open_absolute(path)?)?));
    }
    let parent = open_absolute(super::parent_path(path)?)?;
    Ok(NodeId::from_stat(&entry_stat(
        &parent,
        super::filename(path)?,
    )?))
}

pub(super) fn reject_protected(fd: &OwnedFd, blocked: &[NodeId]) -> io::Result<()> {
    if blocked.is_empty() {
        return Ok(());
    }
    reject_protected_entry(&fs::fstat(fd)?, blocked)
}

pub(super) fn reject_protected_entry(stat: &Stat, blocked: &[NodeId]) -> io::Result<()> {
    let id = NodeId::from_stat(stat);
    if blocked.iter().any(|protected| protected.same_inode(id)) {
        return Err(deny("a path component aliases a protected object"));
    }
    Ok(())
}

pub(super) fn open_subdirectory(fd: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
    let child = fs::openat(fd, name, DIRECTORY_FLAGS, Mode::empty())?;
    let parent_id = directory_id(fd)?;
    let child_id = directory_id(&child)?;
    if child_id.device != parent_id.device || child_id.mount != parent_id.mount {
        return Err(deny(
            "nested mount points are outside the discovery or cleanup boundary",
        ));
    }
    Ok(child)
}

pub(super) fn directory_id(fd: &impl AsFd) -> io::Result<NodeId> {
    let id = NodeId::from_stat(&fs::fstat(fd)?);
    #[cfg(target_os = "linux")]
    let id = NodeId {
        mount: mount_id(fd, OsStr::new(""), AtFlags::EMPTY_PATH)?,
        ..id
    };
    Ok(id)
}

#[cfg(target_os = "linux")]
pub(super) fn mount_id(fd: &impl AsFd, name: &OsStr, flags: AtFlags) -> io::Result<u64> {
    let stat = fs::statx(fd, name, flags, fs::StatxFlags::MNT_ID)?;
    if stat.stx_mask & fs::StatxFlags::MNT_ID.bits() == 0 {
        return Err(deny(
            "the kernel could not verify filesystem mount boundaries",
        ));
    }
    Ok(stat.stx_mnt_id)
}

#[cfg(target_os = "macos")]
pub(super) fn mount_id(_fd: &impl AsFd, _name: &OsStr, _flags: AtFlags) -> io::Result<u64> {
    // macOS differs by device number at an ordinary volume mount boundary.
    Ok(0)
}

pub(super) fn entry_stat(fd: &impl AsFd, name: &OsStr) -> io::Result<Stat> {
    Ok(fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW)?)
}

pub(super) fn checked_file(parent: &OwnedFd, name: &OsStr) -> io::Result<File> {
    let snapshot = entry_stat(parent, name)?;
    if FileType::from_raw_mode(snapshot.st_mode) != FileType::RegularFile {
        return Err(deny(
            "metadata must be a regular file, not a link or special object",
        ));
    }
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let fd = fs::openat(parent, name, flags, Mode::empty())?;
    let observed = fs::fstat(&fd)?;
    let parent_id = directory_id(parent)?;
    if EntryStamp::from_stat(&observed) != EntryStamp::from_stat(&snapshot)
        || NodeId::from_stat(&observed).device != parent_id.device
        || directory_id(&fd)?.mount != parent_id.mount
    {
        return Err(deny("metadata changed or crosses a mount boundary"));
    }
    Ok(File::from(fd))
}

#[cfg(target_os = "macos")]
pub(super) use application::cache_directory_stamp;
#[cfg(target_os = "macos")]
pub(super) use application::cask_staging_stamp;
#[cfg(target_os = "macos")]
pub(super) use application::http_storage_directory_stamp;
#[cfg(target_os = "macos")]
pub(super) use application::stamp as application_stamp;

#[cfg(target_os = "macos")]
mod application {
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;

    use sha2::{Digest, Sha256};

    use super::*;

    const MAX_PLIST_BYTES: u64 = 1024 * 1024;
    const HTTP_STORAGE_DATABASE: &[u8] = b"httpstorages.sqlite";
    const HTTP_STORAGE_FILES: [&[u8]; 3] = [
        HTTP_STORAGE_DATABASE,
        b"httpstorages.sqlite-wal",
        b"httpstorages.sqlite-shm",
    ];
    pub(super) const MAX_BUNDLE_ENTRIES: usize = 32_768;
    pub(super) const MAX_CACHE_ENTRIES: usize = 4_096;
    pub(super) const MAX_DEPTH: usize = 48;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Tree<'a> {
        Bundle,
        Cache,
        HttpStorage,
        CaskStaging(&'a OsStr),
    }

    pub(crate) fn stamp(parent: &OwnedFd, name: &OsStr, uid: u32) -> io::Result<[u8; 32]> {
        directory_stamp(parent, name, uid, Tree::Bundle)
    }

    pub(super) fn feed_bundle_plist(
        bundle: &OwnedFd,
        digest: &mut Sha256,
        uid: u32,
    ) -> io::Result<()> {
        let contents = open_subdirectory(bundle, OsStr::new("Contents"))?;
        let mut plist = checked_file(&contents, OsStr::new("Info.plist"))?;
        if !safe_user_entry(&fs::fstat(&plist)?, uid) {
            return Err(deny(
                "application metadata does not belong exclusively to the current user",
            ));
        }
        let mut bytes = Vec::new();
        (&mut plist)
            .take(MAX_PLIST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_PLIST_BYTES {
            return Err(invalid(
                "application Info.plist is empty or exceeds the discovery limit",
            ));
        }
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
        Ok(())
    }

    pub(crate) fn cache_directory_stamp(
        parent: &OwnedFd,
        name: &OsStr,
        uid: u32,
    ) -> io::Result<[u8; 32]> {
        directory_stamp(parent, name, uid, Tree::Cache)
    }

    pub(crate) fn cask_staging_stamp(
        parent: &OwnedFd,
        name: &OsStr,
        staged_app: &OsStr,
        uid: u32,
    ) -> io::Result<[u8; 32]> {
        directory_stamp(parent, name, uid, Tree::CaskStaging(staged_app))
    }

    pub(crate) fn http_storage_directory_stamp(
        parent: &OwnedFd,
        name: &OsStr,
        uid: u32,
    ) -> io::Result<[u8; 32]> {
        directory_stamp(parent, name, uid, Tree::HttpStorage)
    }

    fn directory_stamp(
        parent: &OwnedFd,
        name: &OsStr,
        uid: u32,
        tree: Tree<'_>,
    ) -> io::Result<[u8; 32]> {
        let directory = open_subdirectory(parent, name)?;
        let opened = EntryStamp::from_stat(&fs::fstat(&directory)?);
        require_current_user_directory(&directory, uid)?;
        let mut digest = Sha256::new();
        let (mut remaining, changed) = match tree {
            Tree::Bundle => {
                feed_bundle_plist(&directory, &mut digest, uid)?;
                (
                    MAX_BUNDLE_ENTRIES,
                    "the application bundle changed during verification",
                )
            }
            Tree::Cache => (
                MAX_CACHE_ENTRIES,
                "the cache directory changed during verification",
            ),
            Tree::HttpStorage => (
                HTTP_STORAGE_FILES.len(),
                "the HTTP storage directory changed during verification",
            ),
            Tree::CaskStaging(_) => (
                MAX_CACHE_ENTRIES,
                "the cask's staging directory changed during verification",
            ),
        };
        hash_contents(&directory, &mut digest, &mut remaining, uid, 0, tree)?;
        if opened != EntryStamp::from_stat(&entry_stat(parent, name)?) {
            return Err(deny(changed));
        }
        Ok(digest.finalize().into())
    }

    fn hash_contents(
        directory: &OwnedFd,
        digest: &mut Sha256,
        remaining: &mut usize,
        uid: u32,
        depth: usize,
        tree: Tree<'_>,
    ) -> io::Result<()> {
        if depth >= MAX_DEPTH {
            return Err(deny("the directory tree exceeds the discovery depth limit"));
        }
        let mut names = Vec::new();
        for entry in fs::Dir::read_from(directory)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            *remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| deny("the directory tree exceeds the discovery entry limit"))?;
            names.push(OsString::from_vec(name.to_vec()));
        }
        if tree == Tree::HttpStorage {
            // SQLite sidecars belong to the same database state. Verify the
            // whole set before authorizing one move of its private directory.
            let has_database = names
                .iter()
                .any(|name| name.as_bytes() == HTTP_STORAGE_DATABASE);
            let known_files = names
                .iter()
                .all(|name| HTTP_STORAGE_FILES.contains(&name.as_bytes()));
            if !has_database || !known_files {
                return Err(deny(
                    "HTTP storage must contain its SQLite database and only its known sidecars",
                ));
            }
        }
        names.sort_unstable();
        for name in names {
            let stat = entry_stat(directory, &name)?;
            let entry = EntryStamp::from_stat(&stat);
            let kind = FileType::from_raw_mode(stat.st_mode);
            feed_tree_entry(digest, &name, depth, &entry)?;
            match kind {
                FileType::Directory if tree != Tree::HttpStorage => {
                    if matches!(tree, Tree::Cache | Tree::CaskStaging(_))
                        && crate::is_bundle_name(Path::new(&name))
                    {
                        return Err(deny(
                            "the cache tree contains an independent application bundle",
                        ));
                    }
                    let child = open_subdirectory(directory, &name)?;
                    require_current_user_directory(&child, uid)?;
                    if entry != EntryStamp::from_stat(&fs::fstat(&child)?) {
                        return Err(deny("an included directory changed during verification"));
                    }
                    hash_contents(&child, digest, remaining, uid, depth + 1, tree)?;
                    if entry != EntryStamp::from_stat(&entry_stat(directory, &name)?) {
                        return Err(deny("an included directory changed during verification"));
                    }
                }
                FileType::RegularFile if safe_user_entry(&stat, uid) => {
                    let file = checked_file(directory, &name)?;
                    if entry != EntryStamp::from_stat(&fs::fstat(&file)?) {
                        return Err(deny("an included file changed during verification"));
                    }
                    if acl_allows_mutation(&file)? {
                        return Err(deny("an included file allows shared writes"));
                    }
                }
                FileType::Symlink
                    if stat.st_uid == uid
                        && stat.st_nlink == 1
                        && (tree == Tree::Bundle
                            || matches!(tree, Tree::CaskStaging(app) if depth == 0 && name.as_os_str() == app)) =>
                    {}
                _ => {
                    return Err(deny(
                        "the directory tree contains a shared or unsupported object",
                    ));
                }
            }
        }
        Ok(())
    }

    // Expiry uses this exact encoding when binding its deletion inventory
    // to an existing quarantine fingerprint.
    pub(super) fn feed_tree_entry(
        digest: &mut Sha256,
        name: &OsStr,
        depth: usize,
        entry: &EntryStamp,
    ) -> io::Result<()> {
        digest.update((depth as u64).to_le_bytes());
        digest.update((name.as_bytes().len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        let encoded = serde_json::to_vec(entry).map_err(io::Error::other)?;
        digest.update((encoded.len() as u64).to_le_bytes());
        digest.update(encoded);
        Ok(())
    }
}

#[allow(
    clippy::unnecessary_cast,
    reason = "native mode width is platform defined"
)]
pub(super) fn safe_user_entry(stat: &Stat, uid: u32) -> bool {
    stat.st_uid == uid && stat.st_nlink == 1 && stat.st_mode as u32 & FOREIGN_WRITE_BITS == 0
}

#[allow(
    clippy::unnecessary_cast,
    reason = "native mode width is platform defined"
)]
pub(super) fn trusted_directory(fd: &OwnedFd, uid: u32) -> io::Result<bool> {
    let stat = fs::fstat(fd)?;
    let mode = stat.st_mode as u32;
    // Root-owned sticky directories such as /tmp cannot let peer UIDs replace our entries.
    let ordinary = mode & FOREIGN_WRITE_BITS == 0 || stat.st_uid == 0 && mode & 0o1000 != 0;
    Ok(ordinary && (stat.st_uid == 0 || stat.st_uid == uid) && !acl_allows_mutation(fd)?)
}

pub(super) fn require_current_user_directory(fd: &OwnedFd, uid: u32) -> io::Result<()> {
    if fs::fstat(fd)?.st_uid != uid || !trusted_directory(fd, uid)? {
        return Err(deny(
            "the destination directory must belong to the current user and disallow shared writes",
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn is_sticky_application_directory(fd: &OwnedFd) -> io::Result<bool> {
    let stat = fs::fstat(fd)?;
    Ok(stat.st_uid == 0
        && stat.st_mode & (libc::S_ISVTX | libc::S_IWOTH) == libc::S_ISVTX
        && !acl_allows_mutation(fd)?)
}

#[allow(
    clippy::unnecessary_cast,
    reason = "native mode width is platform defined"
)]
pub(super) fn require_private(fd: &impl AsFd, uid: u32) -> io::Result<()> {
    let stat = fs::fstat(fd)?;
    if stat.st_uid != uid || stat.st_mode as u32 & FOREIGN_PERMISSIONS != 0 {
        return Err(deny(
            "UninstallAny state must be private and belong to the current user",
        ));
    }
    #[cfg(target_os = "macos")]
    if apple_acl::has_access_grant(fd)? {
        // Extended ACLs can grant access beyond the private POSIX mode.
        return Err(deny("UninstallAny state must not have ACL allow grants"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn acl_allows_mutation(_fd: &impl AsFd) -> io::Result<bool> {
    // Linux POSIX ACL effective group/user-class permissions are reflected in mode group bits.
    Ok(false)
}

#[cfg(target_os = "macos")]
pub(super) fn acl_allows_mutation(fd: &impl AsFd) -> io::Result<bool> {
    apple_acl::has_write_grant(fd)
}

#[cfg(target_os = "linux")]
pub(super) fn require_local(fd: &impl AsFd) -> io::Result<()> {
    let kind = fs::fstatfs(fd)?.f_type;
    // Known local filesystem types, with kernel-enforced exclusive rename checked separately.
    if !matches!(
        kind as u64,
        0xef53 | 0x9123683e | 0x58465342 | 0x01021994 | 0x794c7630
    ) {
        return Err(deny("cleanup is restricted to verified local filesystems"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn require_local(fd: &impl AsFd) -> io::Result<()> {
    let info = fs::fstatfs(fd)?;
    let name = info.f_fstypename.map(|byte| byte as u8);
    if !CStr::from_bytes_until_nul(&name)
        .is_ok_and(|name| matches!(name.to_bytes(), b"apfs" | b"hfs"))
        || info.f_flags & libc::MNT_LOCAL as u32 == 0
    {
        return Err(deny("cleanup is restricted to verified local filesystems"));
    }
    if info.f_flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0 {
        return Err(deny("the volume does not enforce file ownership"));
    }
    Ok(())
}

pub(super) fn rename_exclusive(from: (&OwnedFd, &OsStr), to: (&OwnedFd, &OsStr)) -> io::Result<()> {
    // rustix dispatches RENAME_NOREPLACE on Linux and RENAME_EXCL on macOS.
    Ok(fs::renameat_with(
        from.0,
        from.1,
        to.0,
        to.1,
        RenameFlags::NOREPLACE,
    )?)
}

pub(super) fn sync_move(from: &OwnedFd, to: &OwnedFd) -> io::Result<()> {
    let from_synced = fs::fsync(from);
    let to_synced = fs::fsync(to);
    from_synced.and(to_synced).map_err(|error| {
        io::Error::other(format!(
            "the item moved, but the filesystem could not sync both directories: {error}"
        ))
    })
}

pub(super) fn deny(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

pub(super) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(super) fn user_home() -> io::Result<PathBuf> {
    let uid = rustix::process::geteuid().as_raw();
    // SAFETY: sysconf reads system configuration and takes a known selector.
    let recommended = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = usize::try_from(recommended)
        .unwrap_or(MIN_PW_BUFFER)
        .clamp(MIN_PW_BUFFER, MAX_PW_BUFFER);
    loop {
        let mut buffer = vec![0_u8; size];
        let mut entry = MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: entry, found and the writable buffer live through the reentrant lookup.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                size,
                &mut found,
            )
        };
        if status == libc::ERANGE && size < MAX_PW_BUFFER {
            size = (size * 2).min(MAX_PW_BUFFER);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if found.is_null() {
            return Err(deny(
                "the effective account has no system home directory record",
            ));
        }
        // SAFETY: successful non-null lookup initializes the passwd fields and pw_dir
        // points to a NUL-terminated string in the live buffer when present.
        let directory = unsafe { entry.assume_init().pw_dir };
        if directory.is_null() {
            return Err(deny(
                "the effective account has no system home directory record",
            ));
        }
        // SAFETY: the successful lookup keeps the NUL-terminated pw_dir valid in buffer.
        let bytes = unsafe { CStr::from_ptr(directory) }.to_bytes().to_vec();
        let path = PathBuf::from(OsString::from_vec(bytes));
        super::check_absolute(&path)?;
        return Ok(path);
    }
}

#[cfg(target_os = "macos")]
mod apple_acl {
    use std::ffi::c_void;
    use std::io;
    use std::os::fd::{AsFd, AsRawFd};
    use std::ptr::{NonNull, null_mut};

    const ACL_TYPE_EXTENDED: u32 = 0x100;
    const ACL_FIRST_ENTRY: i32 = 0;
    const ACL_NEXT_ENTRY: i32 = -1;
    const ACL_EXTENDED_ALLOW: u32 = 1;
    // ACL_WRITE_DATA, ACL_DELETE, ACL_APPEND_DATA, ACL_DELETE_CHILD, ACL_WRITE_ATTRIBUTES,
    // ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER from macOS sys/acl.h.
    const ACL_MUTATION: u64 =
        (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: u32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, id: libc::c_int, entry: *mut *mut c_void)
        -> libc::c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut u32) -> libc::c_int;
        fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> libc::c_int;
        fn acl_free(value: *mut c_void) -> libc::c_int;
    }

    struct Acl(NonNull<c_void>);

    impl Drop for Acl {
        fn drop(&mut self) {
            // SAFETY: the pointer was returned by acl_get_fd_np and has one owner.
            unsafe { acl_free(self.0.as_ptr()) };
        }
    }

    pub(super) fn has_write_grant(fd: &impl AsFd) -> io::Result<bool> {
        has_allow_grant(fd, ACL_MUTATION)
    }

    pub(super) fn has_access_grant(fd: &impl AsFd) -> io::Result<bool> {
        has_allow_grant(fd, u64::MAX)
    }

    fn has_allow_grant(fd: &impl AsFd, mask: u64) -> io::Result<bool> {
        // SAFETY: fd remains valid, and the ACL type is the macOS extended type.
        let pointer = unsafe { acl_get_fd_np(fd.as_fd().as_raw_fd(), ACL_TYPE_EXTENDED) };
        let Some(pointer) = NonNull::new(pointer) else {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOATTR)) {
                return Ok(false);
            }
            return Err(error);
        };
        let acl = Acl(pointer);
        let mut id = ACL_FIRST_ENTRY;
        loop {
            let mut entry = null_mut();
            // SAFETY: acl remains valid; entry receives an opaque ACL-owned pointer.
            let status = unsafe { acl_get_entry(acl.0.as_ptr(), id, &mut entry) };
            if status != 0 {
                let error = io::Error::last_os_error();
                // Darwin reports EINVAL at the end of an already-started ACL.
                let end_of_entries =
                    id == ACL_NEXT_ENTRY && error.raw_os_error() == Some(libc::EINVAL);
                if end_of_entries || error.raw_os_error() == Some(libc::ENOENT) {
                    return Ok(false);
                }
                return Err(error);
            }
            let mut tag = 0;
            let mut permissions = 0;
            // SAFETY: the entry is ACL-owned and both result pointers are valid for C writes.
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0
                || unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if tag == ACL_EXTENDED_ALLOW && permissions & mask != 0 {
                return Ok(true);
            }
            id = ACL_NEXT_ENTRY;
        }
    }
}
