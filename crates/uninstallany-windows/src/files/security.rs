use std::ffi::c_void;
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::io::OwnedHandle;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};

use super::native::{denied, raw};
use crate::registry::current_user_sid;

pub(super) struct PrivateSecurity {
    user: String,
    descriptor: LocalAllocation,
}

impl PrivateSecurity {
    pub(super) fn new() -> io::Result<Self> {
        let user = current_user_sid()?;
        let descriptor: Vec<u16> = format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut pointer = null_mut();
        // SAFETY: The terminated SDDL string is live and the output pointer is writable.
        let success = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                SDDL_REVISION_1,
                &mut pointer,
                null_mut(),
            )
        };
        if success == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            user,
            descriptor: LocalAllocation(pointer),
        })
    }

    pub(super) fn descriptor(&self) -> *mut c_void {
        self.descriptor.0
    }

    pub(super) fn require_private(&self, handle: &OwnedHandle) -> io::Result<()> {
        self.require_restricted_acl(handle, true)
    }

    pub(super) fn require_safe_source(&self, handle: &OwnedHandle) -> io::Result<()> {
        self.require_restricted_acl(handle, false)
    }

    fn require_restricted_acl(
        &self,
        handle: &OwnedHandle,
        private_directory: bool,
    ) -> io::Result<()> {
        let (mut owner, mut acl, mut descriptor) = (null_mut(), null_mut(), null_mut());
        // SAFETY: The file handle is live and the requested output pointers are writable.
        let result = unsafe {
            GetSecurityInfo(
                raw(handle),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let descriptor = LocalAllocation(descriptor);
        if owner.is_null() || acl.is_null() || descriptor.0.is_null() {
            return Err(denied(
                "the file has no verifiable owner or discretionary ACL",
            ));
        }
        if private_directory {
            let (mut control, mut revision) = (0, 0);
            // SAFETY: Windows owns the complete descriptor and the output integers are writable.
            let result =
                unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) };
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            if control & SE_DACL_PROTECTED == 0 || sid_string(owner)? != self.user {
                return Err(denied("the private storage owner or inheritance changed"));
            }
        } else if !self.is_allowed_sid(owner, false)? {
            return Err(denied(
                "the file owner falls outside the private storage scope",
            ));
        }

        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `acl` is owned by the descriptor above and the size buffer matches the class.
        let result = unsafe {
            GetAclInformation(
                acl,
                (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        for index in 0..info.AceCount {
            let mut entry = null_mut();
            // SAFETY: The entry index is bounded by the ACL information and the pointer is writable.
            if unsafe { GetAce(acl, index, &mut entry) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a Windows ACL entry starts with an ACE_HEADER.
            let header = unsafe { &*entry.cast::<ACE_HEADER>() };
            match u32::from(header.AceType) {
                ACCESS_DENIED_ACE_TYPE if !private_directory => continue,
                ACCESS_ALLOWED_ACE_TYPE
                    if usize::from(header.AceSize) >= size_of::<ACCESS_ALLOWED_ACE>() => {}
                _ => {
                    return Err(denied(
                        "unsupported access-control entry for private storage",
                    ));
                }
            }
            // SAFETY: The allow ACE embeds a SID at SidStart and belongs to the live descriptor.
            let sid = unsafe {
                entry
                    .cast::<u8>()
                    .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                    .cast()
            };
            if !self.is_allowed_sid(sid, private_directory)? {
                return Err(denied(
                    "the file grants access outside the private storage scope",
                ));
            }
        }
        Ok(())
    }

    fn is_allowed_sid(&self, sid: PSID, strict: bool) -> io::Result<bool> {
        // SAFETY: Callers use SIDs held by a live Windows security descriptor.
        let is_privileged = unsafe {
            IsWellKnownSid(sid, WinLocalSystemSid) != 0
                || (!strict && IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0)
        };
        Ok(is_privileged || sid_string(sid)? == self.user)
    }
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    // SAFETY: The UID points to a SID owned by a live Windows response.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(text.cast());
    wide_string(text)
}

fn wide_string(text: *const u16) -> io::Result<String> {
    if text.is_null() {
        return Err(io::Error::other("Windows returned a null string"));
    }
    let mut length = 0;
    // SAFETY: Only callers holding a Windows-owned, null-terminated UTF-16 string use this.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: The OS-provided allocation contains all units through the terminator just found.
    let units = unsafe { std::slice::from_raw_parts(text, length) };
    String::from_utf16(units).map_err(io::Error::other)
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: This owns only memory allocated by Windows APIs specifying LocalFree.
        unsafe { LocalFree(self.0) };
    }
}
