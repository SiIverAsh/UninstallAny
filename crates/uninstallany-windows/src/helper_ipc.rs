//! A single local request and result between the GUI and the elevated helper.

#[cfg(feature = "privileged-helper")]
use std::ffi::c_void;
use std::io;
use std::mem::{replace, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use uuid::Uuid;
#[cfg(feature = "privileged-helper")]
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_PATH_NOT_FOUND, ERROR_PIPE_CONNECTED, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
#[cfg(feature = "privileged-helper")]
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
#[cfg(feature = "privileged-helper")]
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA,
    OPEN_EXISTING, ReadFile, SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT, SYNCHRONIZE, WriteFile,
};
#[cfg(feature = "privileged-helper")]
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
#[cfg(feature = "privileged-helper")]
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcessId, GetProcessId, WaitForSingleObject,
};
use windows_sys::core::BOOL;

const MAX_FRAME_BYTES: u32 = 4_096;
const HEADER_BYTES: u32 = size_of::<u32>() as u32;
#[cfg(feature = "privileged-helper")]
const PIPE_BUFFER_BYTES: u32 = HEADER_BYTES + MAX_FRAME_BYTES;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_POLL_MS: u32 = 25;
const SEND_TIMEOUT: Duration = Duration::from_secs(15);
const CLIENT_ACCESS: u32 = FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

/// A fresh endpoint created by the elevated helper after pinning its GUI caller.
#[cfg(feature = "privileged-helper")]
pub(super) struct Server {
    pipe: OwnedHandle,
}

#[cfg(feature = "privileged-helper")]
impl Server {
    /// Creates the only instance, granting the verified caller just client access.
    pub(super) fn create(token: Uuid, caller_sid: &str) -> io::Result<Self> {
        let name = pipe_name(token);
        let security = PipeSecurity::new(caller_sid)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        };
        // SAFETY: the name, security descriptor and attributes remain live for the call.
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &attributes,
            )
        };
        Ok(Self {
            pipe: own_handle(pipe)?,
        })
    }

    /// Accepts only the original GUI process already pinned before creating the pipe.
    pub(super) fn accept(self, caller: &OwnedHandle) -> io::Result<Channel> {
        let pipe = self.pipe.as_raw_handle();
        let deadline = deadline(CONNECT_TIMEOUT)?;
        overlapped(pipe, deadline, IoKind::Connect, |operation| {
            // SAFETY: the server handle stays live and operation owns a completion event.
            unsafe { ConnectNamedPipe(pipe, operation) }
        })?;
        verify_peer(pipe, caller, Peer::Client)?;
        Ok(Channel::new(self.pipe))
    }
}

/// Connects only to the exact elevated process returned by the authorized launch.
pub(super) fn connect(token: Uuid, helper: &OwnedHandle) -> io::Result<Channel> {
    let name = pipe_name(token);
    let deadline = deadline(CONNECT_TIMEOUT)?;
    let pipe = loop {
        let pause = wait_millis(deadline)?.min(CONNECT_POLL_MS);
        // SAFETY: the local name is terminated and contains a typed UUID. No
        // impersonation or identification permission is granted to the server.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                CLIENT_ACCESS,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                null_mut(),
            )
        };
        match own_handle(handle) {
            Ok(pipe) => break pipe,
            Err(error)
                if matches!(
                    raw_error(&error),
                    Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
                ) =>
            {
                // SAFETY: waiting on the live launch handle stops the retry if the helper exits.
                match unsafe { WaitForSingleObject(helper.as_raw_handle(), pause) } {
                    WAIT_TIMEOUT => {}
                    WAIT_FAILED => return Err(io::Error::last_os_error()),
                    _ => return Err(denied("the elevated helper exited before opening its pipe")),
                }
            }
            Err(error) => return Err(error),
        }
    };
    verify_peer(pipe.as_raw_handle(), helper, Peer::Server)?;
    Ok(Channel::new(pipe))
}

/// One authenticated exchange. No code may attach a second request to the channel.
pub(super) struct Channel {
    pipe: OwnedHandle,
    can_send: bool,
    can_receive: bool,
}

impl Channel {
    fn new(pipe: OwnedHandle) -> Self {
        Self {
            pipe,
            can_send: true,
            can_receive: true,
        }
    }

    /// Sends one bounded frame within the same deadline, even after short writes.
    pub(super) fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        if !replace(&mut self.can_send, false) {
            return Err(invalid("the helper channel can only send one frame"));
        }
        let length = u32::try_from(bytes.len())
            .map_err(|_| invalid("the helper frame exceeds the size limit"))?;
        frame_length(length)?;
        let mut frame = Vec::with_capacity(HEADER_BYTES as usize + bytes.len());
        frame.extend(length.to_le_bytes());
        frame.extend_from_slice(bytes);
        let pipe = self.pipe.as_raw_handle();
        let deadline = deadline(SEND_TIMEOUT)?;
        let mut remaining = frame.as_slice();
        while !remaining.is_empty() {
            let written = overlapped(pipe, deadline, IoKind::Transfer, |operation| {
                // SAFETY: remaining stays live until the overlapped operation has finished.
                unsafe {
                    WriteFile(
                        pipe,
                        remaining.as_ptr(),
                        remaining.len() as u32,
                        null_mut(),
                        operation,
                    )
                }
            })? as usize;
            if written == 0 || written > remaining.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the helper pipe did not finish writing the frame",
                ));
            }
            remaining = &remaining[written..];
        }
        Ok(())
    }

    /// Receives one bounded frame, validating length before allocating its contents.
    pub(super) fn receive(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        if !replace(&mut self.can_receive, false) {
            return Err(invalid("the helper channel can only receive one frame"));
        }
        let deadline = deadline(timeout)?;
        let mut header = [0; HEADER_BYTES as usize];
        self.read_exact(&mut header, deadline)?;
        let length = frame_length(u32::from_le_bytes(header))?;
        let mut bytes = vec![0; length as usize];
        self.read_exact(&mut bytes, deadline)?;
        Ok(bytes)
    }

    fn read_exact(&self, mut remaining: &mut [u8], deadline: Instant) -> io::Result<()> {
        let pipe = self.pipe.as_raw_handle();
        while !remaining.is_empty() {
            let read = overlapped(pipe, deadline, IoKind::Transfer, |operation| {
                // SAFETY: remaining is writable for the requested count and is
                // never reused while the overlapped read remains pending.
                unsafe {
                    ReadFile(
                        pipe,
                        remaining.as_mut_ptr(),
                        remaining.len() as u32,
                        null_mut(),
                        operation,
                    )
                }
            })? as usize;
            if read == 0 || read > remaining.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the helper pipe did not finish reading the frame",
                ));
            }
            remaining = &mut remaining[read..];
        }
        Ok(())
    }
}

enum Peer {
    #[cfg(feature = "privileged-helper")]
    Client,
    Server,
}

fn verify_peer(pipe: HANDLE, expected: &OwnedHandle, peer: Peer) -> io::Result<()> {
    let process = expected.as_raw_handle();
    // SAFETY: the caller keeps the expected process handle live through verification.
    let expected_id = unsafe { GetProcessId(process) };
    if expected_id == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut actual_id = 0;
    // SAFETY: pipe is a connected named pipe and actual_id is a writable output.
    let result = unsafe {
        match peer {
            #[cfg(feature = "privileged-helper")]
            Peer::Client => GetNamedPipeClientProcessId(pipe, &mut actual_id),
            Peer::Server => GetNamedPipeServerProcessId(pipe, &mut actual_id),
        }
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    if actual_id != expected_id {
        return Err(denied("unexpected process connected to the helper pipe"));
    }
    // SAFETY: this process always has a valid ID, and both session lookups use live PIDs.
    let own_session = interactive_session(unsafe { GetCurrentProcessId() })?;
    if interactive_session(actual_id)? != own_session {
        return Err(denied(
            "the helper pipe peer belongs to a different session",
        ));
    }
    // SAFETY: the process handle is live and a zero timeout is a liveness probe.
    match unsafe { WaitForSingleObject(process, 0) } {
        WAIT_TIMEOUT => Ok(()),
        WAIT_OBJECT_0 => Err(denied("the expected helper pipe peer has already exited")),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(denied(
            "the helper pipe peer liveness could not be verified",
        )),
    }
}

fn interactive_session(pid: u32) -> io::Result<u32> {
    let mut session = 0;
    // SAFETY: Windows checks the process ID and owns no references to the writable output.
    if unsafe { ProcessIdToSessionId(pid, &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if session == 0 {
        return Err(denied(
            "the helper pipe is restricted to interactive sessions",
        ));
    }
    Ok(session)
}

#[derive(Clone, Copy)]
enum IoKind {
    #[cfg(feature = "privileged-helper")]
    Connect,
    Transfer,
}

impl IoKind {
    fn is_connect(self) -> bool {
        match self {
            #[cfg(feature = "privileged-helper")]
            Self::Connect => true,
            Self::Transfer => false,
        }
    }
}

fn overlapped(
    pipe: HANDLE,
    deadline: Instant,
    kind: IoKind,
    start: impl FnOnce(*mut OVERLAPPED) -> BOOL,
) -> io::Result<u32> {
    wait_millis(deadline)?;
    // SAFETY: a private unnamed manual-reset event uses the default descriptor.
    let event = own_handle(unsafe { CreateEventW(null(), 1, 0, null()) })?;
    let mut operation = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..OVERLAPPED::default()
    };
    let mut count = 0;
    if start(&mut operation) != 0 {
        if kind.is_connect() {
            return Ok(0);
        }
        // SAFETY: the I/O already completed and supplies its result in operation.
        if unsafe { GetOverlappedResult(pipe, &operation, &mut count, 0) } != 0 {
            return Ok(count);
        }
        return Err(io::Error::last_os_error());
    }
    let error = io::Error::last_os_error();
    let code = raw_error(&error);
    if kind.is_connect() && code == Some(ERROR_PIPE_CONNECTED) {
        return Ok(0);
    }
    if code != Some(ERROR_IO_PENDING) {
        return Err(error);
    }
    let wait = wait_millis(deadline).and_then(|millis| {
        // SAFETY: operation is still live and records this exact pending pipe I/O.
        let completed = unsafe { GetOverlappedResultEx(pipe, &operation, &mut count, millis, 0) };
        if completed != 0 {
            Ok(count)
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == i32::try_from(WAIT_TIMEOUT).ok() {
                Err(timed_out())
            } else {
                Err(error)
            }
        }
    });
    if wait.is_err() {
        // SAFETY: cancellation alone does not free the operation's buffers.
        // Drain its completion before the event, stack and caller's buffer are released.
        unsafe {
            CancelIoEx(pipe, &operation);
            GetOverlappedResult(pipe, &operation, &mut count, 1);
        }
    }
    wait
}

#[cfg(feature = "privileged-helper")]
struct PipeSecurity(*mut c_void);

#[cfg(feature = "privileged-helper")]
impl PipeSecurity {
    fn new(caller_sid: &str) -> io::Result<Self> {
        let Some(sid_fields) = caller_sid.strip_prefix("S-1-") else {
            return Err(invalid("the verified GUI has an invalid user SID"));
        };
        if !sid_fields
            .split('-')
            .all(|field| !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(invalid("the verified GUI has an invalid user SID"));
        }
        // The explicit medium label permits the authenticated ordinary GUI to
        // write this pipe even though its creator is elevated. Low integrity
        // processes remain unable to write, including those with the same SID.
        // Client rights omit generic write, which grants server instance creation.
        let descriptor: Vec<u16> = format!(
            "D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;{CLIENT_ACCESS:#x};;;{caller_sid})S:(ML;;NW;;;ME)"
        )
        .encode_utf16()
        .chain([0])
        .collect();
        let mut pointer = null_mut();
        // SAFETY: the SDDL is terminated, the SID came from the process token,
        // and pointer receives the allocated security descriptor on success.
        let result = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                SDDL_REVISION_1,
                &mut pointer,
                null_mut(),
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        if pointer.is_null() {
            return Err(denied(
                "Windows returned no helper pipe security descriptor",
            ));
        }
        Ok(Self(pointer))
    }
}

#[cfg(feature = "privileged-helper")]
impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: the SDDL conversion allocated this descriptor with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

fn pipe_name(token: Uuid) -> Vec<u16> {
    format!(r"\\.\pipe\UninstallAny.Helper.{token}")
        .encode_utf16()
        .chain([0])
        .collect()
}

fn own_handle(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call transferred a single ownership of this handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn raw_error(error: &io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}

fn frame_length(length: u32) -> io::Result<u32> {
    if !(1..=MAX_FRAME_BYTES).contains(&length) {
        return Err(invalid(
            "the helper frame is empty or exceeds the size limit",
        ));
    }
    Ok(length)
}

fn deadline(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| invalid("helper pipe timeout is out of range"))
}

fn wait_millis(deadline: Instant) -> io::Result<u32> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(timed_out());
    }
    // Windows reserves u32::MAX for an unbounded wait.
    let millis = remaining.as_millis().clamp(1, u128::from(u32::MAX - 1));
    u32::try_from(millis).map_err(io::Error::other)
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "the helper pipe operation timed out",
    )
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
