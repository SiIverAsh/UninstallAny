use std::io;
use std::marker::PhantomData;
use std::mem::{align_of, size_of, size_of_val};
use std::ptr::null;
use std::rc::Rc;
use std::slice;

use uninstallany_core::{Access, Cancellation, Category, Proposal, Result, Risk, Scan, Target};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};
use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL,
    SERVICE_WIN32,
};

use super::uninstall::{RegisteredScope, service_image};

// These are the per-call limits of EnumServicesStatusExW and QueryServiceConfigW.
const ENUM_BUFFER_BYTES: usize = 256 * 1024;
const CONFIG_BUFFER_BYTES: usize = 8 * 1024;
const MAX_ENUM_PAGES: usize = 4;

/// Initializes COM for the lifetime of the Windows inventory calls on this thread.
pub(super) struct ComApartment(PhantomData<Rc<()>>);

impl ComApartment {
    pub(super) fn initialize() -> io::Result<Self> {
        // SAFETY: null is reserved, and success is balanced on this same thread.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .map_err(io::Error::other)?;
        Ok(Self(PhantomData))
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: success, including S_FALSE, acquired one thread-local COM reference.
        unsafe { CoUninitialize() };
    }
}

/// Looks for an application's directly configured Win32 service executables.
pub(super) fn discover_services(scope: &RegisteredScope, cancel: &Cancellation) -> Result<Scan> {
    let manager = open_service_manager(cancel)?;
    let mut inventory = Scan::default();
    let mut resume = 0;
    let mut page = vec![0usize; ENUM_BUFFER_BYTES / size_of::<usize>()];
    let mut config = vec![0usize; CONFIG_BUFFER_BYTES / size_of::<usize>()];
    let mut unreadable = 0usize;

    for _ in 0..MAX_ENUM_PAGES {
        cancel.check()?;
        let (count, has_more) = enum_services(&manager, &mut page, &mut resume)?;
        // SAFETY: enum_services initialized and verified this count of aligned
        // service status structures, and page remains borrowed during access.
        let entries = unsafe {
            slice::from_raw_parts(page.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), count)
        };
        for entry in entries {
            cancel.check()?;
            let item = (|| -> io::Result<Option<Proposal>> {
                let name = read_wide(&page, entry.lpServiceName)?;
                let display_name = read_wide(&page, entry.lpDisplayName)?;
                let command = query_command(&manager, &name, &mut config)?;
                Ok(service_image(&command, scope)?.map(|image| Proposal {
                    target: Target::Reference(format!(
                        "Windows service: {display_name} ({name}) — {}",
                        image.path.display()
                    )),
                    category: Category::Service,
                    evidence: image.evidence,
                    reason: image.reason(
                        "SCM service executable matches the verified application directory",
                    ),
                    risk: Risk::High,
                    access: Access::ReadOnly(
                        "service configuration and state restore are not implemented".into(),
                    ),
                }))
            })();
            match item {
                Ok(Some(service)) => inventory.proposals.push(service),
                Ok(None) => {}
                Err(_) => unreadable += 1,
            }
        }
        if !has_more {
            break;
        }
    }

    if resume != 0 {
        inventory
            .warnings
            .push("Windows service enumeration reached its bounded page limit".to_owned());
    }
    if unreadable > 0 {
        inventory.warnings.push(format!(
            "could not inspect {unreadable} Windows services or their configured executable paths"
        ));
    }
    Ok(inventory)
}

fn open_service_manager(cancel: &Cancellation) -> Result<ServiceHandle> {
    cancel.check()?;
    // SAFETY: null names select the local active SCM database. Only query rights
    // are requested, so the handle cannot be used to start or change services.
    let manager = unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    Ok(ServiceHandle::new(manager)?)
}

fn enum_services(
    manager: &ServiceHandle,
    buffer: &mut [usize],
    resume: &mut u32,
) -> io::Result<(usize, bool)> {
    let mut needed = 0;
    let mut count = 0;
    let capacity = size_of_val(buffer);
    // SAFETY: buffer has pointer alignment and is writable for capacity bytes.
    // These handles and outputs have the lifetimes required by the SCM API.
    let ok = unsafe {
        EnumServicesStatusExW(
            manager.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buffer.as_mut_ptr().cast(),
            capacity as u32,
            &mut needed,
            &mut count,
            resume,
            null(),
        )
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
            return Err(error);
        }
        if count == 0 || *resume == 0 {
            return Err(invalid_service_data(
                "Windows service enumeration made no progress",
            ));
        }
    }
    let count = count as usize;
    if count > capacity / size_of::<ENUM_SERVICE_STATUS_PROCESSW>() {
        return Err(invalid_service_data(
            "Windows reported too many service entries for the supplied buffer",
        ));
    }
    Ok((count, ok == 0))
}

fn query_command(manager: &ServiceHandle, name: &str, buffer: &mut [usize]) -> io::Result<String> {
    let name: Vec<_> = name.encode_utf16().chain([0]).collect();
    // SAFETY: manager is live and name is NUL-terminated.
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_CONFIG) };
    let service = ServiceHandle::new(service)?;
    let mut needed = 0;
    let capacity = size_of_val(buffer);
    let query = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: the buffer has pointer alignment and room for the native header
    // and string data. The API checks capacity and reports insufficient space.
    if unsafe { QueryServiceConfigW(service.0, query, capacity as u32, &mut needed) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call initialized the query header at this address.
    let binary_path = unsafe { (*query).lpBinaryPathName };
    read_wide(buffer, binary_path)
}

fn read_wide(buffer: &[usize], text: *const u16) -> io::Result<String> {
    let start = buffer.as_ptr() as usize;
    let capacity = size_of_val(buffer);
    let offset = (text as usize)
        .checked_sub(start)
        .filter(|offset| *offset < capacity && offset % align_of::<u16>() == 0)
        .ok_or_else(|| invalid_service_data("Windows returned text outside the service buffer"))?;
    // SAFETY: offset is aligned and in the live buffer. Bound the read to its
    // remaining full UTF-16 units before scanning for the terminator.
    let units = unsafe {
        slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
            (capacity - offset) / size_of::<u16>(),
        )
    };
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid_service_data("Windows returned text with no UTF-16 terminator"))?;
    String::from_utf16(&units[..end])
        .map_err(|_| invalid_service_data("Windows returned invalid UTF-16 in the service buffer"))
}

fn invalid_service_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct ServiceHandle(SC_HANDLE);

impl ServiceHandle {
    fn new(handle: SC_HANDLE) -> io::Result<Self> {
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: this uniquely owns a live SCM or service handle.
        unsafe { CloseServiceHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_discovery_stops_before_opening_the_scm() {
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            open_service_manager(&cancel),
            Err(uninstallany_core::Error::Cancelled)
        ));
    }

    #[test]
    fn service_text_reader_stays_within_its_native_buffer() {
        let buffer = [usize::from(b's')];
        let start = buffer.as_ptr().cast::<u16>();
        assert_eq!(read_wide(&buffer, start).unwrap(), "s");
        assert!(read_wide(&buffer, null()).is_err());
        let unterminated = [usize::MAX];
        assert!(read_wide(&unterminated, unterminated.as_ptr().cast()).is_err());
    }
}
