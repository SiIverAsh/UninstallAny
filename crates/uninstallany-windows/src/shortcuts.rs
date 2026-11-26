//! Reads the literal local target from a bounded MS-SHLLINK record.

use std::{io, path::PathBuf};

use super::files::native::LocalPath;

/// Upper bound for reading and parsing an individual shortcut.
pub(super) const MAX_SHORTCUT_BYTES: u64 = 64 * 1024;

const HEADER_LEN: usize = 0x4c;
const CLASS_ID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const TARGET_ID_LIST: u32 = 1 << 0;
const LINK_INFO: u32 = 1 << 1;
const RELATIVE_PATH: u32 = 1 << 3;
const ARGUMENTS: u32 = 1 << 5;
const UNICODE: u32 = 1 << 7;
const STRING_FLAGS: [u32; 5] = [1 << 2, RELATIVE_PATH, 1 << 4, ARGUMENTS, 1 << 6];
// ForceNoLinkInfo, HasExpString, RunInSeparateProcess, HasDarwinID,
// RunAsUser, RunWithShimLayer, PreferEnvironmentPath and UNC aliasing.
const UNSUPPORTED_FLAGS: u32 =
    (1 << 8) | (1 << 9) | (1 << 10) | (1 << 12) | (1 << 13) | (1 << 17) | (1 << 25) | (1 << 26);
const UNKNOWN_FLAGS: u32 = !((1 << 27) - 1);

const LINK_INFO_HEADER_LEN: usize = 0x1c;
const UNICODE_LINK_INFO_HEADER_LEN: usize = 0x24;
const LOCAL_VOLUME_AND_PATH: u32 = 1;
const VOLUME_HEADER_LEN: usize = 0x10;
const FIXED_DRIVE: u32 = 3;

const CONSOLE_BLOCK: (u32, usize) = (0xa000_0002, 0xcc);
const TRACKER_BLOCK: (u32, usize) = (0xa000_0003, 0x60);
const CONSOLE_CODE_PAGE_BLOCK: (u32, usize) = (0xa000_0004, 0x0c);
const ICON_ENVIRONMENT_BLOCK: (u32, usize) = (0xa000_0007, 0x314);

/// The literal local path recorded in LinkInfo, without resolving the shortcut.
pub(super) struct ShortcutTarget {
    pub(super) path: PathBuf,
    pub(super) volume_serial: u32,
    /// Only true when no alternate target or activation arguments were found.
    pub(super) direct: bool,
}

/// Extracts a supported `.lnk` target from bytes obtained through a guarded read.
///
/// Namespace-only and other unsupported shortcut forms return `None`.
/// This function never opens the path, interprets a namespace ID, or loads the shell.
pub(super) fn target(contents: &[u8]) -> io::Result<Option<ShortcutTarget>> {
    if u64::try_from(contents.len()).map_err(|_| malformed())? > MAX_SHORTCUT_BYTES
        || offset(contents, 0)? != HEADER_LEN
        || contents.get(4..20) != Some(CLASS_ID.as_slice())
    {
        return Err(malformed());
    }
    let flags = at_u32(contents, 20)?;
    if flags & LINK_INFO == 0 || flags & (UNSUPPORTED_FLAGS | UNKNOWN_FLAGS) != 0 {
        return Ok(None);
    }
    let mut body = contents.get(HEADER_LEN..).ok_or_else(malformed)?;
    if flags & TARGET_ID_LIST != 0 {
        // Skip the namespace data opaquely. Its presence prevents direct attribution.
        let size = usize::from(at_u16(body, 0)?);
        let (list, rest) = body[2..].split_at_checked(size).ok_or_else(malformed)?;
        if size < 2 || !list.ends_with(&[0, 0]) {
            return Err(malformed());
        }
        body = rest;
    }
    let (info, strings) = body
        .split_at_checked(offset(body, 0)?)
        .ok_or_else(malformed)?;
    let Some((recorded_path, volume_serial, ambiguous_link_info)) = local_link_info(info)? else {
        return Ok(None);
    };
    let (extra, has_arguments) = parse_string_data(strings, flags)?;
    let Some(has_tracker) = parse_extra_data(extra)? else {
        return Ok(None);
    };
    Ok(Some(ShortcutTarget {
        path: recorded_path,
        volume_serial,
        direct: !(flags & (TARGET_ID_LIST | RELATIVE_PATH) != 0
            || has_arguments
            || has_tracker
            || ambiguous_link_info),
    }))
}

fn local_link_info(info: &[u8]) -> io::Result<Option<(PathBuf, u32, bool)>> {
    let header = offset(info, 4)?;
    let unicode = match header {
        LINK_INFO_HEADER_LEN => false,
        UNICODE_LINK_INFO_HEADER_LEN => true,
        _ => return Ok(None),
    };
    if at_u32(info, 8)? != LOCAL_VOLUME_AND_PATH || offset(info, 20)? != 0 {
        return Ok(None);
    }
    let volume = offset(info, 12)?;
    let base = offset(info, 16)?;
    let suffix = offset(info, 24)?;
    if volume < header || base <= volume || suffix <= base {
        return Err(malformed());
    }
    let volume_data = info.get(volume..base).ok_or_else(malformed)?;
    let volume_len = offset(volume_data, 0)?;
    if !(VOLUME_HEADER_LEN + 1..=volume_data.len()).contains(&volume_len) {
        return Err(malformed());
    }
    if at_u32(volume_data, 4)? != FIXED_DRIVE {
        return Ok(None);
    }
    let volume_serial = at_u32(volume_data, 8)?;

    let ansi_base = ansi(info.get(base..suffix).ok_or_else(malformed)?)?;
    if ansi_base.is_empty() {
        return Ok(None);
    }
    let (text, ambiguous) = if unicode {
        let unicode_base = offset(info, 28)?;
        let unicode_suffix = offset(info, 32)?;
        if unicode_base <= suffix || unicode_suffix <= unicode_base {
            return Err(malformed());
        }
        let ansi_suffix = ansi(info.get(suffix..unicode_base).ok_or_else(malformed)?)?;
        let base = utf16(
            info.get(unicode_base..unicode_suffix)
                .ok_or_else(malformed)?,
        )?;
        let suffix = utf16(info.get(unicode_suffix..).ok_or_else(malformed)?)?;
        if base.is_empty() {
            return Ok(None);
        }
        let text = base + &suffix;
        let ansi_path = ascii_path(ansi_base, ansi_suffix);
        // A suffix is useful to display, but direct attribution requires a
        // full literal path in both representations.
        let ambiguous = !suffix.is_empty()
            || !ansi_suffix.is_empty()
            || ansi_path.as_deref() != Some(text.as_str());
        (text, ambiguous)
    } else {
        let suffix = ansi(info.get(suffix..).ok_or_else(malformed)?)?;
        let Some(text) = ascii_path(ansi_base, suffix) else {
            return Ok(None);
        };
        (text, !suffix.is_empty())
    };
    if text.contains(['%', '"'])
        || text.ends_with(['\\', '/'])
        || text.chars().any(char::is_control)
    {
        return Ok(None);
    }
    let path = PathBuf::from(text);
    Ok(LocalPath::parse(&path)
        .ok()
        .map(|_| (path, volume_serial, ambiguous)))
}

fn parse_string_data(mut data: &[u8], flags: u32) -> io::Result<(&[u8], bool)> {
    let wide = flags & UNICODE != 0;
    let mut has_arguments = false;
    for field in STRING_FLAGS {
        if flags & field != 0 {
            let count = usize::from(at_u16(data, 0)?);
            let bytes = if wide { count * 2 } else { count };
            data = data.get(2 + bytes..).ok_or_else(malformed)?;
            has_arguments |= field == ARGUMENTS && count != 0;
        }
    }
    Ok((data, has_arguments))
}

fn parse_extra_data(mut data: &[u8]) -> io::Result<Option<bool>> {
    if data.is_empty() {
        return Ok(Some(false));
    }
    let mut has_tracker = false;
    loop {
        let size = offset(data, 0)?;
        if size < 4 {
            return if data.len() == 4 {
                Ok(Some(has_tracker))
            } else {
                Err(malformed())
            };
        }
        if size < 8 {
            return Err(malformed());
        }
        let (block, rest) = data.split_at_checked(size).ok_or_else(malformed)?;
        match (at_u32(block, 4)?, size) {
            TRACKER_BLOCK => has_tracker = true,
            CONSOLE_BLOCK | CONSOLE_CODE_PAGE_BLOCK | ICON_ENVIRONMENT_BLOCK => {}
            // Other records can introduce a second path or a shell activation route.
            _ => return Ok(None),
        }
        data = rest;
    }
}

fn ascii_path(base: &[u8], suffix: &[u8]) -> Option<String> {
    if !base.is_ascii() || !suffix.is_ascii() {
        return None;
    }
    Some(std::str::from_utf8(base).ok()?.to_owned() + std::str::from_utf8(suffix).ok()?)
}

fn ansi(data: &[u8]) -> io::Result<&[u8]> {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(malformed)?;
    Ok(&data[..end])
}

fn utf16(data: &[u8]) -> io::Result<String> {
    let mut units = Vec::new();
    for unit in data.chunks_exact(2) {
        let unit = u16::from_le_bytes([unit[0], unit[1]]);
        if unit == 0 {
            return String::from_utf16(&units).map_err(|_| malformed());
        }
        units.push(unit);
    }
    Err(malformed())
}

fn at_u16(data: &[u8], start: usize) -> io::Result<u16> {
    let bytes = data.get(start..start + 2).ok_or_else(malformed)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn at_u32(data: &[u8], start: usize) -> io::Result<u32> {
    let bytes = data.get(start..start + 4).ok_or_else(malformed)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn offset(data: &[u8], start: usize) -> io::Result<usize> {
    usize::try_from(at_u32(data, start)?).map_err(|_| malformed())
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Windows shortcut data")
}
