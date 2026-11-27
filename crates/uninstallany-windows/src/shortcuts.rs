//! Reads local targets and exact target ID lists from bounded MS-SHLLINK data.

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
const NAME_STRING: u32 = 1 << 2;
const RELATIVE_PATH: u32 = 1 << 3;
const ARGUMENTS: u32 = 1 << 5;
const ICON_LOCATION: u32 = 1 << 6;
const UNICODE: u32 = 1 << 7;
const STRING_FLAGS: [u32; 5] = [NAME_STRING, RELATIVE_PATH, 1 << 4, ARGUMENTS, ICON_LOCATION];
// ForceNoLinkInfo, HasExpString, RunInSeparateProcess, HasDarwinID,
// RunAsUser, RunWithShimLayer, PreferEnvironmentPath and UNC aliasing.
const UNSUPPORTED_FLAGS: u32 =
    (1 << 8) | (1 << 9) | (1 << 10) | (1 << 12) | (1 << 13) | (1 << 17) | (1 << 25) | (1 << 26);
const UNKNOWN_FLAGS: u32 = !((1 << 27) - 1);
const PRESENTATION_FLAGS: u32 = NAME_STRING | ICON_LOCATION | UNICODE;
// ForceNoLinkTrack, DisableLinkPathTracking, DisableKnownFolderTracking,
// and DisableKnownFolderAlias cannot introduce an alternate launch target.
const SUPPRESS_TRACKING_FLAGS: u32 = (1 << 18) | (1 << 20) | (1 << 21) | (1 << 22);
const STARTUP_FLAGS: u32 = LINK_INFO | PRESENTATION_FLAGS | SUPPRESS_TRACKING_FLAGS;
// MS-SHLLINK LinkFlags: presentation, suppressing LinkInfo and tracking,
// and collecting metadata on save. No ExtraData blocks are accepted below.
const PACKAGED_FLAGS: u32 =
    TARGET_ID_LIST | PRESENTATION_FLAGS | SUPPRESS_TRACKING_FLAGS | (1 << 8) | (1 << 19);
const MAX_PRESENTATION_UNITS: usize = 260;

const HOTKEY_OFFSET: usize = 0x40;
const RESERVED_HEADER_FIELDS: usize = 0x42;
const ID_TERMINATOR: [u8; 2] = [0; 2];
const EXTRA_TERMINATOR: [u8; 4] = [0; 4];

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
    let flags = shortcut_flags(contents)?;
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

/// Reads the literal executable path and fixed volume recorded by a Startup link.
///
/// Accepts only LinkInfo, optional name/icon presentation, and an absent or
/// zero ExtraData terminator. Activation strings, alternate targets, and
/// startup hotkeys are excluded. No Shell resolution or file open occurs.
pub(super) fn startup_target(contents: &[u8]) -> io::Result<Option<ShortcutTarget>> {
    let flags = shortcut_flags(contents)?;
    if flags & LINK_INFO == 0
        || flags & !STARTUP_FLAGS != 0
        || at_u16(contents, HOTKEY_OFFSET)? != 0
    {
        return Ok(None);
    }
    check_reserved_header(contents)?;
    let body = &contents[HEADER_LEN..];
    let (info, strings) = body
        .split_at_checked(offset(body, 0)?)
        .ok_or_else(malformed)?;
    let Some((path, volume_serial, false)) = local_link_info(info)? else {
        return Ok(None);
    };
    if !path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        return Ok(None);
    }
    let extra = skip_presentation(strings, flags)?;
    if !extra.is_empty() && extra != EXTRA_TERMINATOR {
        return Ok(None);
    }
    Ok(Some(ShortcutTarget {
        path,
        volume_serial,
        direct: true,
    }))
}

/// Returns the one target ID list, including its terminator, for byte comparison.
///
/// Supports links with no LinkInfo or activation strings. Only name and icon
/// presentation strings and an optional zero ExtraData terminator are used.
/// Item data stays opaque. The caller must compare the entire list with a
/// trusted packaged-app target before using it as attribution evidence.
pub(super) fn packaged_target_id(contents: &[u8]) -> io::Result<Option<&[u8]>> {
    let flags = shortcut_flags(contents)?;
    if flags & TARGET_ID_LIST == 0 || flags & !PACKAGED_FLAGS != 0 {
        return Ok(None);
    }
    check_reserved_header(contents)?;

    let body = &contents[HEADER_LEN..];
    let size = usize::from(at_u16(body, 0)?);
    let (list, strings) = body[2..].split_at_checked(size).ok_or_else(malformed)?;
    let mut items = list;
    // Walk item lengths so an early terminator cannot hide a different ID list.
    while items.len() > ID_TERMINATOR.len() {
        let size = usize::from(at_u16(items, 0)?);
        if size <= ID_TERMINATOR.len() {
            return Err(malformed());
        }
        items = items.get(size..).ok_or_else(malformed)?;
    }
    if items != ID_TERMINATOR {
        return Err(malformed());
    }
    if list == ID_TERMINATOR {
        return Ok(None);
    }

    let extra = skip_presentation(strings, flags)?;
    // Property stores, alternate PIDLs and other ExtraData can influence
    // resolution or activation. The exact target ID list is our only input.
    Ok((extra.is_empty() || extra == EXTRA_TERMINATOR).then_some(list))
}

fn shortcut_flags(contents: &[u8]) -> io::Result<u32> {
    if contents.len() < HEADER_LEN
        || u64::try_from(contents.len()).map_err(|_| malformed())? > MAX_SHORTCUT_BYTES
        || offset(contents, 0)? != HEADER_LEN
        || contents.get(4..20) != Some(CLASS_ID.as_slice())
    {
        return Err(malformed());
    }
    at_u32(contents, 20)
}

fn check_reserved_header(contents: &[u8]) -> io::Result<()> {
    if contents[RESERVED_HEADER_FIELDS..HEADER_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(malformed());
    }
    Ok(())
}

fn skip_presentation(mut data: &[u8], flags: u32) -> io::Result<&[u8]> {
    let wide = flags & UNICODE != 0;
    for field in [NAME_STRING, ICON_LOCATION] {
        if flags & field == 0 {
            continue;
        }
        let count = usize::from(at_u16(data, 0)?);
        if count > MAX_PRESENTATION_UNITS {
            return Err(malformed());
        }
        let size = if wide { count * 2 } else { count };
        let (text, rest) = data[2..].split_at_checked(size).ok_or_else(malformed)?;
        if wide {
            let units = text
                .chunks_exact(2)
                .map(|unit| u16::from_le_bytes([unit[0], unit[1]]));
            if char::decode_utf16(units).any(|unit| !unit.is_ok_and(|character| character != '\0'))
            {
                return Err(malformed());
            }
        } else if !text.is_ascii() || text.contains(&0) {
            return Err(malformed());
        }
        data = rest;
    }
    Ok(data)
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

#[cfg(test)]
mod tests {
    use super::*;

    const ID_LIST: &[u8] = &[4, 0, 0x1f, 0x50, 5, 0, 0x7a, 0xab, 0x01, 0, 0];
    const TEST_VOLUME: u32 = 0x1234_abcd;
    const TEST_EXECUTABLE: &str = r"C:\Apps\Sample\Sample.exe";

    fn shortcut_header(flags: u32) -> Vec<u8> {
        let mut contents = vec![0; HEADER_LEN];
        contents[..4].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        contents[4..20].copy_from_slice(&CLASS_ID);
        contents[20..24].copy_from_slice(&flags.to_le_bytes());
        contents[60..64].copy_from_slice(&1_u32.to_le_bytes());
        contents
    }

    fn shortcut(flags: u32, list: &[u8]) -> Vec<u8> {
        let mut contents = shortcut_header(flags);
        contents.extend_from_slice(&(list.len() as u16).to_le_bytes());
        contents.extend_from_slice(list);
        contents
    }

    fn startup_shortcut(flags: u32, base: &str, suffix: &str, drive: u32) -> Vec<u8> {
        let volume_size = VOLUME_HEADER_LEN + 1;
        let base_offset = LINK_INFO_HEADER_LEN + volume_size;
        let suffix_offset = base_offset + base.len() + 1;
        let info_size = suffix_offset + suffix.len() + 1;
        let mut contents = shortcut_header(LINK_INFO | flags);
        for field in [
            info_size as u32,
            LINK_INFO_HEADER_LEN as u32,
            LOCAL_VOLUME_AND_PATH,
            LINK_INFO_HEADER_LEN as u32,
            base_offset as u32,
            0, // No network share.
            suffix_offset as u32,
            volume_size as u32,
            drive,
            TEST_VOLUME,
            VOLUME_HEADER_LEN as u32,
        ] {
            contents.extend_from_slice(&field.to_le_bytes());
        }
        contents.push(0); // Empty volume label.
        contents.extend_from_slice(base.as_bytes());
        contents.push(0);
        contents.extend_from_slice(suffix.as_bytes());
        contents.push(0);
        contents
    }

    #[test]
    fn startup_shortcut_returns_one_literal_executable_and_volume() -> io::Result<()> {
        let flags = NAME_STRING | ICON_LOCATION | UNICODE | SUPPRESS_TRACKING_FLAGS;
        let mut contents = startup_shortcut(flags, TEST_EXECUTABLE, "", FIXED_DRIVE);
        contents.extend_from_slice(&[1, 0, b'A', 0, 0, 0]);
        let target = startup_target(&contents)?.expect("one literal Startup executable");
        assert!(target.direct);
        assert_eq!(target.path, PathBuf::from(TEST_EXECUTABLE));
        assert_eq!(target.volume_serial, TEST_VOLUME);
        contents.extend_from_slice(&EXTRA_TERMINATOR);
        assert!(startup_target(&contents)?.is_some());
        Ok(())
    }

    #[test]
    fn startup_shortcut_rejects_activation_flags_and_extra_data() -> io::Result<()> {
        let flags = [
            TARGET_ID_LIST,
            RELATIVE_PATH,
            1 << 4, // HasWorkingDir
            ARGUMENTS,
            1 << 9,  // HasExpString
            1 << 12, // HasDarwinID
            1 << 13, // RunAsUser
            1 << 23, // AllowLinkToLink
            1 << 31, // Reserved
        ];
        for flag in flags {
            let contents = startup_shortcut(flag, TEST_EXECUTABLE, "", FIXED_DRIVE);
            assert!(startup_target(&contents)?.is_none(), "flag {flag:#x}");
        }

        let mut contents = startup_shortcut(0, TEST_EXECUTABLE, "", FIXED_DRIVE);
        contents.extend_from_slice(&(CONSOLE_CODE_PAGE_BLOCK.1 as u32).to_le_bytes());
        contents.extend_from_slice(&CONSOLE_CODE_PAGE_BLOCK.0.to_le_bytes());
        contents.extend_from_slice(&437_u32.to_le_bytes());
        contents.extend_from_slice(&EXTRA_TERMINATOR);
        assert!(startup_target(&contents)?.is_none());
        assert!(target(&contents)?.is_some());
        Ok(())
    }

    #[test]
    fn startup_shortcut_rejects_non_executables_and_ambiguous_paths() -> io::Result<()> {
        for (base, suffix, drive) in [
            (r"C:\Apps\Sample.cmd", "", FIXED_DRIVE),
            (r"C:\Apps\", "Sample.exe", FIXED_DRIVE),
            (TEST_EXECUTABLE, "", 4), // DRIVE_REMOTE
        ] {
            let contents = startup_shortcut(0, base, suffix, drive);
            assert!(startup_target(&contents)?.is_none());
        }
        let mut contents = startup_shortcut(0, TEST_EXECUTABLE, "", FIXED_DRIVE);
        contents[HOTKEY_OFFSET] = b'A';
        assert!(startup_target(&contents)?.is_none());
        Ok(())
    }

    #[test]
    fn packaged_shortcut_returns_the_full_id_list_with_its_terminator() -> io::Result<()> {
        let mut contents = shortcut(PACKAGED_FLAGS, ID_LIST);
        // The allowed Unicode name is “A”. The icon location is empty.
        contents.extend_from_slice(&[1, 0, b'A', 0, 0, 0]);
        assert_eq!(packaged_target_id(&contents)?, Some(ID_LIST));
        contents.extend_from_slice(&EXTRA_TERMINATOR);
        assert_eq!(packaged_target_id(&contents)?, Some(ID_LIST));
        Ok(())
    }

    #[test]
    fn packaged_shortcut_rejects_alternate_targets_and_activation_flags() -> io::Result<()> {
        let flags = [
            LINK_INFO,
            RELATIVE_PATH,
            1 << 4, // HasWorkingDir
            ARGUMENTS,
            1 << 9,  // HasExpString
            1 << 12, // HasDarwinID
            1 << 13, // RunAsUser
            1 << 17, // RunWithShimLayer
            1 << 23, // AllowLinkToLink
            1 << 25, // PreferEnvironmentPath
            1 << 26, // KeepLocalIDListForUNCTarget
            1 << 31, // Reserved
        ];
        for flag in flags {
            let contents = shortcut(TARGET_ID_LIST | flag, ID_LIST);
            assert_eq!(packaged_target_id(&contents)?, None, "flag {flag:#x}");
        }
        let without_target = shortcut(UNICODE, ID_LIST);
        assert_eq!(packaged_target_id(&without_target)?, None);
        Ok(())
    }

    #[test]
    fn packaged_shortcut_rejects_extra_data_and_bytes_after_its_terminal() -> io::Result<()> {
        let extra_signatures: [u32; 8] = [
            0xa000_0001, // EnvironmentVariableDataBlock
            TRACKER_BLOCK.0,
            0xa000_0005, // SpecialFolderDataBlock
            0xa000_0006, // DarwinDataBlock
            ICON_ENVIRONMENT_BLOCK.0,
            0xa000_0009, // PropertyStoreDataBlock
            0xa000_000b, // KnownFolderDataBlock
            0xa000_000c, // VistaAndAboveIDListDataBlock
        ];
        for signature in extra_signatures {
            let mut contents = shortcut(TARGET_ID_LIST, ID_LIST);
            contents.extend_from_slice(&8_u32.to_le_bytes());
            contents.extend_from_slice(&signature.to_le_bytes());
            contents.extend_from_slice(&EXTRA_TERMINATOR);
            assert_eq!(packaged_target_id(&contents)?, None, "block {signature:#x}");
        }

        let mut contents = shortcut(TARGET_ID_LIST, ID_LIST);
        contents.extend_from_slice(&EXTRA_TERMINATOR);
        contents.push(1);
        assert_eq!(packaged_target_id(&contents)?, None);
        Ok(())
    }

    #[test]
    fn packaged_shortcut_requires_complete_and_nonempty_item_framing() -> io::Result<()> {
        let malformed_lists: &[&[u8]] = &[
            &[0, 0, 4, 0, 0x1f, 0x50, 0, 0], // Bytes after a terminator
            &[1, 0, 0, 0],                   // Item shorter than its size field
            &[9, 0, 0x1f, 0x50, 0, 0],       // Item extends beyond its list
            &[4, 0, 0x1f, 0x50],             // Missing terminator
        ];
        for &list in malformed_lists {
            let contents = shortcut(TARGET_ID_LIST, list);
            assert_eq!(
                packaged_target_id(&contents).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
            );
        }

        let empty = shortcut(TARGET_ID_LIST, &ID_TERMINATOR);
        assert_eq!(packaged_target_id(&empty)?, None);
        Ok(())
    }
}
