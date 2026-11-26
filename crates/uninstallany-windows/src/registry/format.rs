use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::System::Registry::{REG_BINARY, REG_DWORD, REG_LINK, REG_QWORD, REG_SZ};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct RawValue {
    pub kind: u32,
    pub data: Vec<u8>,
}

impl RawValue {
    pub(super) fn string(&self) -> Option<String> {
        if self.data.len() % 2 != 0 {
            return None;
        }
        let words: Vec<u16> = self
            .data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let end = words
            .iter()
            .position(|word| *word == 0)
            .unwrap_or(words.len());
        if words[end..].iter().any(|word| *word != 0) {
            return None;
        }
        String::from_utf16(&words[..end]).ok()
    }

    pub(super) fn dword(&self) -> Option<u32> {
        if self.kind != REG_DWORD {
            return None;
        }
        let data: [u8; 4] = self.data.as_slice().try_into().ok()?;
        Some(u32::from_le_bytes(data))
    }

    pub(super) fn can_export(&self) -> bool {
        self.kind <= REG_QWORD && self.kind != REG_LINK
    }
}

pub(super) fn valid_value_name(name: &str) -> bool {
    !name.chars().any(char::is_control)
}

fn escape_string(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if character == '"' || character == '\\' {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// Exports only the captured values. The `.reg` view annotation is for reviewers.
/// The actual restore uses typed native writes under the original registry view.
pub(super) fn export(
    hive: &str,
    view: &str,
    key: &str,
    values: &BTreeMap<String, RawValue>,
) -> io::Result<Vec<u8>> {
    if key
        .chars()
        .any(|character| character.is_control() || character == ']')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe .reg key name",
        ));
    }
    let mut text = format!(
        "Windows Registry Editor Version 5.00\r\n\r\n; Original view: {view}\r\n\r\n[{hive}\\{key}]\r\n"
    );
    for (name, value) in values {
        if !valid_value_name(name) || !value.can_export() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexportable registry value",
            ));
        }
        if name.is_empty() {
            text.push('@');
        } else {
            write!(text, "\"{}\"", escape_string(name)).map_err(io::Error::other)?;
        }
        text.push('=');
        if let Some(number) = value.dword() {
            write!(text, "dword:{number:08x}").map_err(io::Error::other)?;
        } else if let Some(string) = exact_string(value) {
            write!(text, "\"{}\"", escape_string(&string)).map_err(io::Error::other)?;
        } else {
            append_hex(&mut text, value)?;
        }
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    Ok(std::iter::once(0xfeff)
        .chain(text.encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect())
}

pub(super) fn exact_string(value: &RawValue) -> Option<String> {
    if value.kind != REG_SZ {
        return None;
    }
    let text = value.string()?;
    if !valid_value_name(&text) {
        return None;
    }
    let standard = text
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes);
    standard.eq(value.data.iter().copied()).then_some(text)
}

fn append_hex(text: &mut String, value: &RawValue) -> io::Result<()> {
    const HEX_BYTES_PER_LINE: usize = 20;
    if value.kind == REG_BINARY {
        text.push_str("hex:");
    } else {
        write!(text, "hex({:x}):", value.kind).map_err(io::Error::other)?;
    }
    for (index, byte) in value.data.iter().enumerate() {
        if index != 0 {
            text.push(',');
            if index % HEX_BYTES_PER_LINE == 0 {
                text.push_str("\\\r\n  ");
            }
        }
        write!(text, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8]) -> io::Result<String> {
        let words = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&words).map_err(io::Error::other)
    }

    #[test]
    fn exports_exact_selected_values_with_regedit_escapes() -> io::Result<()> {
        let values = BTreeMap::from([
            (
                String::new(),
                RawValue {
                    kind: REG_BINARY,
                    data: vec![0, 1, 255],
                },
            ),
            (
                "Path\"Value".to_string(),
                RawValue {
                    kind: REG_SZ,
                    data: "C:\\应用\0"
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect(),
                },
            ),
        ]);
        let content = text(&export(
            "HKEY_CURRENT_USER",
            "shared",
            "Software\\Vendor\\App",
            &values,
        )?)?;
        assert!(content.starts_with('\u{feff}'));
        assert!(content.contains("[HKEY_CURRENT_USER\\Software\\Vendor\\App]\r\n"));
        assert!(content.contains("@=hex:00,01,ff\r\n"));
        assert!(content.contains("\"Path\\\"Value\"=\"C:\\\\应用\"\r\n"));
        Ok(())
    }

    #[test]
    fn preserves_unterminated_registry_strings_as_hex() -> io::Result<()> {
        let values = BTreeMap::from([(
            "Value".to_string(),
            RawValue {
                kind: REG_SZ,
                data: vec![65, 0],
            },
        )]);
        let content = text(&export(
            "HKEY_CURRENT_USER",
            "shared",
            "Software\\Vendor\\App",
            &values,
        )?)?;
        assert!(content.contains("\"Value\"=hex(1):41,00\r\n"));
        Ok(())
    }

    #[test]
    fn rejects_registry_links_and_line_breaks() {
        let values = BTreeMap::from([(
            "SymbolicLinkValue".to_string(),
            RawValue {
                kind: REG_LINK,
                data: vec![0, 0],
            },
        )]);
        let key = "Software\\Vendor\\App";
        assert!(export("HKEY_CURRENT_USER", "shared", key, &values).is_err());
        assert!(
            export(
                "HKEY_CURRENT_USER",
                "shared",
                "Software\\Vendor\r\nApp",
                &BTreeMap::new()
            )
            .is_err()
        );
    }
}
