use std::io;

use core_foundation::{
    base::{CFType, TCFType},
    data::CFData,
    dictionary::CFDictionary,
    propertylist::{CFPropertyList, create_with_data, kCFPropertyListImmutable},
    string::CFString,
};

pub(super) fn dictionary(bytes: &[u8]) -> io::Result<CFDictionary> {
    let (raw, _) = create_with_data(CFData::from_buffer(bytes), kCFPropertyListImmutable)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    // SAFETY: Core Foundation returned a non-null property-list object under
    // the create rule. Its dynamic type is checked before accessing values.
    let property = unsafe { CFPropertyList::wrap_under_create_rule(raw) };
    property.downcast_into::<CFDictionary>().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the property list is not a dictionary",
        )
    })
}

pub(super) fn string(dictionary: &CFDictionary, key: &str) -> Option<String> {
    let key = CFString::new(key);
    let value = dictionary.find(key.as_CFTypeRef())?;
    // SAFETY: A Core Foundation property list dictionary retains its values.
    // The borrowed object remains valid for this call and gets retained.
    let value = unsafe { CFType::wrap_under_get_rule(*value) };
    let text = value.downcast_into::<CFString>()?.to_string();
    (!text.trim().is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_foundation::propertylist::{create_data, kCFPropertyListBinaryFormat_v1_0};

    #[test]
    fn looks_up_typed_xml_and_binary_plist_values() -> io::Result<()> {
        let bytes = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>example.editor</string><key>other</key><integer>42</integer></dict></plist>"#;
        let parsed = dictionary(bytes)?;
        let binary = create_data(parsed.as_CFTypeRef(), kCFPropertyListBinaryFormat_v1_0)
            .map_err(|error| io::Error::other(error.to_string()))?;
        for source in [parsed, dictionary(binary.bytes())?] {
            assert_eq!(
                string(&source, "CFBundleIdentifier").as_deref(),
                Some("example.editor")
            );
            assert!(string(&source, "other").is_none());
            assert!(string(&source, "missing").is_none());
        }
        Ok(())
    }
}
