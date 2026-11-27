use std::io;

use sha2::{Digest, Sha256};
use uninstallany_core::{RegistryChangeReceipt, RegistryTarget};
use uuid::Uuid;
use windows_sys::Win32::System::Registry::{REG_BINARY, RegSetValueExW};

use super::{denied, format::RawValue, invalid, native};

const RECEIPT_VERSION: u8 = 1;
const RECEIPT_BYTES: usize = 34;

pub(super) struct Receipt {
    name: String,
    binding: [u8; 32],
}

impl Receipt {
    pub(super) fn bind(id: Uuid, target: &RegistryTarget, snapshot: &[u8]) -> io::Result<Self> {
        let address = serde_json::to_vec(&(id, target)).map_err(io::Error::other)?;
        let mut binding = Sha256::new();
        binding.update(address);
        binding.update(Sha256::digest(snapshot));
        Ok(Self {
            name: id.to_string(),
            binding: binding.finalize().into(),
        })
    }

    pub(super) fn read(&self) -> io::Result<Option<RegistryChangeReceipt>> {
        let Some(key) = native::open_recovery_key(None)? else {
            return Ok(None);
        };
        self.read_from(&key)
    }

    pub(super) fn stage(
        &self,
        transaction: &native::Transaction,
        phase: RegistryChangeReceipt,
    ) -> io::Result<()> {
        let key = native::open_recovery_key(Some(transaction))?
            .ok_or_else(|| denied("the private Windows registry recovery key disappeared"))?;
        match (phase, self.read_from(&key)?) {
            (_, None) | (RegistryChangeReceipt::Restored, Some(RegistryChangeReceipt::Applied)) => {
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "this backup already has a committed registry receipt for this phase",
                ));
            }
        }

        let name = native::wide(&self.name);
        let payload = self.encode(phase);
        // SAFETY: The key is open for this transaction, and the terminated
        // value name and entire payload remain live for the native call.
        native::status(unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_BINARY,
                payload.as_ptr(),
                RECEIPT_BYTES as u32,
            )
        })
    }

    pub(super) fn commit(
        &self,
        transaction: native::Transaction,
        phase: RegistryChangeReceipt,
    ) -> io::Result<()> {
        let Err(commit) = transaction.commit() else {
            return Ok(());
        };
        // The transaction handle is closed. Check only the receipt from an
        // independent, non-transacted read, never the current target value.
        match self.read() {
            Ok(Some(observed)) if observed == phase => Ok(()),
            Ok(_) => Err(commit),
            Err(receipt) => Err(io::Error::other(format!(
                "could not verify the Windows registry commit ({commit}); backup retained. Receipt check: {receipt}"
            ))),
        }
    }

    fn read_from(&self, key: &native::Key) -> io::Result<Option<RegistryChangeReceipt>> {
        native::query(key, &self.name)?
            .map(|raw| self.decode(&raw))
            .transpose()
    }

    fn encode(&self, phase: RegistryChangeReceipt) -> [u8; RECEIPT_BYTES] {
        let code = match phase {
            RegistryChangeReceipt::Applied => 1,
            RegistryChangeReceipt::Restored => 2,
        };
        let header = [RECEIPT_VERSION, code];
        let mut digest = Sha256::new();
        digest.update(b"UninstallAny Windows registry change receipt");
        digest.update(header);
        digest.update(self.binding);
        let mut payload = [0; RECEIPT_BYTES];
        payload[..header.len()].copy_from_slice(&header);
        payload[header.len()..].copy_from_slice(&digest.finalize());
        payload
    }

    fn decode(&self, value: &RawValue) -> io::Result<RegistryChangeReceipt> {
        if value.kind == REG_BINARY {
            for phase in [
                RegistryChangeReceipt::Applied,
                RegistryChangeReceipt::Restored,
            ] {
                if value.data == self.encode(phase) {
                    return Ok(phase);
                }
            }
        }
        Err(invalid(
            "invalid Windows registry recovery receipt for this backup",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uninstallany_core::{RegistryHive, RegistryView};

    #[test]
    fn receipt_rejects_a_different_phase_address_snapshot_or_backup() -> io::Result<()> {
        let id = Uuid::new_v4();
        let target = RegistryTarget {
            hive: RegistryHive::CurrentUser,
            view: RegistryView::Native,
            key: r"Software\Example Vendor\Example Tool".into(),
            value: Some("Setting".into()),
        };
        let receipt = Receipt::bind(id, &target, b"original")?;
        let mut value = RawValue {
            kind: REG_BINARY,
            data: receipt.encode(RegistryChangeReceipt::Applied).to_vec(),
        };
        assert_eq!(receipt.decode(&value)?, RegistryChangeReceipt::Applied);
        assert!(
            Receipt::bind(Uuid::new_v4(), &target, b"original")?
                .decode(&value)
                .is_err()
        );
        assert!(
            Receipt::bind(id, &target, b"replaced")?
                .decode(&value)
                .is_err()
        );
        let other_target = RegistryTarget {
            value: Some("Other".into()),
            ..target
        };
        assert!(
            Receipt::bind(id, &other_target, b"original")?
                .decode(&value)
                .is_err()
        );
        value.data[1] = 2;
        assert!(receipt.decode(&value).is_err());
        Ok(())
    }
}
