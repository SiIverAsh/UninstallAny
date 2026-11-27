use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use rustix::fs::{self, Mode, OFlags};

use crate::command::{Program, trusted_regular_file};

pub(crate) struct SystemHelper {
    pub(crate) executable: &'static str,
    pub(crate) policy_path: &'static str,
    pub(crate) policy: &'static [u8],
}

impl SystemHelper {
    pub(crate) fn launcher(&self) -> io::Result<(Program, Program)> {
        self.require_policy()?;
        Ok((
            Program::fixed(Path::new("/usr/bin/pkexec"))?,
            Program::fixed(Path::new(self.executable))?,
        ))
    }

    pub(crate) fn require_policy(&self) -> io::Result<()> {
        let path = Path::new(self.policy_path);
        trusted_regular_file(path)?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let descriptor = fs::open(path, flags, Mode::empty()).map_err(io::Error::from)?;
        let mut bytes = Vec::new();
        File::from(descriptor)
            .take(u64::try_from(self.policy.len() + 1).map_err(io::Error::other)?)
            .read_to_end(&mut bytes)?;
        if bytes != self.policy {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("the authorization policy differs for {}", self.executable),
            ));
        }
        Ok(())
    }
}
