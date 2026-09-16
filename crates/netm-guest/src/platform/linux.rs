//! Linux platform configurator (placeholder; `ip` / `resolvectl` based
//! implementation lands in a later phase).

use anyhow::{bail, Result};
use netm_proto::TunnelConfig;

use super::PlatformConfigurator;
use crate::RouteMode;

#[derive(Debug, Default)]
pub struct LinuxConfigurator;

impl PlatformConfigurator for LinuxConfigurator {
    fn apply(&mut self, _: &str, _: &TunnelConfig, _: &RouteMode, _: bool) -> Result<()> {
        bail!("Linux guest is not yet supported")
    }

    fn revert(&mut self) -> Result<()> {
        Ok(())
    }
}
