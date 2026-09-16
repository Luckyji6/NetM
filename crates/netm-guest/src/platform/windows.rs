//! Windows platform configurator (placeholder; Wintun + `netsh` / `route`
//! based implementation lands in a later phase).

use anyhow::{bail, Result};
use netm_proto::TunnelConfig;

use super::PlatformConfigurator;
use crate::RouteMode;

#[derive(Debug, Default)]
pub struct WindowsConfigurator;

impl PlatformConfigurator for WindowsConfigurator {
    fn apply(&mut self, _: &str, _: &TunnelConfig, _: &RouteMode, _: bool) -> Result<()> {
        bail!("Windows guest is not yet supported")
    }

    fn revert(&mut self) -> Result<()> {
        Ok(())
    }
}
