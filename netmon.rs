// SPDX-License-Identifier: GPL-2.0

//! Rust out-of-tree sample
use kernel::prelude::*;

module! {
    type: NetworkMonitor,
    name: "network_monitor",
    author: "Me&&Co",
    description: "Network monitor module written in Rust",
    license: "GPL",
}

struct NetworkMonitor;

impl kernel::Module for NetworkMonitor {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust Network Monitor (init)\n");

        Ok(NetworkMonitor {})
    }
}

impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        pr_info!("Rust Network Monitor (exit)\n");
    }
}