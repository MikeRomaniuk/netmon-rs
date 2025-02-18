//! Rust Network Monitor driver.

mod error;
mod netfilter;

use core::pin::Pin;

// `netfilter` is my bindings crate inside the Linux kernel sourcetree with all headers I need.
use kernel::netfilter::{nf_hook_state, sk_buff};
use kernel::pr_cont;
use kernel::prelude::*;
use netfilter::{
    HookNum, HookPriority, HookResponse, IpProtocol, Ipv4Addr, NetFilterHookOps, NetworkPacket, ProtocolFamily, SkBuff,
};

// Add information about the module.
module! {
    type: NetMon,
    name: "netmon",
    author: "Apriorit",
    description: "Network monitor module written in Rust",
    license: "GPL",
}

// This won't be in an async context, so there is no sense to wrap them in Muxex/whatever.
static mut PROTOCOLS: Vec<IpProtocol> = Vec::new();
static mut ADDRS: Vec<Ipv4Addr> = Vec::new();
static mut PORTS: Vec<u16> = Vec::new();

/// Structure, representing a kernel module.
struct NetMon {
    /// Netfilter hook operations.
    nfho: Pin<Box<NetFilterHookOps>>,
}

// SAFETY: It is allowed to unregister a network filter hook
// on a different thread from where you registered.
unsafe impl Send for NetMon {}
// SAFETY: All `&self` methods on this type are written to ensure that it is safe to call them in
// parallel.
unsafe impl Sync for NetMon {}

impl NetMon {
    /// Handle the packet on which points [skb](SkBuff).
    ///
    /// # Arguments:
    ///
    /// * [skb](SkBuff): buffer with metadata about hte package.
    fn handle_packet(skb: &SkBuff) -> Result<(), error::Error> {
        // Get the `NetworkPacket` from the `skb``.
        let packet = NetworkPacket::from_skb(skb)?;

        let source_addr = packet.source_addr();
        let destination_addr = packet.destination_addr();

        // SAFETY: vectors were mutated during the initialization and never changed after.
        if unsafe { !ADDRS.is_empty() && (!ADDRS.contains(&source_addr) && !ADDRS.contains(&destination_addr)) } {
            return Ok(());
        }

        let protocol = packet.protocol()?;

        // SAFETY: vectors were mutated during the initialization and never changed after.
        if unsafe { !PROTOCOLS.is_empty() && !PROTOCOLS.contains(&protocol) } {
            return Ok(());
        }

        let destination_port = packet.destination_port();
        let source_port = packet.source_port();

        // SAFETY: vectors were mutated during the initialization and never changed after.
        if unsafe { !PORTS.is_empty() && (!PORTS.contains(&source_port) && !PORTS.contains(&destination_port)) } {
            return Ok(());
        }
        // Print the info about the packet.
        pr_info!("{protocol:?}: {source_addr:?}:{source_port} -> {destination_addr:?}:{destination_port}\n");
        // Print the payload.
        Self::print_packet(skb)?;

        Ok(())
    }

    /// Prints the payload of the packet on which points [skb](SkBuff).
    ///
    /// # Arguments:
    ///
    /// * [skb](SkBuff): buffer with metadata about hte package.
    fn print_packet(skb: &SkBuff) -> Result<(), error::Error> {
        const ROW_SIZE: usize = 16;

        pr_info!("Packet hex dump:\n");

        // Data of the packet starts from Mac header.
        let data = skb.mac_header()?;

        for (line_num, chunk) in data.chunks(ROW_SIZE).enumerate() {
            pr_info!("{:0>6}\t", line_num * 10);

            for byte in chunk {
                pr_cont!("{:02X} ", byte);
            }

            pr_cont!("\n");
        }

        Ok(())
    }

    /// Creates a new instance and registers netfilter hook operations in the system.
    ///
    /// # Arguments:
    ///
    /// * [nfho](Pin<Box<NetFilterHookOps>>): netfilter hook operations.
    fn new(mut nfho: Pin<Box<NetFilterHookOps>>) -> Result<Self, kernel::error::Error> {
        // SAFETY: init_net should be valid at any point.
        nfho.as_mut().register(unsafe { &mut kernel::netfilter::init_net })?;

        Ok(Self { nfho })
    }

    /// Unregisters the previously registered hook.
    fn unregister_net_hook(&mut self) {
        // SAFETY: init_net should be valid at any point.
        self.nfho.unregister(unsafe { &mut kernel::netfilter::init_net });
    }
}

impl kernel::Module for NetMon {
    fn init(_: &'static ThisModule) -> Result<Self> {
        // Set up sample filtering rules.
        // SAFETY: we are in sync context, so it's fine to operate with mutable statics.
        unsafe {
            PORTS.try_push(443)?;
            PROTOCOLS.try_push(IpProtocol::Tcp)?;
            PROTOCOLS.try_push(IpProtocol::Udp)?;
        };

        // Create a netfilter hook operations.
        let mut nfho: Pin<Box<NetFilterHookOps>> = Box::pin_init(NetFilterHookOps::new())?;

        // Set up the hook.
        {
            let mut nfho = nfho.as_mut();
            // Set the hook function.
            nfho.set_hook(Some(hook_fn));
            // Set the hook to be called in the Network layer before
            // the packet is passed to the internal routing engine.
            nfho.set_hooknum(HookNum::PreRouting);
            // Set the protocol family.
            nfho.set_protocol_family(ProtocolFamily::Inet);
            // Set the hook priority.
            nfho.set_priority(HookPriority::First)
        }

        // Create a module instance and register the hook operations.
        let netmon = NetMon::new(nfho)?;

        pr_info!("Rust Network Monitor (init)\n");

        // Finish an initialization with a success.
        Ok(netmon)
    }
}

impl Drop for NetMon {
    fn drop(&mut self) {
        // Unregister the hook.
        self.unregister_net_hook();
        pr_info!("Rust Network Monitor (exit)\n");
    }
}

/// Netfilter hook function.
///
/// This function will be registered in the kernel
/// to be called at specific points in the network stack.
///
/// Function registration is done by inserting `nf_hook_ops` with the [`nf_register_hook`] function.
///
/// # Safety
///
/// This function is safe, since the validity of the `skb` is checked.
pub unsafe extern "C" fn hook_fn(
    _priv_: *mut core::ffi::c_void,
    skb: *mut sk_buff,
    _state: *const nf_hook_state,
) -> core::ffi::c_uint {
    // SAFETY: if `skb` is a null-pointer, the [`Option::None`] is returned by the `as_ref()` function.
    match unsafe { skb.as_ref() } {
        Some(_) => {
            // SAFETY: if `skb` was a null-pointer, we would never be in `Some` branch.
            let skb = unsafe { SkBuff::from_ptr(skb) };

            if let Err(err) = NetMon::handle_packet(skb) {
                pr_err!("Could not handle a packet: {err}")
            }
        }
        None => {
            pr_err!("skb is None");
        }
    }

    HookResponse::Accept as _
}
