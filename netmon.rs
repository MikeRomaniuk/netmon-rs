//! Rust Network Monitor driver.

mod error;
mod netfilter;

use core::pin::Pin;
// `netfilter` is my bindings crate inside the Linux kernel sourcetree with all headers I need.
use kernel::netfilter::{nf_hook_state, sk_buff};
use kernel::pr_cont;
use kernel::prelude::*;
use netfilter::{
    HookNum, HookPriority, HookResponse, IpProtocol, Ipv4Addr, NetFilterHookOps, ProtocolFamily,
    SkBuff, TransportPacket,
};

module! {
    type: NetMon,
    name: "netmon",
    author: "Me&&Co",
    description: "Network monitor module written in Rust",
    license: "GPL",
}

// This won't be in an async context, so there is no sense to wrap them in Muxex/whatever.
static mut PROTOCOLS: Vec<IpProtocol> = Vec::new();
static mut ADDRS: Vec<Ipv4Addr> = Vec::new();
static mut PORTS: Vec<u16> = Vec::new();

struct NetMon {
    nfho: Pin<Box<NetFilterHookOps>>,
}

impl NetMon {
    fn handle_packet(skb: &SkBuff) -> Result<(), error::Error> {
        let packet = TransportPacket::from_skb(skb)?;

        let source_addr = packet.source_addr();
        let destination_addr = packet.destination_addr();

        // SAFETY: we are in sync context, so it's fine to operate with mutable statisc.
        if unsafe {
            !ADDRS.is_empty()
                && (!ADDRS.contains(&source_addr) && !ADDRS.contains(&destination_addr))
        } {
            return Ok(());
        }

        let protocol = packet.protocol();

        // SAFETY: we are in sync context, so it's fine to operate with mutable statisc.
        if unsafe { !PROTOCOLS.is_empty() && !PROTOCOLS.contains(&protocol) } {
            return Ok(());
        }

        let destination_port = packet.destination_port();
        let source_port = packet.source_port();

        // SAFETY: we are in sync context, so it's fine to operate with mutable statics.
        if unsafe {
            !PORTS.is_empty()
                && (!PORTS.contains(&source_port) && !PORTS.contains(&destination_port))
        } {
            return Ok(());
        }

        pr_info!("{protocol:?}: {source_addr:?}:{source_port} -> {destination_addr:?}:{destination_port}\n");
        Self::print_packet(skb)?;

        Ok(())
    }

    fn print_packet(skb: &SkBuff) -> Result<(), error::Error> {
        const ROW_SIZE: usize = 16;

        pr_info!("Packet hex dump:\n");

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

    fn new(mut nfho: Pin<Box<NetFilterHookOps>>) -> Result<Self, kernel::error::Error> {
        use kernel::netfilter::init_net;

        // SAFETY: init_net should be valid at any point.
        nfho.as_mut().register(unsafe { &mut init_net })?;

        Ok(Self { nfho })
    }

    fn unregister_net_hook(&mut self) {
        use kernel::netfilter::init_net;

        // SAFETY: init_net should be valid at any point.
        let _ = &self.nfho.unregister(unsafe { &mut init_net });
    }
}

unsafe impl Send for NetMon {}
unsafe impl Sync for NetMon {}

impl kernel::Module for NetMon {
    fn init(_: &'static ThisModule) -> Result<Self> {
        let mut nfho: Pin<Box<NetFilterHookOps>> = Box::pin_init(NetFilterHookOps::new())?;

        {
            let mut nfho = nfho.as_mut();
            nfho.set_hook(Some(hook_fn));
            nfho.set_hooknum(HookNum::PreRouting);
            nfho.set_protocol_family(ProtocolFamily::Inet);
            nfho.set_priority(HookPriority::First)
        }

        let netmon = NetMon::new(nfho)?;

        // SAFETY: we are in sync context, so it's fine to operate with mutable statics.
        unsafe {
            PORTS.try_push(443)?;
            PROTOCOLS.try_push(IpProtocol::Tcp)?;
            PROTOCOLS.try_push(IpProtocol::Udp)?;
        };

        pr_info!("Rust Network Monitor (init)\n");
        Ok(netmon)
    }
}

impl Drop for NetMon {
    fn drop(&mut self) {
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
            // We ignore the error, since we can't do something if it is the error.
            let _ = NetMon::handle_packet(skb);
        }
        None => {
            pr_err!("skb is None");
        }
    }

    HookResponse::Accept.into()
}
