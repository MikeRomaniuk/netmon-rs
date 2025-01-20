//! Rust Network Monitor driver.

mod netfilter;

use core::pin::Pin;
use kernel::error::to_result;
// `netfilter` is my bindings crate with all headers I need.
use kernel::netfilter::{nf_hook_state, nf_register_net_hook, nf_unregister_net_hook, sk_buff};
use kernel::pr_cont;
use kernel::prelude::*;
use netfilter::{
    HookNum, HookPriority, HookResponse, IpProtocol, Ipv4Addr, NetFilterHookOps, ProtocolFamily,
    SkBuff, TcpHeader, UdpHeader,
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
    fn handle_packet(skb: &SkBuff) {
        let iph = skb.get_ip_header();

        let source_addr = iph.source_addr();
        let destination_addr = iph.destination_addr();

        // SAFETY: we are in sync context, so it's fine to operate with mutable statisc.
        if unsafe {
            !ADDRS.is_empty()
                && (!ADDRS.contains(&source_addr) && !ADDRS.contains(&destination_addr))
        } {
            return;
        }

        let protocol = iph.protocol();

        // SAFETY: we are in sync context, so it's fine to operate with mutable statisc.
        if unsafe { !PROTOCOLS.is_empty() && !PROTOCOLS.contains(&protocol) } {
            return;
        }

        // TODO: abstract this with TransportLayerProtocol trait;
        let (destination_port, source_port) = match protocol {
            IpProtocol::Tcp => {
                let tcp = unsafe { TcpHeader::from_ptr(skb.transport_header() as *const _) };
                (tcp.destination_port(), tcp.source_port())
            }
            IpProtocol::Udp => {
                let udp = unsafe { UdpHeader::from_ptr(skb.transport_header() as *const _) };
                (udp.destination_port(), udp.source_port())
            }
            _ => {
                pr_info!("Unsoported protocol {protocol:?}");
                return;
            }
        };

        // SAFETY: we are in sync context, so it's fine to operate with mutable statisc.
        if unsafe {
            !PORTS.is_empty()
                && (!PORTS.contains(&source_port) && !PORTS.contains(&destination_port))
        } {
            return;
        }

        pr_info!("{protocol:?}: {source_addr:?}:{source_port} -> {destination_addr:?}:{destination_port}\n");
        Self::print_packet(skb);
    }

    fn print_packet(skb: &SkBuff) {
        const ROW_SIZE: usize = 16;

        pr_info!("Packet hex dump:\n");

        let data = skb.mac_header();

        for (line_num, chunk) in data.chunks(ROW_SIZE).enumerate() {
            pr_info!("{:0>6}\t", line_num * 10);

            for byte in chunk {
                pr_cont!("{:02X} ", byte);
            }

            pr_cont!("\n");
        }
    }

    fn new(mut nfho: Pin<Box<NetFilterHookOps>>) -> Result<Self, kernel::error::Error> {
        use kernel::netfilter::init_net;

        to_result(unsafe {
            nf_register_net_hook(
                &mut init_net as *mut _,
                &nfho.as_mut().get_unchecked_mut().inner as *const _,
            )
        })?;

        Ok(Self { nfho })
    }

    fn unregister_net_hook(&mut self) {
        use kernel::netfilter::init_net;

        unsafe {
            nf_unregister_net_hook(
                &mut init_net as *mut _,
                &self.nfho.as_mut().get_unchecked_mut().inner as *const _,
            );
        }
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

        // SAFETY: we are in sync context, so it's fine to operate with mutable statisc.
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
            NetMon::handle_packet(skb);
        }
        None => {
            pr_err!("skb is None");
        }
    }

    HookResponse::Accept.into()
}
