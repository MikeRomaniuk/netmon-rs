//! Rust Network Monitor driver.

mod netfilter;

use core::pin::Pin;
use kernel::error::to_result;
use kernel::netfilter::{
    init_net, nf_hook_state, nf_inet_hooks_NF_INET_PRE_ROUTING, nf_register_net_hook,
    nf_unregister_net_hook, sk_buff,
};
use kernel::prelude::*;
use netfilter::{HookPriority, HookResponse, NetFilterHookOps, ProtocolFamily};

module! {
    type: NetMon,
    name: "netmon",
    author: "Me&&Co",
    description: "Network monitor module written in Rust",
    license: "GPL",
}

struct NetMon {
    nfho: Pin<Box<NetFilterHookOps>>,
}

unsafe impl Send for NetMon {}
unsafe impl Sync for NetMon {}

impl kernel::Module for NetMon {
    fn init(_: &'static ThisModule) -> Result<Self> {
        let mut nfho: Pin<Box<NetFilterHookOps>> = Box::pin_init(NetFilterHookOps::new())?;

        {
            let mut nfho = nfho.as_mut();
            nfho.set_hook(Some(hook_fn));
            nfho.set_hooknum(nf_inet_hooks_NF_INET_PRE_ROUTING);
            nfho.set_protocol_family(ProtocolFamily::Inet);
            nfho.set_priority(HookPriority::First)
        }

        to_result(unsafe {
            nf_register_net_hook(
                &mut init_net as *mut _,
                &nfho.as_mut().get_unchecked_mut().inner as *const _,
            )
        })?;

        pr_info!("Rust Network Monitor (init)\n");
        Ok(NetMon { nfho })
    }
}

impl Drop for NetMon {
    fn drop(&mut self) {
        unsafe {
            nf_unregister_net_hook(
                &mut init_net as *mut _,
                &self.nfho.as_mut().get_unchecked_mut().inner as *const _,
            );
        }
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
    let skb_option = unsafe { skb.as_ref() };
    pr_info!("I am in this thing!");
    match skb_option {
        Some(_skb) => {
            return HookResponse::Accept.into();
        }
        None => {
            return HookResponse::Accept.into();
        }
    }
}
