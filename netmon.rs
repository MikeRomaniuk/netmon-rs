//! Rust Network Monitor driver.

use core::pin::Pin;
use kernel::error::to_result;
use kernel::netfilter::{init_net, nf_hook_ops, nf_register_net_hook, nf_unregister_net_hook};
use kernel::prelude::*;

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

#[pin_data]
struct NetFilterHookOps {
    #[pin]
    inner: nf_hook_ops,
}

impl NetFilterHookOps {
    fn new() -> impl PinInit<Self> {
        // Took implementaion from the bindgen, because I couldn't use
        // the `default` function of the `Default` trait.
        let nfho: nf_hook_ops = {
            let mut s = ::core::mem::MaybeUninit::<nf_hook_ops>::uninit();
            unsafe {
                ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
                s.assume_init()
            }
        };
        pin_init!(Self { inner: nfho })
    }
}
