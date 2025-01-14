//! Network filter abstractions.

use kernel::netfilter::{nf_hook_ops, nf_hookfn};
use kernel::prelude::*;

#[pin_data]
pub struct NetFilterHookOps {
    #[pin]
    pub(crate) inner: nf_hook_ops,
}

impl core::ops::Deref for NetFilterHookOps {
    type Target = nf_hook_ops;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl NetFilterHookOps {
    pub(crate) fn new() -> impl PinInit<Self> {
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

    pub(crate) fn set_hook(&mut self, hook: nf_hookfn) {
        self.inner.hook = hook
    }

    pub(crate) fn set_hooknum(&mut self, hooknum: HookNum) {
        self.inner.hooknum = hooknum.into()
    }

    pub(crate) fn set_protocol_family(&mut self, pf: ProtocolFamily) {
        self.inner.pf = pf.into()
    }

    pub(crate) fn set_priority(&mut self, priority: HookPriority) {
        self.inner.priority = priority.into()
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolFamily {
    Unspec = 0,
    Unix = 1,
    Inet = 2,
    Ax25 = 3,
    Ipx = 4,
    Appletalk = 5,
    Netrom = 6,
    Bridge = 7,
    Atmpvc = 8,
    X25 = 9,
    Inet6 = 10,
    Rose = 11,
    Decnet = 12,
    Netbeui = 13,
    Security = 14,
    Key = 15,
    Netlink = 16,
    Packet = 17,
    Ash = 18,
    Econet = 19,
    Atmsvc = 20,
    Rds = 21,
    Sna = 22,
    Irda = 23,
    Pppox = 24,
    Wanpipe = 25,
    Llc = 26,
    Ib = 27,
    Mpls = 28,
    Can = 29,
    Tipc = 30,
    Bluetooth = 31,
    Iucv = 32,
    Rxrpc = 33,
    Isdn = 34,
    Phonet = 35,
    Ieee802154 = 36,
    Caif = 37,
    Alg = 38,
    Nfc = 39,
    Vsock = 40,
    Kcm = 41,
    Qipcrtr = 42,
    Smc = 43,
    Xdp = 44,
    Mctp = 45,
    Max = 46,
}

impl ProtocolFamily {
    pub const LOCAL: ProtocolFamily = ProtocolFamily::Unix;
    pub const ROUTE: ProtocolFamily = ProtocolFamily::Netlink;
}

impl From<ProtocolFamily> for u8 {
    fn from(value: ProtocolFamily) -> Self {
        value as u8
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPriority {
    First = -2147483648,
    RawBeforeDefrag = -450,
    ConntrackDefrag = -400,
    Raw = -300,
    SelinuxFirst = -225,
    Conntrack = -200,
    Mangle = -150,
    NatDst = -100,
    Filter = 0,
    Security = 50,
    NatSrc = 100,
    SelinuxLast = 225,
    ConntrackHelper = 300,
    ConntrackConfirm = 2147483647,
}

impl HookPriority {
    pub const LAST: HookPriority = HookPriority::ConntrackConfirm;
}

impl From<HookPriority> for i32 {
    fn from(value: HookPriority) -> Self {
        value as i32
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookResponse {
    Drop = 0,
    Accept = 1,
    Stolen = 2,
    Queue = 3,
    Repeat = 4,
    Stop = 5,
}

impl HookResponse {
    pub const MAX_VERDICT: u32 = 5;
}

impl From<HookResponse> for u32 {
    fn from(value: HookResponse) -> Self {
        value as u32
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookNum {
    PreRouting = 0,
    LocalIn = 1,
    Forward = 2,
    LocalOut = 3,
    PostRouting = 4,
    NumHooks = 5,
}

impl HookNum {
    pub const INGRESS: HookNum = HookNum::NumHooks;
}

impl From<HookNum> for u32 {
    fn from(value: HookNum) -> Self {
        value as u32
    }
}