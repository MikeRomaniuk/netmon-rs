//! Network filter abstractions.

use core::cell::UnsafeCell;
use kernel::netfilter::{
    in_addr, iphdr, net, nf_hook_ops, nf_hookfn, nf_register_net_hook, nf_unregister_net_hook,
    sk_buff, tcphdr, udphdr,
};
// `netfilter` is my bindings crate with all headers I need.
use crate::error;
use kernel::error::to_result;
use kernel::netfilter;
use kernel::prelude::*;

/// A safe wrapper around the kernel's [`struct nf_hook_ops`]: srctree/include/linux/netfilter.h.
/// Manages registration and configuration of network packet filtering hooks.
#[pin_data]
pub struct NetFilterHookOps {
    #[pin]
    pub(crate) inner: nf_hook_ops,
}

/// Provides read-only access to the underlying netfilter hook operations.
impl core::ops::Deref for NetFilterHookOps {
    type Target = nf_hook_ops;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// Implement the necessary functions.
impl NetFilterHookOps {
    /// Creates a new instance of NetFilterHookOps with zeroed memory.
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

    /// Sets the hook function to be called when packets match the filter.
    pub(crate) fn set_hook(&mut self, hook: nf_hookfn) {
        self.inner.hook = hook
    }

    /// Configures which hook point in the networking stack to attach to.
    pub(crate) fn set_hooknum(&mut self, hooknum: HookNum) {
        self.inner.hooknum = hooknum.into()
    }

    /// Specifies the protocol family this hook operates on.
    pub(crate) fn set_protocol_family(&mut self, pf: ProtocolFamily) {
        self.inner.pf = pf.into()
    }

    /// Sets the priority level of this hook relative to other hooks.
    pub(crate) fn set_priority(&mut self, priority: HookPriority) {
        self.inner.priority = priority.into()
    }

    /// Registers this netfilter hook with the specified network namespace.
    pub(crate) fn register(&mut self, net: &mut net) -> Result<(), Error> {
        // SAFETY: The net pointer and hook ops reference remain valid for the duration
        // of the call since they are borrowed mutably. The hook ops struct should be valid
        // as long as the hook is registered.
        to_result(unsafe { nf_register_net_hook(net as *mut _, &self.inner as *const _) })?;
        Ok(())
    }

    /// Unregisters this netfilter hook from the specified network namespace.
    pub(crate) fn unregister(&mut self, net: &mut net) {
        // SAFETY: The net pointer and hook ops reference remain valid for the duration
        // of the call since they are borrowed mutably.
        unsafe {
            nf_unregister_net_hook(net as *mut _, &self.inner as *const _);
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolFamily {
    Unspec = netfilter::AF_UNSPEC,
    Unix = netfilter::AF_UNIX,
    Inet = netfilter::AF_INET,
    Ax25 = netfilter::AF_AX25,
    Ipx = netfilter::AF_IPX,
    Appletalk = netfilter::AF_APPLETALK,
    Netrom = netfilter::AF_NETROM,
    Bridge = netfilter::AF_BRIDGE,
    Atmpvc = netfilter::AF_ATMPVC,
    X25 = netfilter::AF_X25,
    Inet6 = netfilter::AF_INET6,
    Rose = netfilter::AF_ROSE,
    Decnet = netfilter::AF_DECnet,
    Netbeui = netfilter::AF_NETBEUI,
    Security = netfilter::AF_SECURITY,
    Key = netfilter::AF_KEY,
    Netlink = netfilter::AF_NETLINK,
    Packet = netfilter::AF_PACKET,
    Ash = netfilter::AF_ASH,
    Econet = netfilter::AF_ECONET,
    Atmsvc = netfilter::AF_ATMSVC,
    Rds = netfilter::AF_RDS,
    Sna = netfilter::AF_SNA,
    Irda = netfilter::AF_IRDA,
    Pppox = netfilter::AF_PPPOX,
    Wanpipe = netfilter::AF_WANPIPE,
    Llc = netfilter::AF_LLC,
    Ib = netfilter::AF_IB,
    Mpls = netfilter::AF_MPLS,
    Can = netfilter::AF_CAN,
    Tipc = netfilter::AF_TIPC,
    Bluetooth = netfilter::AF_BLUETOOTH,
    Iucv = netfilter::AF_IUCV,
    Rxrpc = netfilter::AF_RXRPC,
    Isdn = netfilter::AF_ISDN,
    Phonet = netfilter::AF_PHONET,
    Ieee802154 = netfilter::AF_IEEE802154,
    Caif = netfilter::AF_CAIF,
    Alg = netfilter::AF_ALG,
    Nfc = netfilter::AF_NFC,
    Vsock = netfilter::AF_VSOCK,
    Kcm = netfilter::AF_KCM,
    Qipcrtr = netfilter::AF_QIPCRTR,
    Smc = netfilter::AF_SMC,
    Xdp = netfilter::AF_XDP,
    Mctp = netfilter::AF_MCTP,
    Max = netfilter::AF_MAX,
}

impl ProtocolFamily {
    const LOCAL: ProtocolFamily = ProtocolFamily::Unix;
    const ROUTE: ProtocolFamily = ProtocolFamily::Netlink;
}

impl From<ProtocolFamily> for u8 {
    fn from(value: ProtocolFamily) -> Self {
        value as u8
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPriority {
    First = netfilter::nf_ip_hook_priorities_NF_IP_PRI_FIRST,
    RawBeforeDefrag = netfilter::nf_ip_hook_priorities_NF_IP_PRI_RAW_BEFORE_DEFRAG,
    ConntrackDefrag = netfilter::nf_ip_hook_priorities_NF_IP_PRI_CONNTRACK_DEFRAG,
    Raw = netfilter::nf_ip_hook_priorities_NF_IP_PRI_RAW,
    SelinuxFirst = netfilter::nf_ip_hook_priorities_NF_IP_PRI_SELINUX_FIRST,
    Conntrack = netfilter::nf_ip_hook_priorities_NF_IP_PRI_CONNTRACK,
    Mangle = netfilter::nf_ip_hook_priorities_NF_IP_PRI_MANGLE,
    NatDst = netfilter::nf_ip_hook_priorities_NF_IP_PRI_NAT_DST,
    Filter = netfilter::nf_ip_hook_priorities_NF_IP_PRI_FILTER,
    Security = netfilter::nf_ip_hook_priorities_NF_IP_PRI_SECURITY,
    NatSrc = netfilter::nf_ip_hook_priorities_NF_IP_PRI_NAT_SRC,
    SelinuxLast = netfilter::nf_ip_hook_priorities_NF_IP_PRI_SELINUX_LAST,
    ConntrackHelper = netfilter::nf_ip_hook_priorities_NF_IP_PRI_CONNTRACK_HELPER,
    ConntrackConfirm = netfilter::nf_ip_hook_priorities_NF_IP_PRI_CONNTRACK_CONFIRM,
}

impl HookPriority {
    pub(crate) const LAST: HookPriority = HookPriority::ConntrackConfirm;
}

impl From<HookPriority> for i32 {
    fn from(value: HookPriority) -> Self {
        value as i32
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookResponse {
    Drop = netfilter::NF_DROP,
    Accept = netfilter::NF_ACCEPT,
    Stolen = netfilter::NF_STOLEN,
    Queue = netfilter::NF_QUEUE,
    Repeat = netfilter::NF_REPEAT,
    Stop = netfilter::NF_STOP,
}

impl HookResponse {
    pub(crate) const MAX_VERDICT: HookResponse = HookResponse::Stop;
}

impl From<HookResponse> for u32 {
    fn from(value: HookResponse) -> Self {
        value as u32
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookNum {
    PreRouting = netfilter::nf_inet_hooks_NF_INET_PRE_ROUTING,
    LocalIn = netfilter::nf_inet_hooks_NF_INET_LOCAL_IN,
    Forward = netfilter::nf_inet_hooks_NF_INET_FORWARD,
    LocalOut = netfilter::nf_inet_hooks_NF_INET_LOCAL_OUT,
    PostRouting = netfilter::nf_inet_hooks_NF_INET_POST_ROUTING,
    NumHooks = netfilter::nf_inet_hooks_NF_INET_NUMHOOKS,
}

impl HookNum {
    pub const INGRESS: HookNum = HookNum::NumHooks;
}

impl From<HookNum> for u32 {
    fn from(value: HookNum) -> Self {
        value as u32
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Ip = netfilter::IPPROTO_IP,
    Icmp = netfilter::IPPROTO_ICMP,
    Igmp = netfilter::IPPROTO_IGMP,
    Ipip = netfilter::IPPROTO_IPIP,
    Tcp = netfilter::IPPROTO_TCP,
    Egp = netfilter::IPPROTO_EGP,
    Pup = netfilter::IPPROTO_PUP,
    Udp = netfilter::IPPROTO_UDP,
    Idp = netfilter::IPPROTO_IDP,
    Tp = netfilter::IPPROTO_TP,
    Dccp = netfilter::IPPROTO_DCCP,
    Ipv6 = netfilter::IPPROTO_IPV6,
    Rsvp = netfilter::IPPROTO_RSVP,
    Gre = netfilter::IPPROTO_GRE,
    Esp = netfilter::IPPROTO_ESP,
    Ah = netfilter::IPPROTO_AH,
    Mtp = netfilter::IPPROTO_MTP,
    Beetph = netfilter::IPPROTO_BEETPH,
    Encap = netfilter::IPPROTO_ENCAP,
    Pim = netfilter::IPPROTO_PIM,
    Comp = netfilter::IPPROTO_COMP,
    L2tp = netfilter::IPPROTO_L2TP,
    Sctp = netfilter::IPPROTO_SCTP,
    Udplite = netfilter::IPPROTO_UDPLITE,
    Mpls = netfilter::IPPROTO_MPLS,
    Ethernet = netfilter::IPPROTO_ETHERNET,
    Raw = netfilter::IPPROTO_RAW,
    Mptcp = netfilter::IPPROTO_MPTCP,
    Max = netfilter::IPPROTO_MAX,
}

impl From<IpProtocol> for u32 {
    fn from(value: IpProtocol) -> Self {
        value as u32
    }
}

impl TryFrom<u32> for IpProtocol {
    type Error = error::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            netfilter::IPPROTO_IP => Ok(Self::Ip),
            netfilter::IPPROTO_ICMP => Ok(Self::Icmp),
            netfilter::IPPROTO_IGMP => Ok(Self::Igmp),
            netfilter::IPPROTO_IPIP => Ok(Self::Ipip),
            netfilter::IPPROTO_TCP => Ok(Self::Tcp),
            netfilter::IPPROTO_EGP => Ok(Self::Egp),
            netfilter::IPPROTO_PUP => Ok(Self::Pup),
            netfilter::IPPROTO_UDP => Ok(Self::Udp),
            netfilter::IPPROTO_IDP => Ok(Self::Idp),
            netfilter::IPPROTO_TP => Ok(Self::Tp),
            netfilter::IPPROTO_DCCP => Ok(Self::Dccp),
            netfilter::IPPROTO_IPV6 => Ok(Self::Ipv6),
            netfilter::IPPROTO_RSVP => Ok(Self::Rsvp),
            netfilter::IPPROTO_GRE => Ok(Self::Gre),
            netfilter::IPPROTO_ESP => Ok(Self::Esp),
            netfilter::IPPROTO_AH => Ok(Self::Ah),
            netfilter::IPPROTO_MTP => Ok(Self::Mtp),
            netfilter::IPPROTO_BEETPH => Ok(Self::Beetph),
            netfilter::IPPROTO_ENCAP => Ok(Self::Encap),
            netfilter::IPPROTO_PIM => Ok(Self::Pim),
            netfilter::IPPROTO_COMP => Ok(Self::Comp),
            netfilter::IPPROTO_L2TP => Ok(Self::L2tp),
            netfilter::IPPROTO_SCTP => Ok(Self::Sctp),
            netfilter::IPPROTO_UDPLITE => Ok(Self::Udplite),
            netfilter::IPPROTO_MPLS => Ok(Self::Mpls),
            netfilter::IPPROTO_ETHERNET => Ok(Self::Ethernet),
            netfilter::IPPROTO_RAW => Ok(Self::Raw),
            netfilter::IPPROTO_MPTCP => Ok(Self::Mptcp),
            netfilter::IPPROTO_MAX => Ok(Self::Max),
            _ => Err(error::Error::new(
                "unknown protocol value",
                error::Kind::Unknown,
            )),
        }
    }
}

/// Wraps the kernel's `struct iphdr`.
#[repr(transparent)]
pub(crate) struct IpHeader(UnsafeCell<iphdr>);

impl IpHeader {
    pub(crate) fn protocol(&self) -> Result<IpProtocol, error::Error> {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        IpProtocol::try_from(u32::from(unsafe {
            core::ptr::addr_of!((*self.0.get()).protocol).read()
        }))
    }

    pub(crate) fn source_addr(&self) -> Ipv4Addr {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        let s_addr =
            unsafe { core::ptr::addr_of!((*self.0.get()).__bindgen_anon_1.addrs.saddr).read() };
        Ipv4Addr(in_addr { s_addr })
    }

    pub(crate) fn destination_addr(&self) -> Ipv4Addr {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        let s_addr =
            unsafe { core::ptr::addr_of!((*self.0.get()).__bindgen_anon_1.addrs.daddr).read() };
        Ipv4Addr(in_addr { s_addr })
    }

    /// Creates a reference to an [`IpHeader`] from a valid pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid and remains valid for the lifetime of the
    /// returned [`IpHeader`] instance.
    pub(crate) unsafe fn from_ptr<'a>(ptr: *const iphdr) -> &'a IpHeader {
        // SAFETY: The safety requirements guarantee the validity of the dereference, while the
        // `IpHeader` type being transparent makes the cast ok.
        unsafe { &*ptr.cast() }
    }
}
/// Wraps the kernel's `struct sk_buff`.
///
/// Took part of the implementaion from an [`old API`](https://rust-for-linux.github.io/docs/rust/src/kernel/net.rs.html#65-99)
#[repr(transparent)]
pub(crate) struct SkBuff(UnsafeCell<sk_buff>);

impl SkBuff {
    /// Creates a reference to an [`SkBuff`] from a valid pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid and remains valid for the lifetime of the
    /// returned [`SkBuff`] instance.
    pub(crate) unsafe fn from_ptr<'a>(ptr: *const sk_buff) -> &'a SkBuff {
        // SAFETY: The safety requirements guarantee the validity of the dereference, while the
        // `SkBuff` type being transparent makes the cast ok.
        unsafe { &*ptr.cast() }
    }

    /// Returns the total length of the data (in all segments) in the skb.
    pub(crate) fn len(&self) -> u32 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).len).read() }
    }

    pub(crate) fn data_len(&self) -> u32 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).data_len).read() }
    }

    pub(crate) fn mac_header(&self) -> Result<&[u8], error::Error> {
        let len: usize = if self.is_nonlinear() {
            self.data_len()
        } else {
            self.len()
        }
        .try_into()?;

        // SAFETY: The existence of a shared reference means `self.0` is valid.
        let data = unsafe {
            core::ptr::addr_of!((*self.0.get()).head)
                .read()
                .wrapping_add(
                    core::ptr::addr_of!(
                        (*self.0.get()).__bindgen_anon_4.headers.as_ref().mac_header
                    )
                    .read()
                    .into(),
                )
        };

        // SAFETY: The `struct sk_buff` conventions guarantee that at least `skb_mac_header_len(skb)` bytes
        // are valid from `skb->mac_header`.
        Ok(unsafe { core::slice::from_raw_parts(data, len) })
    }

    fn get_network_header_addr(&self) -> *mut u8 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe {
            core::ptr::addr_of!((*self.0.get()).head)
                .read()
                .wrapping_add(
                    core::ptr::addr_of!(
                        (*self.0.get())
                            .__bindgen_anon_4
                            .headers
                            .as_ref()
                            .network_header
                    )
                    .read()
                    .into(),
                )
        }
    }

    pub(crate) fn ip_header(&self) -> *mut u8 {
        self.get_network_header_addr()
    }

    pub(crate) fn is_nonlinear(&self) -> bool {
        self.data_len() != 0
    }

    pub(crate) fn transport_header(&self) -> *mut u8 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe {
            core::ptr::addr_of!((*self.0.get()).head)
                .read()
                .wrapping_add(
                    core::ptr::addr_of!(
                        (*self.0.get())
                            .__bindgen_anon_4
                            .headers
                            .as_ref()
                            .transport_header
                    )
                    .read()
                    .into(),
                )
        }
    }
}

/// An IPv4 address.
///
/// This is equivalent to C's `in_addr`.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct Ipv4Addr(in_addr);

impl Ipv4Addr {
    /// A wildcard IPv4 address.
    ///
    /// Binding to this address means binding to all IPv4 addresses.
    // pub(crate) const ANY: Self = Self::new(0, 0, 0, 0);

    /// The IPv4 loopback address.
    // pub(crate) const LOOPBACK: Self = Self::new(127, 0, 0, 1);

    /// The IPv4 broadcast address.
    // pub(crate) const BROADCAST: Self = Self::new(255, 255, 255, 255);

    /// Creates a new IPv4 address with the given components.
    #[allow(dead_code)]
    pub(crate) const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(in_addr {
            s_addr: u32::from_be_bytes([a, b, c, d]),
        })
    }
}

impl PartialEq for Ipv4Addr {
    fn eq(&self, other: &Self) -> bool {
        self.0.s_addr.eq(&other.0.s_addr)
    }
}

impl core::fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.0.s_addr.to_le_bytes();

        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

#[repr(transparent)]
pub(crate) struct TcpHeader(UnsafeCell<tcphdr>);

impl TcpHeader {
    /// Creates a reference to an [`TcpHeader`] from a valid pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid and remains valid for the lifetime of the
    /// returned [`TcpHeader`] instance.
    pub(crate) unsafe fn from_ptr<'a>(ptr: *const tcphdr) -> &'a TcpHeader {
        // SAFETY: The safety requirements guarantee the validity of the dereference, while the
        // `TcpHeader` type being transparent makes the cast ok.
        unsafe { &*ptr.cast() }
    }

    pub(crate) fn destination_port(&self) -> u16 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).dest).read() }.swap_bytes()
    }

    pub(crate) fn source_port(&self) -> u16 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).source).read() }.swap_bytes()
    }
}

#[repr(transparent)]
pub(crate) struct UdpHeader(UnsafeCell<udphdr>);

impl UdpHeader {
    /// Creates a reference to an [`UdpHeader`] from a valid pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid and remains valid for the lifetime of the
    /// returned [`UdpHeader`] instance.
    pub(crate) unsafe fn from_ptr<'a>(ptr: *const udphdr) -> &'a UdpHeader {
        // SAFETY: The safety requirements guarantee the validity of the dereference, while the
        // `UdpHeader` type being transparent makes the cast ok.
        unsafe { &*ptr.cast() }
    }

    pub(crate) fn destination_port(&self) -> u16 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).dest).read() }
    }

    pub(crate) fn source_port(&self) -> u16 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).source).read() }
    }
}

// pub(crate) trait TransportLayerProtocol<'a> {
//     fn destination_port(&'a self) -> u16;

//     fn destination_addr(&'a self) -> Ipv4Addr;

//     fn source_port(&'a self) -> u16;

//     fn source_addr(&'a self) -> Ipv4Addr;

//     fn from_skb(sk_buff: &'a SkBuff) -> &'a Self;
// }

// pub(crate) struct Tcp<'a> {
//     ip_header: &'a IpHeader,
//     tcp_header: &'a TcpHeader,
// }

// impl<'a> TransportLayerProtocol<'a> for Tcp<'a> {
//     fn from_skb(sk_buff: &'a SkBuff) -> &'a Self {
//         let ip_header = unsafe { IpHeader::from_ptr(sk_buff.ip_header() as *const _) };
//         let tcp_header =
//     }
// }

pub(crate) enum TransportLayerProtocol<'a> {
    Udp { udp_header: &'a UdpHeader },
    Tcp { tcp_header: &'a TcpHeader },
}

impl<'a> TransportLayerProtocol<'a> {
    pub(crate) fn new(sk_buff: &'a SkBuff, protocol: IpProtocol) -> Result<Self, error::Error> {
        match protocol {
            IpProtocol::Tcp => {
                let tcp_header =
                    unsafe { TcpHeader::from_ptr(sk_buff.transport_header() as *const _) };
                Ok(Self::Tcp { tcp_header })
            }
            IpProtocol::Udp => {
                let udp_header =
                    unsafe { UdpHeader::from_ptr(sk_buff.transport_header() as *const _) };
                Ok(Self::Udp { udp_header })
            }
            _ => Err(error::Error::new(
                "unsupported protocol",
                error::Kind::Unsupported,
            )),
        }
    }

    pub(crate) fn destination_port(&self) -> u16 {
        match self {
            Self::Udp { udp_header } => udp_header.destination_port(),
            Self::Tcp { tcp_header } => tcp_header.destination_port(),
        }
    }

    pub(crate) fn source_port(&self) -> u16 {
        match self {
            Self::Udp { udp_header } => udp_header.source_port(),
            Self::Tcp { tcp_header } => tcp_header.source_port(),
        }
    }
}

pub(crate) struct TransportPacket<'a> {
    ip_header: &'a IpHeader,
    transport_layer: TransportLayerProtocol<'a>,
}

impl<'a> TransportPacket<'a> {
    pub(crate) fn from_skb(sk_buff: &'a SkBuff) -> Result<Self, error::Error> {
        let ip_header = unsafe { IpHeader::from_ptr(sk_buff.ip_header() as *const _) };

        let protocol = ip_header.protocol()?;

        let transport_layer = TransportLayerProtocol::new(sk_buff, protocol)?;

        Ok(Self {
            ip_header,
            transport_layer,
        })
    }

    pub(crate) fn destination_addr(&self) -> Ipv4Addr {
        self.ip_header.destination_addr()
    }

    pub(crate) fn source_addr(&self) -> Ipv4Addr {
        self.ip_header.source_addr()
    }

    pub(crate) fn destination_port(&self) -> u16 {
        self.transport_layer.destination_port()
    }

    pub(crate) fn source_port(&self) -> u16 {
        self.transport_layer.source_port()
    }

    pub(crate) fn protocol(&self) -> IpProtocol {
        self.ip_header
            .protocol()
            .expect("if instance exists, the protocol should be valid")
    }
}
