//! Network filter abstractions.

// Some bindings are not used in the code, but they are important for demonstration purpuses.
#![allow(dead_code)]

use core::cell::UnsafeCell;

use kernel::error::to_result;
// `netfilter` is my bindings crate with all headers I need.
use kernel::netfilter;
use kernel::netfilter::{
    in_addr, iphdr, net, nf_hook_ops, nf_hookfn, nf_register_net_hook, nf_unregister_net_hook, sk_buff, tcphdr, udphdr,
};
use kernel::prelude::*;

use crate::error;

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
        self.inner.hooknum = hooknum as _
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

/// Represents network protocol families.
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

/// Represents priority levels for netfilter hooks.
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

/// Represents possible return values from netfilter hook callback functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookResponse {
    /// Drop the packet.
    Drop = netfilter::NF_DROP as _,
    /// Accept the packet.
    Accept = netfilter::NF_ACCEPT as _,
    /// Packet has been "stolen" or consumed by the hook function.
    Stolen = netfilter::NF_STOLEN as _,
    /// Queue the packet to userspace for processing.
    Queue = netfilter::NF_QUEUE as _,
    /// Run the current hook function again.
    Repeat = netfilter::NF_REPEAT as _,
    #[deprecated(note = "Deprecated, for userspace nf_queue compatibility.")]
    Stop = netfilter::NF_STOP as _,
}

impl HookResponse {
    /// The highest possible verdict number.
    #[allow(deprecated)]
    pub(crate) const MAX_VERDICT: HookResponse = HookResponse::Stop;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookNum {
    PreRouting = netfilter::nf_inet_hooks_NF_INET_PRE_ROUTING as _,
    LocalIn = netfilter::nf_inet_hooks_NF_INET_LOCAL_IN as _,
    Forward = netfilter::nf_inet_hooks_NF_INET_FORWARD as _,
    LocalOut = netfilter::nf_inet_hooks_NF_INET_LOCAL_OUT as _,
    PostRouting = netfilter::nf_inet_hooks_NF_INET_POST_ROUTING as _,
    NumHooks = netfilter::nf_inet_hooks_NF_INET_NUMHOOKS as _,
}

impl HookNum {
    pub(crate) const INGRESS: HookNum = HookNum::NumHooks;
}

/// Represents IP protocols used in network packet headers
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
            _ => Err(error::Error::new("unknown protocol value", error::Kind::Unknown)),
        }
    }
}

/// Wraps the kernel's `[`struct iphdr`]: srctree/include/linux/ip.h.
#[repr(transparent)]
pub(crate) struct IpHeader(UnsafeCell<iphdr>);

impl IpHeader {
    /// Gets the protocol from the header.
    pub(crate) fn protocol(&self) -> Result<IpProtocol, error::Error> {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        IpProtocol::try_from(u32::from(unsafe {
            core::ptr::addr_of!((*self.0.get()).protocol).read()
        }))
    }

    /// Gets the source address from the header.
    pub(crate) fn source_addr(&self) -> Ipv4Addr {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        let s_addr = unsafe { core::ptr::addr_of!((*self.0.get()).__bindgen_anon_1.addrs.saddr).read() };
        Ipv4Addr(in_addr { s_addr })
    }

    /// Gets the destination address from the header.
    pub(crate) fn destination_addr(&self) -> Ipv4Addr {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        let s_addr = unsafe { core::ptr::addr_of!((*self.0.get()).__bindgen_anon_1.addrs.daddr).read() };
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

/// Wrapper around the kernel's [`struct sk_buff`]: srctree/include/linux/skbuff.h.
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

    /// Returns the length of the data in the skb.
    pub(crate) fn data_len(&self) -> u32 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).data_len).read() }
    }

    /// Returns a reference to the MAC header of the skb, ensuring it's within valid bounds.
    pub(crate) fn mac_header(&self) -> Result<&[u8], error::Error> {
        let len: usize = if self.is_nonlinear() {
            self.data_len()
        } else {
            self.len()
        }
        .try_into()?;

        // SAFETY: The existence of a shared reference means `self.0` is valid.
        let data = unsafe {
            core::ptr::addr_of!((*self.0.get()).head).read().wrapping_add(
                core::ptr::addr_of!((*self.0.get()).__bindgen_anon_4.headers.as_ref().mac_header)
                    .read()
                    .into(),
            )
        };

        // SAFETY: The `struct sk_buff` conventions guarantee that at least `skb_mac_header_len(skb)` bytes
        // are valid from `skb->mac_header`.
        Ok(unsafe { core::slice::from_raw_parts(data, len) })
    }

    /// Returns the address of the network header within the skb.
    pub(crate) fn ip_header_addr(&self) -> *mut u8 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe {
            core::ptr::addr_of!((*self.0.get()).head).read().wrapping_add(
                core::ptr::addr_of!((*self.0.get()).__bindgen_anon_4.headers.as_ref().network_header)
                    .read()
                    .into(),
            )
        }
    }

    /// Determines if the skb is nonlinear, meaning its data is spread across multiple segments.
    pub(crate) fn is_nonlinear(&self) -> bool {
        self.data_len() != 0
    }

    /// Returns the address of the transport layer header within the skb.
    pub(crate) fn transport_header(&self) -> *mut u8 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe {
            core::ptr::addr_of!((*self.0.get()).head).read().wrapping_add(
                core::ptr::addr_of!((*self.0.get()).__bindgen_anon_4.headers.as_ref().transport_header)
                    .read()
                    .into(),
            )
        }
    }
}

/// Represents an IPv4 address.
///
/// This is equivalent [`struct in_addr`]: srctree/include/linux/in.h in C API.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct Ipv4Addr(in_addr);

impl Ipv4Addr {
    /// A wildcard IPv4 address.
    ///
    /// Binding to this address means binding to all IPv4 addresses.
    pub(crate) const ANY: Self = Self::new(0, 0, 0, 0);

    /// The IPv4 loopback address.
    pub(crate) const LOOPBACK: Self = Self::new(127, 0, 0, 1);

    /// The IPv4 broadcast address.
    pub(crate) const BROADCAST: Self = Self::new(255, 255, 255, 255);

    /// Creates a new IPv4 address with the given components.
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

/// Wrapper around the kernel's [`struct tcphdr`]: srctree/include/linux/tcp.h.
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

    /// Gets the destination port from the header.
    pub(crate) fn destination_port(&self) -> u16 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).dest).read() }.swap_bytes()
    }

    /// Gets the source port from the header.
    pub(crate) fn source_port(&self) -> u16 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).source).read() }.swap_bytes()
    }
}

/// Wrapper around the kernel's [`struct udphdr`]: srctree/include/linux/udp.h.
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

    /// Gets the destination port from the header.
    pub(crate) fn destination_port(&self) -> u16 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).dest).read() }
    }

    /// Gets the source port from the header.
    pub(crate) fn source_port(&self) -> u16 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).source).read() }
    }
}

/// Abstraction over TCP and UDP headers.
pub(crate) enum TransportLayerProtocol<'a> {
    Udp { udp_header: &'a UdpHeader },
    Tcp { tcp_header: &'a TcpHeader },
}

impl<'a> TransportLayerProtocol<'a> {
    /// Creates a new instance.
    ///
    /// #Arguments:
    ///
    /// * (skb)[SkBuff] - buffer with the metadata.
    /// * (protocol)[IpProtocol] - protocol hint from [IpHeader].
    pub(crate) fn new(sk_buff: &'a SkBuff, protocol: IpProtocol) -> Result<Self, error::Error> {
        match protocol {
            IpProtocol::Tcp => {
                let tcp_header = unsafe { TcpHeader::from_ptr(sk_buff.transport_header() as *const _) };
                Ok(Self::Tcp { tcp_header })
            }
            IpProtocol::Udp => {
                let udp_header = unsafe { UdpHeader::from_ptr(sk_buff.transport_header() as *const _) };
                Ok(Self::Udp { udp_header })
            }
            // For the simplicity, only 2 protocols are supported.
            _ => Err(error::Error::new("unsupported protocol", error::Kind::Unsupported)),
        }
    }

    /// Returns the destination port of the packet.
    pub(crate) fn destination_port(&self) -> u16 {
        match self {
            Self::Udp { udp_header } => udp_header.destination_port(),
            Self::Tcp { tcp_header } => tcp_header.destination_port(),
        }
    }

    /// Returns the source port of the packet.
    pub(crate) fn source_port(&self) -> u16 {
        match self {
            Self::Udp { udp_header } => udp_header.source_port(),
            Self::Tcp { tcp_header } => tcp_header.source_port(),
        }
    }
}

/// Represents a network packet and contains necessary information necessary to work with the packet.
pub(crate) struct NetworkPacket<'a> {
    /// Reference to the IP header of the packet.
    ip_header: &'a IpHeader,
    /// Reference to the transport layer protocol of the packet.
    transport_layer: TransportLayerProtocol<'a>,
}

impl<'a> NetworkPacket<'a> {
    /// Constructs a new instance.
    ///
    /// # Arguments:
    ///
    /// * [sk_buff](SkBuff): buffer with the metadata.
    pub(crate) fn from_skb(sk_buff: &'a SkBuff) -> Result<Self, error::Error> {
        let ip_header = unsafe { IpHeader::from_ptr(sk_buff.ip_header_addr() as *const _) };

        let protocol = ip_header.protocol()?;

        let transport_layer = TransportLayerProtocol::new(sk_buff, protocol)?;

        Ok(Self {
            ip_header,
            transport_layer,
        })
    }

    /// Returns a destination address of the packet.
    pub(crate) fn destination_addr(&self) -> Ipv4Addr {
        self.ip_header.destination_addr()
    }

    /// Returns a source address of the packet.
    pub(crate) fn source_addr(&self) -> Ipv4Addr {
        self.ip_header.source_addr()
    }

    /// Returns a destination port of the packet.
    pub(crate) fn destination_port(&self) -> u16 {
        self.transport_layer.destination_port()
    }

    /// Returns a source port of the packet.
    pub(crate) fn source_port(&self) -> u16 {
        self.transport_layer.source_port()
    }

    /// Returns the protocol of the packet.
    pub(crate) fn protocol(&self) -> Result<IpProtocol, error::Error> {
        self.ip_header.protocol()
    }
}
