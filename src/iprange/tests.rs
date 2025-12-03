use super::IpVer::{V4, V6};
use super::{IPv4, IPv6, IpRange, TargetRange};
use crate::{ipv4, ipv6};
use alloc::format;
use pretty_assertions::assert_eq;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_initialization() {
    assert_eq!(
        IpRange::<IPv4>::new("127.0.0.1", "").unwrap().get_version(),
        V4
    );
    assert_eq!(
        IpRange::<IPv4>::new("127.0.0.2", "127.255.255.255")
            .unwrap()
            .get_version(),
        V4
    );
    assert_eq!(
        IpRange::<IPv6>::new("::1", "::2").unwrap().get_version(),
        V6
    );

    assert_eq!(IpRange::<IPv6>::new("::1", "").unwrap().get_version(), V6);
}

#[test]
fn test_get_range() {
    let x = IpRange::<IPv4>::new("127.0.0.1/24", "").unwrap();
    let xx = IpRange::<IPv4>::new("255.255.1.1/16", "").unwrap();
    let xxx = IpRange::<IPv4>::new("127.0.0.1", "127.0.0.255").unwrap();
    assert_eq!(
        x.get_range(),
        ("127.0.0.0".to_string(), "127.0.0.255".to_string())
    );
    assert_eq!(
        xx.get_range(),
        ("255.255.0.0".to_string(), "255.255.255.255".to_string())
    );
    assert_eq!(
        xxx.get_range(),
        ("127.0.0.1".to_string(), "127.0.0.255".to_string())
    );
}

#[test]
fn test_len() {
    assert_eq!(
        IpRange::<IPv4>::new("127.0.0.3", "127.0.0.4")
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        IpRange::<IPv4>::new("127.0.0.3", "127.0.255.4")
            .unwrap()
            .len(),
        65282
    );
    assert_eq!(
        IpRange::<IPv4>::new("127.0.0.1", "255.255.255.255")
            .unwrap()
            .len(),
        2164260863
    );
    assert_eq!(IpRange::<IPv6>::new("::1", "::2").unwrap().len(), 2);
    assert_eq!(
        IpRange::<IPv6>::new("fe80::/10", "").unwrap().len(),
        332306998946228968225951765070086144
    );
}

#[test]
fn test_contains() {
    let range = IpRange::<IPv4>::new("127.0.0.3", "127.0.0.5").unwrap();
    assert!(range.contains("127.0.0.3").unwrap());
    assert!(range.contains("127.0.0.4").unwrap());
    assert!(range.contains("127.0.0.5").unwrap());
    assert!(!range.contains("::1").unwrap());
    assert!(range.contains("0:0:0:0:0:fff:7f00:4").unwrap());
    assert!(range.contains("0:0:0:0:0:fff:7f00:4/127").unwrap());
    assert!(!range.contains("127.0.0.6").unwrap());
}

#[test]
fn test_contains_from_netmask_inputs() {
    let host = "10.0.120.90";
    let mask = "255.255.248.0";
    let prefix = ipv4::netmask2prefix(mask);
    assert_eq!(prefix, 21);

    let cidr = format!("{}/{}", host, prefix);
    let cidr_range = IpRange::<IPv4>::new(&cidr, "").unwrap();
    assert!(cidr_range.contains("10.0.123.1").unwrap());
    assert!(!cidr_range.contains("10.0.128.1").unwrap());

    let bounds = ipv4::subnet2block(&format!("{}/{}", host, mask)).unwrap();
    let explicit = IpRange::<IPv4>::new(&bounds.0, &bounds.1).unwrap();
    assert!(explicit.contains("10.0.123.1").unwrap());
    assert!(!explicit.contains("10.0.128.1").unwrap());
    assert_eq!(cidr_range, explicit);
}

#[test]
fn test_contains_numeric_helpers() {
    let ipv4_range = IpRange::<IPv4>::new("127.0.0.1", "127.0.0.10").unwrap();
    let addr = ipv4::ip2long("127.0.0.5").unwrap();
    assert!(ipv4_range.contains_addr(addr));
    assert!(ipv4_range.contains_range(addr, ipv4::ip2long("127.0.0.6").unwrap()));
    assert!(!ipv4_range.contains_range(
        ipv4::ip2long("127.0.0.0").unwrap(),
        ipv4::ip2long("127.0.0.2").unwrap()
    ));

    let ipv6_range = IpRange::<IPv6>::new("2001:db8::", "2001:db8::5").unwrap();
    let addr6 = ipv6::ip2long("2001:db8::2").unwrap();
    assert!(ipv6_range.contains_addr(addr6));
    assert!(ipv6_range.contains_range(addr6, ipv6::ip2long("2001:db8::3").unwrap()));
    assert!(!ipv6_range.contains_range(
        ipv6::ip2long("2001:db8::6").unwrap(),
        ipv6::ip2long("2001:db8::7").unwrap()
    ));
}

#[test]
fn test_contains_std_helpers() {
    let ipv4_range = IpRange::<IPv4>::new("10.0.0.0/24", "").unwrap();
    assert!(ipv4_range.contains_ipv4(Ipv4Addr::new(10, 0, 0, 42)));
    assert!(!ipv4_range.contains_ipv4(Ipv4Addr::new(10, 0, 1, 1)));
    assert!(
        ipv4_range.contains_ipv4_bounds(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 200))
    );
    assert!(ipv4_range.contains_ipaddr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    assert!(!ipv4_range.contains_ipaddr(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    let ipv6_range = IpRange::<IPv6>::new("2001:db8::/120", "").unwrap();
    let start = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let end = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
    assert!(ipv6_range.contains_ipv6(start));
    assert!(ipv6_range.contains_ipv6_bounds(start, end));
    assert!(!ipv6_range.contains_ipaddr(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

#[test]
fn test_addrs_iterator_ipv4() {
    let range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.3").unwrap();
    let mut iter = range.addrs();
    assert_eq!(iter.size_hint(), (3, Some(3)));
    let collected = iter.by_ref().collect::<Vec<_>>();
    assert_eq!(
        collected,
        [
            ipv4::ip2long("10.0.0.1").unwrap(),
            ipv4::ip2long("10.0.0.2").unwrap(),
            ipv4::ip2long("10.0.0.3").unwrap()
        ]
    );

    // FusedIterator behavior: once exhausted, it stays exhausted
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next(), None);

    // addrs() should not advance the main iterator state
    let mut range_again = range;
    let _ = range_again.addrs().collect::<Vec<_>>();
    assert_eq!(range_again.next().unwrap(), "10.0.0.1");
}

#[test]
fn test_addrs_iterator_ipv6_and_range_consistency() {
    let range = IpRange::<IPv6>::new("2001:db8::", "2001:db8::3").unwrap();
    let addrs = range.addrs().collect::<Vec<_>>();
    assert_eq!(addrs.len(), 4);
    assert_eq!(range.len(), 4);
    assert_eq!(
        range.get_range(),
        ("2001:db8::".to_string(), "2001:db8::3".to_string())
    );
    assert_eq!(ipv6::long2ip(addrs[0], false), "2001:db8::");
    assert_eq!(ipv6::long2ip(*addrs.last().unwrap(), false), "2001:db8::3");
}

#[test]
fn test_iterator_size_hint_and_remaining_updates() {
    let mut range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.2").unwrap();
    assert_eq!(Iterator::size_hint(&range), (2, Some(2)));
    assert_eq!(range.remaining(), 2);

    range.next();
    assert_eq!(Iterator::size_hint(&range), (1, Some(1)));
    assert_eq!(range.remaining(), 1);

    range.next();
    assert_eq!(Iterator::size_hint(&range), (0, Some(0)));
    assert_eq!(range.remaining(), 0);
    assert_eq!(range.next(), None);
    assert_eq!(range.next(), None); // fused behavior for IpRange iterator
}

#[test]
fn test_is_empty_and_reversed_bounds_error() {
    let range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.1").unwrap();
    assert!(!range.is_empty());
    assert!(IpRange::<IPv4>::new("10.0.0.2", "10.0.0.1").is_err());
    assert!(IpRange::<IPv6>::new("2001:db8::2", "2001:db8::1").is_err());
}

#[cfg(feature = "serde")]
#[test]
fn test_serde_roundtrip_ipv4_range() {
    let mut range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.5").unwrap();
    range.next();
    let json = serde_json::to_string(&range).unwrap();
    let decoded: IpRange<IPv4> = serde_json::from_str(&json).unwrap();
    assert_eq!(range, decoded);
    assert_eq!(decoded.remaining(), range.remaining());
}

#[cfg(feature = "serde")]
#[test]
fn test_serde_roundtrip_ipv6_range() {
    let mut range = IpRange::<IPv6>::new("2001:db8::1", "2001:db8::5").unwrap();
    range.next();
    let json = serde_json::to_string(&range).unwrap();
    let decoded: IpRange<IPv6> = serde_json::from_str(&json).unwrap();
    assert_eq!(range, decoded);
    assert_eq!(decoded.remaining(), range.remaining());
}

#[test]
fn test_equal() {
    assert_eq!(
        IpRange::<IPv4>::new("127.0.0.0/8", "").unwrap(),
        IpRange::<IPv4>::new("127.0.0.0", "127.255.255.255").unwrap()
    );
    assert_ne!(
        IpRange::<IPv4>::new("127.0.0.0/8", "").unwrap(),
        IpRange::<IPv4>::new("127.0.0.0", "127.255.255.254").unwrap()
    );
    assert_eq!(
        IpRange::<IPv6>::new("::1/64", "").unwrap(),
        IpRange::<IPv6>::new("::", "::ffff:ffff:ffff:ffff").unwrap()
    );
    assert_ne!(
        IpRange::<IPv6>::new("::1/64", "").unwrap(),
        IpRange::<IPv6>::new("::2", "::ffff:ffff:ffff:ffff").unwrap()
    );
}

#[test]
fn test_next() {
    let mut a = IpRange::<IPv4>::new("127/31", "").unwrap();
    assert_eq!(a.next().unwrap(), "127.0.0.0");
    assert_eq!(a.next().unwrap(), "127.0.0.1");
    assert_eq!(a.next(), None);
    let mut b = IpRange::<IPv6>::new("::1", "::3").unwrap();
    assert_eq!(b.next().unwrap(), "::1");
    assert_eq!(b.next().unwrap(), "::2");
    assert_eq!(b.next().unwrap(), "::3");
    assert_eq!(b.next(), None);
}

#[test]
fn test_remaining() {
    let mut a = IpRange::<IPv4>::new("127/31", "").unwrap();
    assert_eq!(a.remaining(), 2);
    a.next();
    assert_eq!(a.remaining(), 1);
    a.next();
    assert_eq!(a.remaining(), 0);
}

#[test]
fn test_single_address_ranges() {
    let mut v4 = IpRange::<IPv4>::new("0.0.0.0", "0.0.0.0").unwrap();
    assert_eq!(v4.len(), 1);
    assert_eq!(v4.get_range(), ("0.0.0.0".into(), "0.0.0.0".into()));
    assert_eq!(v4.next().unwrap(), "0.0.0.0");
    assert_eq!(v4.next(), None);
}

#[test]
fn test_ipv4_range_broadcast_bounds() {
    let lower = IpRange::<IPv4>::new("0.0.0.0", "0.0.0.1").unwrap();
    assert!(lower.contains("0.0.0.0").unwrap());
    assert!(!lower.contains("255.255.255.255").unwrap());

    let upper = IpRange::<IPv4>::new("255.255.255.254", "255.255.255.255").unwrap();
    assert!(upper.contains("255.255.255.255").unwrap());
    assert!(!upper.contains("0.0.0.0").unwrap());
}

#[test]
fn test_additional_reserved_blocks() {
    assert!(IpRange::<IPv4>::is_reserved(ipv4::PRIVATE_NETWORK_10).unwrap());
    assert!(IpRange::<IPv6>::is_reserved(ipv6::LINK_LOCAL).unwrap());
}

#[test]
fn test_is_reserved() {
    assert!(IpRange::<IPv4>::is_reserved("127.0.0.1").unwrap());
    assert!(IpRange::<IPv4>::is_reserved(crate::ipv4::BROADCAST).unwrap());
    assert!(IpRange::<IPv4>::is_reserved(crate::ipv4::LOOPBACK).unwrap());
    assert!(IpRange::<IPv4>::is_reserved(crate::ipv4::IPV6_TO_IPV4_RELAY).unwrap());
    assert!(!IpRange::<IPv4>::is_reserved("8.8.8.8").unwrap());
    assert!(IpRange::<IPv6>::is_reserved(crate::ipv6::LOOPBACK).unwrap());

    assert_eq!(IpRange::<IPv4>::is_reserved("123456").ok(), None);
    assert_eq!(IpRange::<IPv6>::is_reserved("123456").ok(), None);
}

#[test]
fn test_constructor() {
    assert!(IpRange::<IPv4>::new("Bolognese", "").is_err());
    assert!(IpRange::<IPv6>::new("Bolognese", "").is_err());
}

#[test]
#[should_panic]
fn test_should_panic() {
    IpRange::<IPv4>::new("12345678", "").unwrap();
    IpRange::<IPv6>::new("12345678", "").unwrap();
}

#[test]
fn test_target_range_parse_edge_cases() {
    // IPv4-mapped IPv6
    let t = TargetRange::parse("::ffff:192.168.1.1").unwrap();
    assert!(!t.is_range());

    // IPv4-compatible IPv6 (deprecated but syntax valid)
    let t = TargetRange::parse("::192.168.1.1").unwrap();
    assert!(!t.is_range());

    // IPv6 with embedded IPv4
    let t = TargetRange::parse("2001:db8::192.168.1.1").unwrap();
    assert!(!t.is_range());

    // Invalid inputs
    assert!(TargetRange::parse("192.168.1.1/256").is_err());
    assert!(TargetRange::parse("::/129").is_err());
    assert!(TargetRange::parse("garbage").is_err());
    assert!(TargetRange::parse("1.2.3.4.5").is_err());
    assert!(TargetRange::parse("1234::1234::1234").is_err());

    // Mixed inputs
    let t = TargetRange::parse("1.2.3.4/24").unwrap();
    assert!(t.is_range());

    let t = TargetRange::parse("::1/64").unwrap();
    assert!(t.is_range());
}
