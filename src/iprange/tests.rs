use super::IpVer::{V4, V6};
use super::{AddrIterator, IPv4, IPv6, IpRange, RangeFamily, TargetRange};
use crate::error::Error;
use crate::{ipv4, ipv6};
use alloc::format;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use pretty_assertions::assert_eq;
use std::collections::hash_map::DefaultHasher;
#[cfg(feature = "std")]
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
fn test_cidr_endpoint_constructor_paths() {
    let range = IpRange::<IPv4>::new("10.0.0.4/30", "10.0.0.12/30").unwrap();
    assert_eq!(
        range.bounds(),
        (
            ipv4::ip2long("10.0.0.4").unwrap(),
            ipv4::ip2long("10.0.0.15").unwrap()
        )
    );

    let range = IpRange::<IPv6>::new("2001:db8::4/126", "2001:db8::c/126").unwrap();
    assert_eq!(
        range.bounds(),
        (
            ipv6::ip2long("2001:db8::4").unwrap(),
            ipv6::ip2long("2001:db8::f").unwrap()
        )
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
fn test_numeric_constructors() {
    let v4 = IpRange::<IPv4>::from_bounds(
        ipv4::ip2long("10.0.0.1").unwrap(),
        ipv4::ip2long("10.0.0.3").unwrap(),
    )
    .unwrap();
    assert_eq!(v4.len(), 3);
    assert_eq!(v4.get_range(), ("10.0.0.1".into(), "10.0.0.3".into()));

    let v4_cidr =
        IpRange::<IPv4>::from_addr_prefix(ipv4::ip2long("10.0.1.2").unwrap(), 16).unwrap();
    assert_eq!(
        v4_cidr.bounds(),
        (
            ipv4::ip2long("10.0.0.0").unwrap(),
            ipv4::ip2long("10.0.255.255").unwrap()
        )
    );
    assert_eq!(
        IpRange::<IPv4>::from_addr_prefix(0, 33).unwrap_err(),
        Error::V4CIDR()
    );
    assert_eq!(
        IpRange::<IPv4>::from_bounds(0, u32::MAX).unwrap_err(),
        Error::V4Subnet()
    );

    let v6 =
        IpRange::<IPv6>::from_addr_prefix(ipv6::ip2long("2001:db8::1234").unwrap(), 126).unwrap();
    assert_eq!(
        v6.bounds(),
        (
            ipv6::ip2long("2001:db8::1234").unwrap(),
            ipv6::ip2long("2001:db8::1237").unwrap()
        )
    );
    assert_eq!(
        IpRange::<IPv6>::from_addr_prefix(0, 129).unwrap_err(),
        Error::V6CIDR()
    );
    assert_eq!(
        IpRange::<IPv6>::from_bounds(0, u128::MAX).unwrap_err(),
        Error::V6Subnet()
    );
}

#[test]
fn test_contains() {
    let range = IpRange::<IPv4>::new("127.0.0.3", "127.0.0.5").unwrap();
    assert!(range.contains("127.0.0.3").unwrap());
    assert!(range.contains("127.0.0.3/32").unwrap());
    assert!(range.contains("127.0.0.4").unwrap());
    assert!(range.contains("127.0.0.5").unwrap());
    assert!(!range.contains("::1").unwrap());
    assert!(range.contains("::ffff:127.0.0.4").unwrap());
    assert!(range.contains("0:0:0:0:0:ffff:7f00:4").unwrap());
    assert!(!range.contains("0:0:0:0:0:fff:7f00:4").unwrap());
    assert!(!range.contains("0:0:0:0:0:fff:7f00:4/127").unwrap());
    assert!(!range.contains("127.0.0.6").unwrap());

    let v6 = IpRange::<IPv6>::new("::7f00:0/112", "").unwrap();
    assert!(!v6.contains("127.0.0.1").unwrap());
    assert!(!v6.contains("127.0.0.1/32").unwrap());
    assert!(v6.contains_addr(ipv6::ip2long("::7f00:1").unwrap()));
}

#[test]
fn test_contains_family_fast_paths() {
    let v4 = IpRange::<IPv4>::new("127.0.0.0/24", "").unwrap();
    assert!(v4.contains_strict("127.0.0.7").unwrap());
    assert!(v4.contains_strict("127.0.0.0/25").unwrap());
    assert!(!v4.contains_strict("127.0.1.1").unwrap());
    assert!(v4.contains_strict("::1").is_err());

    let v6 = IpRange::<IPv6>::new("2001:db8::/120", "").unwrap();
    assert!(v6.contains_strict("2001:db8::1").unwrap());
    assert!(v6.contains_strict("2001:db8::/124").unwrap());
    assert!(!v6.contains_strict("2001:db8:1::1").unwrap());
    assert!(v6.contains_strict("127.0.0.1").is_err());
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
        ipv4::ip2long("127.0.0.6").unwrap(),
        ipv4::ip2long("127.0.0.5").unwrap()
    ));
    assert!(!ipv4_range.contains_range(
        ipv4::ip2long("127.0.0.0").unwrap(),
        ipv4::ip2long("127.0.0.2").unwrap()
    ));

    let ipv6_range = IpRange::<IPv6>::new("2001:db8::", "2001:db8::5").unwrap();
    let addr6 = ipv6::ip2long("2001:db8::2").unwrap();
    assert!(ipv6_range.contains_addr(addr6));
    assert!(ipv6_range.contains_range(addr6, ipv6::ip2long("2001:db8::3").unwrap()));
    assert!(!ipv6_range.contains_range(
        ipv6::ip2long("2001:db8::3").unwrap(),
        ipv6::ip2long("2001:db8::2").unwrap()
    ));
    assert!(!ipv6_range.contains_range(
        ipv6::ip2long("2001:db8::6").unwrap(),
        ipv6::ip2long("2001:db8::7").unwrap()
    ));
}

#[cfg(feature = "std")]
#[test]
fn test_contains_std_helpers() {
    let ipv4_range = IpRange::<IPv4>::new("10.0.0.0/24", "").unwrap();
    assert!(ipv4_range.contains_ipv4(Ipv4Addr::new(10, 0, 0, 0)));
    assert!(ipv4_range.contains_ipv4(Ipv4Addr::new(10, 0, 0, 42)));
    assert!(ipv4_range.contains_ipv4(Ipv4Addr::new(10, 0, 0, 255)));
    assert!(!ipv4_range.contains_ipv4(Ipv4Addr::new(9, 255, 255, 255)));
    assert!(!ipv4_range.contains_ipv4(Ipv4Addr::new(10, 0, 1, 1)));
    assert!(
        ipv4_range.contains_ipv4_bounds(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 200))
    );
    assert!(
        !ipv4_range.contains_ipv4_bounds(Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::new(10, 0, 0, 1))
    );
    assert!(
        !ipv4_range
            .contains_ipv4_bounds(Ipv4Addr::new(9, 255, 255, 255), Ipv4Addr::new(10, 0, 0, 1))
    );
    assert!(ipv4_range.contains_ipaddr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    assert!(!ipv4_range.contains_ipaddr(IpAddr::V6(Ipv6Addr::LOCALHOST)));

    let ipv6_range = IpRange::<IPv6>::new("2001:db8::/120", "").unwrap();
    let lower = Ipv6Addr::new(
        0x2001, 0xdb7, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    );
    let start = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let end = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
    let upper = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 1, 0);
    assert!(ipv6_range.contains_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)));
    assert!(ipv6_range.contains_ipv6(start));
    assert!(ipv6_range.contains_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff)));
    assert!(!ipv6_range.contains_ipv6(lower));
    assert!(!ipv6_range.contains_ipv6(upper));
    assert!(ipv6_range.contains_ipv6_bounds(start, end));
    assert!(!ipv6_range.contains_ipv6_bounds(end, start));
    assert!(!ipv6_range.contains_ipv6_bounds(lower, start));
    assert!(ipv6_range.contains_ipaddr(IpAddr::V6(start)));
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
fn test_next_addr_and_for_each_addr() {
    let mut range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.3").unwrap();
    assert_eq!(range.remaining(), 3);
    assert_eq!(range.next_addr(), Some(ipv4::ip2long("10.0.0.1").unwrap()));
    assert_eq!(range.next_addr(), Some(ipv4::ip2long("10.0.0.2").unwrap()));
    assert_eq!(range.next_addr(), Some(ipv4::ip2long("10.0.0.3").unwrap()));
    assert_eq!(range.next_addr(), None);
    assert_eq!(range.remaining(), 0);

    let range = IpRange::<IPv6>::new("2001:db8::", "2001:db8::2").unwrap();
    let mut collected = Vec::new();
    range.for_each_addr(|addr| collected.push(addr));
    assert_eq!(
        collected,
        vec![
            ipv6::ip2long("2001:db8::").unwrap(),
            ipv6::ip2long("2001:db8::1").unwrap(),
            ipv6::ip2long("2001:db8::2").unwrap()
        ]
    );
}

#[test]
fn test_internal_empty_for_each_addr_noop() {
    let range = IpRange::<IPv4> {
        ip_range: super::RangeState {
            start_ip: 0,
            end_ip: 0,
            len: 0,
            next_ip: 0,
            remaining: 0,
        },
        _marker: PhantomData,
    };

    let mut called = false;
    range.for_each_addr(|_| called = true);
    assert!(!called);
}

#[test]
fn test_addrs_view_adapter() {
    let range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.3").unwrap();
    let first = range.addrs_view().next().unwrap();
    assert_eq!(first.to_ip_string(), "10.0.0.1");

    let raws = range
        .addrs_view()
        .map(|view| view.raw())
        .collect::<Vec<u32>>();
    assert_eq!(
        raws,
        vec![
            ipv4::ip2long("10.0.0.1").unwrap(),
            ipv4::ip2long("10.0.0.2").unwrap(),
            ipv4::ip2long("10.0.0.3").unwrap()
        ]
    );

    let texts = range
        .addrs_view()
        .map(|view| view.to_string())
        .collect::<Vec<String>>();
    assert_eq!(
        texts,
        vec![
            "10.0.0.1".to_string(),
            "10.0.0.2".to_string(),
            "10.0.0.3".to_string()
        ]
    );

    let range = IpRange::<IPv6>::new("2001:db8::", "2001:db8::1").unwrap();
    let mut views = range.addrs_view();
    assert_eq!(views.next().unwrap().to_string(), "2001:db8::");
    assert_eq!(views.next().unwrap().to_ip_string(), "2001:db8::1");
}

#[test]
fn test_for_each_ip_str_reuses_format_buffer() {
    let v4 = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.3").unwrap();
    let mut v4_text = Vec::new();
    v4.for_each_ip_str(|ip| v4_text.push(ip.to_string()));
    assert_eq!(v4_text, vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);

    let v6 = IpRange::<IPv6>::new("2001:db8::", "2001:db8::2").unwrap();
    let mut v6_text = Vec::new();
    v6.for_each_ip_str(|ip| v6_text.push(ip.to_string()));
    assert_eq!(v6_text, vec!["2001:db8::", "2001:db8::1", "2001:db8::2"]);
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
fn test_iterator_count_last_nth_overrides() {
    let range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.3").unwrap();
    assert_eq!(range.clone().count(), 3);
    assert_eq!(range.clone().last().as_deref(), Some("10.0.0.3"));

    let mut nth_range = range.clone();
    assert_eq!(nth_range.nth(1).as_deref(), Some("10.0.0.2"));
    assert_eq!(nth_range.remaining(), 1);
    assert_eq!(nth_range.next().as_deref(), Some("10.0.0.3"));
    assert_eq!(nth_range.next(), None);

    let mut out_of_range = range.clone();
    assert_eq!(out_of_range.nth(3), None);
    assert_eq!(out_of_range.remaining(), 0);

    assert_eq!(range.addrs().count(), 3);
    assert_eq!(
        range.addrs().last(),
        Some(ipv4::ip2long("10.0.0.3").unwrap())
    );

    let mut addrs = range.addrs();
    assert_eq!(addrs.nth(1), Some(ipv4::ip2long("10.0.0.2").unwrap()));
    assert_eq!(addrs.next(), Some(ipv4::ip2long("10.0.0.3").unwrap()));

    let mut addrs = range.addrs();
    assert_eq!(addrs.nth(2), Some(ipv4::ip2long("10.0.0.3").unwrap()));
    assert_eq!(addrs.next(), None);
    let mut addrs = range.addrs();
    assert_eq!(addrs.nth(3), None);

    let mut views = range.addrs_view();
    assert_eq!(
        views.nth(1).map(|view| view.raw()),
        Some(ipv4::ip2long("10.0.0.2").unwrap())
    );
    assert_eq!(range.addrs_view().count(), 3);
    assert_eq!(
        range.addrs_view().last().map(|view| view.to_string()),
        Some("10.0.0.3".to_string())
    );
    let mut views = range.addrs_view();
    assert_eq!(
        views.nth(2).map(|view| view.raw()),
        Some(ipv4::ip2long("10.0.0.3").unwrap())
    );
    assert!(views.next().is_none());

    let ipv6_range = IpRange::<IPv6>::new("2001:db8::", "2001:db8::2").unwrap();
    assert_eq!(ipv6_range.clone().count(), 3);
    assert_eq!(ipv6_range.clone().last().as_deref(), Some("2001:db8::2"));
    let mut ipv6_addrs = ipv6_range.addrs();
    assert_eq!(
        ipv6_addrs.nth(1),
        Some(ipv6::ip2long("2001:db8::1").unwrap())
    );
    let mut ipv6_out_of_range = ipv6_range.clone();
    assert_eq!(ipv6_out_of_range.nth(3), None);
    assert_eq!(ipv6_out_of_range.remaining(), 0);
}

#[test]
fn test_huge_ipv6_iterator_shortcuts() {
    let huge = IpRange::<IPv6>::from_bounds(0, usize::MAX as u128 + 5).unwrap();
    assert_eq!(Iterator::size_hint(&huge.clone()), (usize::MAX, None));
    assert_eq!(huge.clone().count(), usize::MAX);

    let mut strings = huge.clone();
    assert_eq!(strings.nth(5).as_deref(), Some("::5"));

    let addrs = huge.addrs();
    assert_eq!(addrs.size_hint(), (usize::MAX, None));
    assert_eq!(addrs.count(), usize::MAX);

    let full_count = AddrIterator::<IPv6> {
        next: Some(0),
        end: u128::MAX,
        _marker: PhantomData,
    };
    assert_eq!(full_count.count(), usize::MAX);

    let mut full_iter = AddrIterator::<IPv6> {
        next: Some(0),
        end: u128::MAX,
        _marker: PhantomData,
    };
    assert_eq!(full_iter.size_hint(), (usize::MAX, None));
    assert_eq!(full_iter.nth(7), Some(7));
    assert_eq!(full_iter.next(), Some(8));

    let mut full_v4_iter = AddrIterator::<IPv4> {
        next: Some(0),
        end: u32::MAX,
        _marker: PhantomData,
    };
    assert_eq!(full_v4_iter.nth(u32::MAX as usize), Some(u32::MAX));
    assert_eq!(full_v4_iter.next(), None);

    #[cfg(target_pointer_width = "64")]
    {
        let full_v4_len = u32::MAX as usize + 1;
        let full_v4_count = AddrIterator::<IPv4> {
            next: Some(0),
            end: u32::MAX,
            _marker: PhantomData,
        };
        assert_eq!(full_v4_count.size_hint(), (full_v4_len, Some(full_v4_len)));
        assert_eq!(full_v4_count.count(), full_v4_len);

        let mut full_v4_out_of_range = AddrIterator::<IPv4> {
            next: Some(0),
            end: u32::MAX,
            _marker: PhantomData,
        };
        assert_eq!(full_v4_out_of_range.nth(full_v4_len), None);
        assert_eq!(full_v4_out_of_range.next(), None);
    }
}

#[test]
fn test_exhausted_iterator_shortcuts() {
    let mut range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.1").unwrap();
    assert_eq!(range.next().as_deref(), Some("10.0.0.1"));
    assert_eq!(range.last(), None);

    let mut range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.1").unwrap();
    assert_eq!(range.next().as_deref(), Some("10.0.0.1"));
    assert_eq!(range.next(), None);

    let mut addrs = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.1")
        .unwrap()
        .addrs();
    assert_eq!(addrs.next(), Some(ipv4::ip2long("10.0.0.1").unwrap()));
    assert_eq!(addrs.size_hint(), (0, Some(0)));
    assert_eq!(addrs.count(), 0);
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
    let mut a = IpRange::<IPv4>::new("127.0.0.0/31", "").unwrap();
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
    let mut a = IpRange::<IPv4>::new("127.0.0.0/31", "").unwrap();
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
    assert!(!IpRange::<IPv4>::is_reserved("2001:db8::1").unwrap());

    assert_eq!(IpRange::<IPv4>::is_reserved("123456").ok(), None);
    assert_eq!(IpRange::<IPv6>::is_reserved("123456").ok(), None);
}

#[test]
fn test_hash_uses_bounds() {
    let first = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.3").unwrap();
    let same = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.3").unwrap();
    let different = IpRange::<IPv4>::new("10.0.0.2", "10.0.0.3").unwrap();

    assert_eq!(hash_range(&first), hash_range(&same));
    assert_ne!(hash_range(&first), hash_range(&different));
}

#[test]
fn test_range_family_trait_methods() {
    assert!(<IPv4 as RangeFamily>::validate_ip("127.0.0.1"));
    assert!(<IPv4 as RangeFamily>::validate_cidr("127.0.0.1/32"));
    assert_eq!(<IPv4 as RangeFamily>::invalid_ip_error(), Error::V4IP());
    assert_eq!(
        <IPv4 as RangeFamily>::invalid_range_error(),
        Error::V4Subnet()
    );
    assert_eq!(<IPv4 as RangeFamily>::wrapping_add_usize(1, 2), 3);

    assert!(<IPv6 as RangeFamily>::validate_ip("::1"));
    assert!(<IPv6 as RangeFamily>::validate_cidr("::1/128"));
    assert_eq!(<IPv6 as RangeFamily>::invalid_ip_error(), Error::V6IP());
    assert_eq!(
        <IPv6 as RangeFamily>::invalid_range_error(),
        Error::V6Subnet()
    );
    assert_eq!(<IPv6 as RangeFamily>::wrapping_add_usize(1, 2), 3);
}

#[test]
fn test_constructor() {
    assert!(IpRange::<IPv4>::new("Bolognese", "").is_err());
    assert!(IpRange::<IPv6>::new("Bolognese", "").is_err());
    assert!(IpRange::<IPv6>::new("127.0.0.1", "").is_err());
    assert!(IpRange::<IPv6>::new("127.0.0.1/32", "").is_err());
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

fn hash_range<T: RangeFamily>(range: &IpRange<T>) -> u64 {
    let mut hasher = DefaultHasher::new();
    range.hash(&mut hasher);
    hasher.finish()
}
