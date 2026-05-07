use super::*;
use pretty_assertions::assert_eq;

#[test]
fn test_validate_ip() {
    for good in [
        "::",
        "::1",
        "2001:db8:85a3::8a2e:370:7334",
        "2001:db8:85a3:0:0:8a2e:370:7334",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1:0:0:1",
        "2001:db8::192.168.0.1",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "::ffff:192.0.2.128",
        "::ffff:0.0.0.0",
        "::ffff:255.255.255.255",
        "1080:0:0:0:8:800:200c:417a",
    ] {
        assert!(validate_ip(good), "{good} rejected unexpectedly");
    }
    for bad in [
        "::ff::ff",
        "::fffff",
        "::ffff:192.0.2.300",
        "::ffff:1.2.3",
        "::ffff:01.2.3.4",
        "::01.2.3.4",
        "::1.2.3",
        ":",
        "1:::1",
        ":1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:8:",
        "1:2:3::4:5:6:7:8",
        "127.0.0.1",
    ] {
        assert!(!validate_ip(bad), "{bad} accepted unexpectedly");
    }
}

#[test]
fn test_ip2long() {
    assert_eq!(ip2long("::"), Ok(0));
    assert_eq!(ip2long("::1"), Ok(1));
    assert_eq!(
        ip2long("2001:db8:85a3::8a2e:370:7334"),
        Ok(0x20010db885a3000000008a2e03707334)
    );
    assert_eq!(
        ip2long("2001:db8::1:0:0:1"),
        Ok(0x20010db8000000000001000000000001)
    );
    assert_eq!(ip2long("::ffff:192.0.2.128"), Ok(281473902969472));
    assert_eq!(
        ip2long("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        Ok(0xffffffffffffffffffffffffffffffff)
    );
    assert!(ip2long("127.0.0.1").is_err());
    assert!(ip2long("ff::ff::ff").is_err());
    assert!(ip2long("fe80::1%eth0").is_err());
    assert!(ip2long(":192.168.0.1").is_err());
    assert!(ip2long("1:2:3:4:5:6:7").is_err());
    assert!(ip2long("1:2:3:4:5:6:7:8:9").is_err());
    assert!(ip2long("1::2::3").is_err());
    assert!(ip2long("1::2:3:4:5:6:7:8").is_err());
    assert!(ip2long("1::2:3:4:5:6:7:8:9").is_err());
    assert!(ip2long("1::2:3:4:5:6:7:").is_err());
    assert!(ip2long("::ffff:1.2.3.4.5").is_err());
    assert!(ip2long("::ffff:1.2.3.a").is_err());
    assert!(ip2long("::ffff:1.2.3.").is_err());
}

#[test]
fn test_long2ip() {
    assert_eq!(long2ip(2130706433, false), "::7f00:1");
    assert_eq!(
        long2ip(42540766411282592856904266426630537217, false),
        "2001:db8::1:0:0:1"
    );
    assert_eq!(long2ip(MIN_IP, false), "::");
    assert_eq!(
        long2ip(MAX_IP, false),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    );
    assert_eq!(
        long2ip(ip2long("1080::8:800:200C:417A").unwrap(), true),
        "4)+k&C#VzJ4br>0wv%Yp"
    );
    assert_eq!(
        fmt_long2ip_to_string(ip2long("2001:db8::1").unwrap()),
        "2001:db8::1"
    );
}

#[test]
fn test_rfc1924_reverse_table_runtime() {
    let table = build_rfc1924_rev_table();
    assert_eq!(table[b'0' as usize], 0);
    assert_eq!(table[b'A' as usize], 10);
    assert_eq!(table[b'z' as usize], 61);
    assert_eq!(table[b'/' as usize], -1);
}

#[test]
fn test_rfc19242long() {
    assert_eq!(rfc19242long("00000000000000000000"), Some(0));
    assert_eq!(
        rfc19242long("4)+k&C#VzJ4br>0wv%Yp"),
        Some(21932261930451111902915077091070067066)
    );
    assert_eq!(rfc19242long("pizza"), None);
    assert_eq!(rfc19242long("=r54lj&NUUO~Hi%c2ym0"), Some(MAX_IP));
    assert_eq!(
        rfc19242long("4)+k&C#VzJ4br>0wv%Yp"),
        Some(ip2long("1080::8:800:200C:417A").unwrap())
    );
    assert_eq!(
        rfc19242long("00000000000000000000"),
        Some(ip2long("::").unwrap())
    );
    assert_eq!(
        rfc19242long("=r54lj&NUUO~Hi%c2ym0"),
        Some(ip2long("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap())
    );

    // Overflow and invalid chars are rejected
    assert!(rfc19242long("~~~~~~~~~~~~~~~~~~~~").is_none());
    assert!(rfc19242long("0000000000000000000\u{80}").is_none());
    assert!(rfc19242long("000000000000000000é").is_none());
}

#[test]
fn test_rfc1924_roundtrip_sampled() {
    let cases: &[u128] = &[
        0,
        1,
        85,
        256,
        42_424,
        1_234_567_890,
        0x20010db8000000000000000000001234,
        MAX_IP,
    ];

    for &value in cases {
        let encoded = long2rfc1924(value);
        let decoded = rfc19242long(&encoded);
        assert_eq!(
            decoded,
            Some(value),
            "roundtrip failed for {value} -> {encoded}"
        );
        assert_eq!(encoded.len(), 20, "encoding length changed for {value}");
    }

    // Invalid length and charset coverage
    assert!(rfc19242long("short").is_none());
    assert!(rfc19242long("!!!!!!!!!!!!!!!!!!!!!").is_none()); // 21 chars
    assert!(rfc19242long("0000000000000000000/").is_none()); // bad character
}

#[test]
fn test_long2rfc1924() {
    assert_eq!(
        long2rfc1924(ip2long("1080::8:800:200C:417A").unwrap()),
        "4)+k&C#VzJ4br>0wv%Yp"
    );
    assert_eq!(long2rfc1924(ip2long("::").unwrap()), "00000000000000000000");
    assert_eq!(
        long2rfc1924(ip2long("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()),
        "=r54lj&NUUO~Hi%c2ym0"
    );
}

#[test]
fn test_validate_cidr() {
    for cidr in [
        "::/128",
        "::/0",
        "8000::/1",
        "2001:db8::/127",
        DOCUMENTATION_NETWORK,
        "fc00::/7",
        "::ffff:0:0/96",
    ] {
        assert!(validate_cidr(cidr), "{cidr} not accepted");
    }
    assert!(!validate_cidr("::"));
    #[cfg(feature = "std")]
    assert!(!validate_cidr_re("::"));
    assert!(!validate_cidr("::/129"));
    assert!(!validate_cidr("127.0.0.1/32"));
    assert!(validate_cidr("::/00")); // leading zeros are tolerated but mean the same value
    assert!(validate_cidr("::/001"));
    assert!(validate_cidr("f::ddb:a/0089"));
    assert!(!validate_cidr("D5B:4E4::/+6"));
    #[cfg(feature = "std")]
    {
        assert!(validate_cidr_re("f::ddb:a/0089"));
        assert!(!validate_cidr_re("D5B:4E4::/+6"));
    }
    assert!(!validate_cidr("::/-1"));
    assert!(!validate_cidr(""));
    assert!(!validate_cidr("::/"));
    assert!(!validate_cidr("::/a"));
    assert!(!validate_cidr("::ffff:1.2.3/96"));
    assert!(!validate_cidr("::ffff:01.2.3.4/96"));
    assert!(!validate_cidr("fe80::1%eth0/64"));
    assert!(!validate_cidr("::/128/128"));
    #[cfg(feature = "std")]
    assert!(!validate_cidr_re("::/128/128"));
    assert!(!validate_cidr(" ::/128"));
}

#[test]
fn test_cidr2block() {
    assert_eq!(
        cidr2block("2001:db8::/48"),
        Ok((
            "2001:db8::".to_string(),
            "2001:db8:0:ffff:ffff:ffff:ffff:ffff".to_string()
        ))
    );
    assert_eq!(
        cidr2block("::/0"),
        Ok((
            "::".to_string(),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string()
        ))
    );
    assert_eq!(
        cidr2block("f::ddb:a/0089"),
        Ok(("f::".to_string(), "f::7f:ffff:ffff".to_string()))
    );
    assert!(cidr2block("D5B:4E4::/+6").is_err());
}

#[test]
fn test_numeric_cidr_bounds() {
    assert_eq!(cidr_bounds("::/128"), Ok((0, 0)));
    assert_eq!(cidr_bounds("::/0"), Ok((0, u128::MAX)));
    assert_eq!(
        cidr_bounds("2001:db8::1234/126"),
        Ok((
            ip2long("2001:db8::1234").unwrap(),
            ip2long("2001:db8::1237").unwrap()
        ))
    );
    assert_eq!(
        block_bounds(ip2long("2001:db8::1234").unwrap(), 32),
        Ok((
            ip2long("2001:db8::").unwrap(),
            ip2long("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff").unwrap()
        ))
    );
    assert!(cidr_bounds("::").is_err());
    assert!(cidr_bounds("::/128/128").is_err());
    assert!(cidr_bounds("::/129").is_err());
    assert!(block_bounds(0, 129).is_err());
}

#[test]
fn test_ipv6_boundary_roundtrip() {
    for ip in ["::", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"] {
        let long = ip2long(ip).unwrap();
        assert_eq!(long2ip(long, false), ip);
    }
}

#[test]
fn test_ipv6_invalid_formats_and_cross_family() {
    for bad in [
        ":::1",
        "2001:db8::1::",
        " ::1",
        "2001:db8::g",
        "2001:db8::192.168.0.256",
        "fe80::1%eth0",
        "::1:2:3:4:5:6:",
        ":1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:8:",
        "1:2:3::4:5:6:7:8",
    ] {
        assert!(
            !validate_ip(bad),
            "unexpectedly accepted malformed IPv6 input {bad}"
        );
    }
    assert!(!validate_cidr("2001:db8::/129"));
}

#[test]
#[cfg(feature = "std")]
fn test_ipv6_rfc_case_insensitive_forms() {
    assert!(validate_ip("::FFFF:192.0.2.128"));
    assert!(validate_ip_re("::FFFF:192.0.2.128"));
    assert!(validate_cidr("::FFFF:0:0/96"));
    assert!(validate_cidr_re("::FFFF:0:0/96"));
    assert!(validate_cidr("::ffff:192.0.2.128/96"));
    assert!(validate_cidr_re("::FFFF:192.0.2.128/96"));
}

#[test]
#[cfg(feature = "std")]
fn test_ipv6_regex_and_optimized_parity_for_mixed_tail_edge_cases() {
    for ip in [
        "::ffff:1.2.3",
        "::ffff:01.2.3.4",
        "::01.2.3.4",
        "::1.2.3",
        ":::1",
        "1:::1",
        "1:2:3:4:5:6:7:",
        ":1:2:3:4:5:6:7",
    ] {
        assert_eq!(
            validate_ip_re(ip),
            validate_ip(ip),
            "regex/optimized mismatch for {ip}"
        );
    }

    for cidr in [
        "::ffff:1.2.3/96",
        "::ffff:01.2.3.4/96",
        "::FFFF:192.0.2.128/96",
        "f::ddb:a/0089",
        "::/00",
        "::/128/128",
    ] {
        assert_eq!(
            validate_cidr_re(cidr),
            validate_cidr(cidr),
            "regex/optimized CIDR mismatch for {cidr}"
        );
    }
}

#[test]
fn test_ipv6_cidr_extremes() {
    assert_eq!(
        cidr2block("::/128"),
        Ok(("::".to_string(), "::".to_string()))
    );
    assert_eq!(
        cidr2block("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
        Ok((
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string(),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string()
        ))
    );
    assert_eq!(
        cidr2block("8000::/1"),
        Ok((
            "8000::".to_string(),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string()
        ))
    );
    assert_eq!(
        cidr2block("2001:db8::/127"),
        Ok(("2001:db8::".to_string(), "2001:db8::1".to_string()))
    );
}

fn fmt_long2ip_to_string(ip: u128) -> String {
    use core::fmt;

    struct Fmt(u128);

    impl fmt::Display for Fmt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            crate::ipv6::fmt_long2ip(f, self.0)
        }
    }

    Fmt(ip).to_string()
}
