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
        "1080:0:0:0:8:800:200c:417a",
    ] {
        assert!(validate_ip(good), "{good} rejected unexpectedly");
    }
    for bad in ["::ff::ff", "::fffff", "::ffff:192.0.2.300"] {
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
    assert!(ip2long("ff::ff::ff").is_err());
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
        "fc00::/7",
        "::ffff:0:0/96",
    ] {
        assert!(validate_cidr(cidr), "{cidr} not accepted");
    }
    assert!(!validate_cidr("::"));
    assert!(!validate_cidr("::/129"));
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
    ] {
        assert!(
            !validate_ip(bad),
            "unexpectedly accepted malformed IPv6 input {bad}"
        );
    }
    assert!(!validate_cidr("2001:db8::/129"));
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
