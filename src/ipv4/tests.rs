use super::*;
use pretty_assertions::assert_eq;

#[test]
fn test_bin() {
    assert_eq!(bin_u32(100u32), "0b1100100");
}

#[test]
fn test_format_tables_runtime() {
    let ascii = build_octet_ascii_table();
    assert_eq!(ascii[0], *b"000");
    assert_eq!(ascii[9], *b"009");
    assert_eq!(ascii[10], *b"010");
    assert_eq!(ascii[100], *b"100");
    assert_eq!(ascii[255], *b"255");

    let lens = build_octet_len_table();
    assert_eq!(lens[0], 1);
    assert_eq!(lens[9], 1);
    assert_eq!(lens[10], 2);
    assert_eq!(lens[99], 2);
    assert_eq!(lens[100], 3);
    assert_eq!(lens[255], 3);
}

#[test]
fn test_validate_ip() {
    assert_eq!(validate_ip("127.0.0.1"), true);
    assert_eq!(validate_ip("0.0.0.0"), true);
    assert_eq!(validate_ip("127.0"), false);
    assert_eq!(validate_ip("01.2.3.4"), false);
    assert_eq!(validate_ip("127.0.0.256"), false);
}

#[test]
fn test_validate_cidr() {
    assert_eq!(validate_cidr("127.0.0.1/32"), true);
    assert_eq!(validate_cidr("127.0/8"), false);
    assert_eq!(validate_cidr("127.0.0.256/32"), false);
    assert_eq!(validate_cidr("127.0.0.0"), false);
    assert_eq!(validate_cidr(LOOPBACK), true);
    assert_eq!(validate_cidr("127.0.0.1/33"), false);
    assert_eq!(validate_cidr("127.0.0.1/030"), true);
    assert_eq!(validate_cidr("127/000"), false);
    assert_eq!(validate_cidr("01.2.3.4/24"), false);
    assert_eq!(validate_cidr(""), false);
    assert_eq!(validate_cidr("127.0.0.1/"), false);
    assert_eq!(validate_cidr("127.0.0.1/a"), false);
    assert_eq!(validate_cidr("127.0.0.1/32/32"), false);
    assert_eq!(validate_cidr(" 127.0.0.1/32"), false);
    #[cfg(feature = "std")]
    {
        assert_eq!(validate_cidr_re("127.0.0.1"), false);
        assert_eq!(validate_cidr_re("127.0.0.1/32/32"), false);
    }
}

#[test]
fn test_ip2network() {
    assert_eq!(ip2network("127").unwrap(), 2130706432);
    assert_eq!(ip2network("127.1").unwrap(), 2130771968);
    assert_eq!(ip2network("127.1.2").unwrap(), 2130772480);
    assert_eq!(
        ip2network("127.1").unwrap(),
        ip2network("127.1.0.0").unwrap()
    );
    assert_eq!(ip2network("255.255.255.255").unwrap(), 4294967295);
    assert_eq!(ip2network("ravioli"), None);
    assert_eq!(ip2network(""), None);
    assert_eq!(ip2network("1.2.3."), None);
    assert_eq!(ip2network("1.2.3.4.5"), None);
    assert_eq!(ip2network("256.1.1.1"), None);
}

#[test]
fn test_ip2long() {
    assert_eq!(ip2long("127.0.0.1"), Ok(2130706433));
    assert!(ip2long("127.1").is_err());
    assert!(ip2long("127").is_err());
    assert!(ip2long("01.2.3.4").is_err());
    assert!(ip2long("127.0.0.256").is_err());
    assert!(ip2long("1.2.3.").is_err());
    assert!(ip2long("1.2.3.4.").is_err());
    assert!(ip2long("1.2.3.4.5").is_err());
    assert!(ip2long("127.0.1").is_err());
}

#[test]
fn test_long2ip() {
    assert_eq!(long2ip(2130706433), "127.0.0.1");
    assert_eq!(long2ip(MAX_IP), "255.255.255.255");
    assert_eq!(long2ip(MIN_IP), "0.0.0.0");
    assert_eq!(fmt_long2ip_to_string(0x6464_6401), "100.100.100.1");
}

#[test]
fn test_ip2hex() {
    assert_eq!(ip2hex("0.0.0.1"), Ok("00000001".to_string()));
    assert_eq!(ip2hex("127.0.0.1"), Ok("7f000001".to_string()));
    assert_eq!(ip2hex("127.255.255.255"), Ok("7fffffff".to_string()));
    assert_eq!(ip2hex("128.0.0.1"), Ok("80000001".to_string()));
    assert!(ip2hex("128.1").is_err());
    assert_eq!(ip2hex("255.255.255.255"), Ok("ffffffff".to_string()));
}

#[test]
fn test_hex2ip() {
    assert_eq!(hex2ip("00000001"), Ok("0.0.0.1".to_string()));
    assert_eq!(hex2ip("0x00000001"), Ok("0.0.0.1".to_string()));
    assert_eq!(hex2ip("7f000001"), Ok("127.0.0.1".to_string()));
    assert_eq!(hex2ip("7fffffff"), Ok("127.255.255.255".to_string()));
    assert_eq!(hex2ip("80000001"), Ok("128.0.0.1".to_string()));
    assert_eq!(hex2ip("ffffffff"), Ok("255.255.255.255".to_string()));
    assert!(hex2ip("").is_err());
    assert!(hex2ip("0x").is_err());
    assert!(hex2ip("zzzzzzzz").is_err());
    assert!(hex2ip("100000000").is_err());
}

#[test]
fn test_cidr2block() {
    assert_eq!(
        cidr2block("127.0.0.1/32"),
        Ok(("127.0.0.1".to_string(), "127.0.0.1".to_string()))
    );
    assert_eq!(
        cidr2block("127.0.0.0/8"),
        Ok(("127.0.0.0".to_string(), "127.255.255.255".to_string()))
    );
    assert_eq!(
        cidr2block("127.0.1.0/16"),
        Ok(("127.0.0.0".to_string(), "127.0.255.255".to_string()))
    );
    assert_eq!(
        cidr2block("127.1.0.0/24"),
        Ok(("127.1.0.0".to_string(), "127.1.0.255".to_string()))
    );
    assert_eq!(
        cidr2block("127.0.0.3/29"),
        Ok(("127.0.0.0".to_string(), "127.0.0.7".to_string()))
    );
    assert_eq!(
        cidr2block("0.0.0.0/32"),
        Ok(("0.0.0.0".to_string(), "0.0.0.0".to_string()))
    );
    assert_eq!(
        cidr2block("255.255.255.255/32"),
        Ok(("255.255.255.255".to_string(), "255.255.255.255".to_string()))
    );
    assert!(
        cidr2block("127.0.0.1/33").is_err(),
        "Invalid prefix should error"
    );
    assert_eq!(
        cidr2block("0.0.0.0/000"),
        Ok(("0.0.0.0".to_string(), "255.255.255.255".to_string()))
    );
    assert!(cidr2block("127/8").is_err());
}

#[test]
fn test_numeric_cidr_bounds() {
    assert_eq!(cidr_bounds("127.0.0.1/32"), Ok((2130706433, 2130706433)));
    assert_eq!(cidr_bounds("127.0.0.3/29"), Ok((2130706432, 2130706439)));
    assert_eq!(cidr_bounds("0.0.0.0/0"), Ok((0, u32::MAX)));
    assert_eq!(
        block_bounds(ip2long("10.0.1.2").unwrap(), 16),
        Ok((
            ip2long("10.0.0.0").unwrap(),
            ip2long("10.0.255.255").unwrap()
        ))
    );
    assert!(cidr_bounds("127.0.0.1").is_err());
    assert!(block_bounds(0, 33).is_err());
}

#[test]
fn test_subnet2block() {
    assert_eq!(
        subnet2block("127.0.0.1/255.255.255.255"),
        Some(("127.0.0.1".to_string(), "127.0.0.1".to_string()))
    );
    assert_eq!(
        subnet2block("127.0.0.0/255.0.0.0"),
        Some(("127.0.0.0".to_string(), "127.255.255.255".to_string()))
    );
    assert_eq!(
        subnet2block("127.0.1.0/255.255.0.0"),
        Some(("127.0.0.0".to_string(), "127.0.255.255".to_string()))
    );
    assert_eq!(
        subnet2block("127.1.0.0/255.255.255.0"),
        Some(("127.1.0.0".to_string(), "127.1.0.255".to_string()))
    );
    assert_eq!(
        subnet2block("127.0.0.3/255.255.255.248"),
        Some(("127.0.0.0".to_string(), "127.0.0.7".to_string()))
    );
    assert_eq!(
        subnet2block("0.0.0.0/0.0.0.0"),
        Some(("0.0.0.0".to_string(), "255.255.255.255".to_string()))
    );
    assert_eq!(subnet2block("127/255"), None);
    assert_eq!(subnet2block("bad"), None);
    assert_eq!(subnet2block("/255.255.255.0"), None);
    assert_eq!(subnet2block("127.0.0.1/"), None);
}

#[test]
fn test_validate_netmask() {
    assert!(validate_netmask("0.0.0.0"));
    assert!(validate_netmask("128.0.0.0"));
    assert!(validate_netmask("255.0.0.0"));
    assert!(validate_netmask("255.255.255.255"));
    assert!(validate_netmask(BROADCAST));
    assert!(!validate_netmask("128.0.0.1"));
    assert!(!validate_netmask("1.255.255.0"));
    assert!(!validate_netmask("0.255.255.0"));
}

#[test]
fn test_netmask2prefix() {
    assert_eq!(netmask2prefix("255.0.0.0"), 8);
    assert_eq!(netmask2prefix("255.128.0.0"), 9);
    assert_eq!(netmask2prefix("255.255.255.254"), 31);
    assert_eq!(netmask2prefix("255.255.255.255"), 32);
    assert_eq!(netmask2prefix("0.0.0.0"), 0);
    assert_eq!(netmask2prefix("127.0.0.1"), 0);
}

#[test]
fn test_validate_subnet() {
    assert!(validate_subnet("127.0.0.1/255.255.255.255"));
    assert!(validate_subnet("127.0.0.0/255.0.0.0"));
    assert!(!validate_subnet("127.0/255.0.0.0"));
    assert!(!validate_subnet("127.0/255"));
    assert!(!validate_subnet("127.0.0.256/255.255.255.255"));
    assert!(!validate_subnet("127.0.0.1/255.255.255.256"));
    assert!(!validate_subnet("127.0.0.0"));
    assert!(!validate_subnet("127.0.0.1/255.255.255.255/127.0.0.2"));
}

#[test]
fn test_bucket_1_prefix_overflow_regression_no_panic() {
    for cidr in [
        "1.2.3.4/292",
        "1.2.3.4/999",
        "1.2.3.4/256",
        "1.2.3.4/2147483648",
    ] {
        assert!(
            !validate_cidr(cidr),
            "validate_cidr unexpectedly accepted {cidr}"
        );
        #[cfg(feature = "std")]
        assert!(
            !validate_cidr_re(cidr),
            "validate_cidr_re unexpectedly accepted {cidr}"
        );
    }
}

#[test]
fn test_bucket_2_rfc_strict_ipv4_text_rules() {
    for ip in ["127", "127.1", "127.0", "01.2.3.4", "1.2.3.04", "001.2.3.4"] {
        assert!(!validate_ip(ip), "validate_ip unexpectedly accepted {ip}");
        assert!(ip2long(ip).is_err(), "ip2long unexpectedly accepted {ip}");
    }

    for cidr in ["127/8", "127.0/8", "01.2.3.4/24"] {
        assert!(
            !validate_cidr(cidr),
            "validate_cidr unexpectedly accepted {cidr}"
        );
        #[cfg(feature = "std")]
        assert!(
            !validate_cidr_re(cidr),
            "validate_cidr_re unexpectedly accepted {cidr}"
        );
    }
}

#[test]
fn test_block_from_ip_and_prefix() {
    assert_eq!(
        _block_from_ip_and_prefix(ip2network("127.0.0.1").unwrap(), 32),
        ("127.0.0.1".to_string(), "127.0.0.1".to_string())
    );
    assert_eq!(
        _block_from_ip_and_prefix(4294967295, 24),
        ("255.255.255.0".to_string(), "255.255.255.255".to_string())
    );
    assert_eq!(
        _block_from_ip_and_prefix(4294967295, 0),
        ("0.0.0.0".to_string(), "255.255.255.255".to_string())
    );
    assert_eq!(
        _block_from_ip_and_prefix(0, 24),
        ("0.0.0.0".to_string(), "0.0.0.255".to_string())
    );
}

fn fmt_long2ip_to_string(ip: u32) -> String {
    use core::fmt;

    struct Fmt(u32);

    impl fmt::Display for Fmt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            crate::ipv4::fmt_long2ip(f, self.0)
        }
    }

    Fmt(ip).to_string()
}
