use super::*;
use pretty_assertions::assert_eq;

#[test]
fn test_bin() {
    assert_eq!(bin_u32(100u32), "0b1100100");
}

#[test]
fn test_validate_ip() {
    assert_eq!(validate_ip("127.0.0.1"), true);
    assert_eq!(validate_ip("127.0"), true);
    assert_eq!(validate_ip("127.0.0.256"), false);
}

#[test]
fn test_validate_cidr() {
    assert_eq!(validate_cidr("127.0.0.1/32"), true);
    assert_eq!(validate_cidr("127.0/8"), true);
    assert_eq!(validate_cidr("127.0.0.256/32"), false);
    assert_eq!(validate_cidr("127.0.0.0"), false);
    assert_eq!(validate_cidr(LOOPBACK), true);
    assert_eq!(validate_cidr("127.0.0.1/33"), false);
    assert_eq!(validate_cidr(""), false);
    assert_eq!(validate_cidr("127.0.0.1/"), false);
    assert_eq!(validate_cidr("127.0.0.1/a"), false);
    assert_eq!(validate_cidr("127.0.0.1/32/32"), false);
    assert_eq!(validate_cidr(" 127.0.0.1/32"), false);
}

#[test]
fn test_ip2network() {
    assert_eq!(ip2network("127.1").unwrap(), 2130771968);
    assert_eq!(
        ip2network("127.1").unwrap(),
        ip2network("127.1.0.0").unwrap()
    );
    assert_eq!(ip2network("255.255.255.255").unwrap(), 4294967295);
    assert_eq!(ip2network("ravioli"), None);
}

#[test]
fn test_ip2long() {
    assert_eq!(ip2long("127.0.0.1"), Ok(2130706433));
    assert_eq!(ip2long("127.1"), Ok(2130706433));
    assert_eq!(ip2long("127"), Ok(2130706432));
    assert!(ip2long("127.0.0.256").is_err());
}

#[test]
fn test_long2ip() {
    assert_eq!(long2ip(2130706433), "127.0.0.1");
    assert_eq!(long2ip(MAX_IP), "255.255.255.255");
    assert_eq!(long2ip(MIN_IP), "0.0.0.0");
}

#[test]
fn test_ip2hex() {
    assert_eq!(ip2hex("0.0.0.1"), Ok("00000001".to_string()));
    assert_eq!(ip2hex("127.0.0.1"), Ok("7f000001".to_string()));
    assert_eq!(ip2hex("127.255.255.255"), Ok("7fffffff".to_string()));
    assert_eq!(ip2hex("128.0.0.1"), Ok("80000001".to_string()));
    assert_eq!(ip2hex("128.1"), Ok("80000001".to_string()));
    assert_eq!(ip2hex("255.255.255.255"), Ok("ffffffff".to_string()));
}

#[test]
fn test_hex2ip() {
    assert_eq!(hex2ip("00000001"), Ok("0.0.0.1".to_string()));
    assert_eq!(hex2ip("7f000001"), Ok("127.0.0.1".to_string()));
    assert_eq!(hex2ip("7fffffff"), Ok("127.255.255.255".to_string()));
    assert_eq!(hex2ip("80000001"), Ok("128.0.0.1".to_string()));
    assert_eq!(hex2ip("ffffffff"), Ok("255.255.255.255".to_string()));
}

#[test]
fn test_cidr2block() {
    assert_eq!(
        cidr2block("127.0.0.1/32"),
        Ok(("127.0.0.1".to_string(), "127.0.0.1".to_string()))
    );
    assert_eq!(
        cidr2block("127/8"),
        Ok(("127.0.0.0".to_string(), "127.255.255.255".to_string()))
    );
    assert_eq!(
        cidr2block("127.0.1/16"),
        Ok(("127.0.0.0".to_string(), "127.0.255.255".to_string()))
    );
    assert_eq!(
        cidr2block("127.1/24"),
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
}

#[test]
fn test_subnet2block() {
    assert_eq!(
        subnet2block("127.0.0.1/255.255.255.255"),
        Some(("127.0.0.1".to_string(), "127.0.0.1".to_string()))
    );
    assert_eq!(
        subnet2block("127/255"),
        Some(("127.0.0.0".to_string(), "127.255.255.255".to_string()))
    );
    assert_eq!(
        subnet2block("127.0.1/255.255"),
        Some(("127.0.0.0".to_string(), "127.0.255.255".to_string()))
    );
    assert_eq!(
        subnet2block("127.1/255.255.255.0"),
        Some(("127.1.0.0".to_string(), "127.1.0.255".to_string()))
    );
    assert_eq!(
        subnet2block("127.0.0.3/255.255.255.248"),
        Some(("127.0.0.0".to_string(), "127.0.0.7".to_string()))
    );
    assert_eq!(
        subnet2block("127/0"),
        Some(("0.0.0.0".to_string(), "255.255.255.255".to_string()))
    );
    assert_eq!(subnet2block("bad"), None);
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
    assert!(validate_subnet("127.0/255.0.0.0"));
    assert!(validate_subnet("127.0/255"));
    assert!(!validate_subnet("127.0.0.256/255.255.255.255"));
    assert!(!validate_subnet("127.0.0.1/255.255.255.256"));
    assert!(!validate_subnet("127.0.0.0"));
    assert!(!validate_subnet("127.0.0.1/255.255.255.255/127.0.0.2"));
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
