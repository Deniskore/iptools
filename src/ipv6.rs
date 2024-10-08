// Copyright (c) 2022 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT

use ahash::AHashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use std::borrow::BorrowMut;

use crate::error::Error;
use crate::error::Result;

static HEX_RE: Lazy<&Regex> = Lazy::new(|| {
    static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
    RE.get_or_init(|| regex::Regex::new(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$").unwrap())
});

static DOTTED_QUAD_RE: Lazy<&Regex> = Lazy::new(|| {
    static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
    RE.get_or_init(|| regex::Regex::new(r"^([0-9a-f]{0,4}:){2,6}(\d{1,3}\.){0,3}\d{1,3}$").unwrap())
});

static CIDR_RE: Lazy<&Regex> = Lazy::new(|| {
    static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
    RE.get_or_init(|| regex::Regex::new(r"^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}/\d{1,3}$").unwrap())
});

// Regex for validating an IPv6 in hex notation
static RE_RFC1924: Lazy<&Regex> = Lazy::new(|| {
    static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
    RE.get_or_init(|| regex::Regex::new(r"^[0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~]{20}$").unwrap())
});

// RFC 1924 reverse lookup
const _RFC1924_REV: bool = true;

/// Last ip
pub const MAX_IP: u128 = u128::MAX;

/// First ip
pub const MIN_IP: u128 = 0;

/// IETF and IANA reserved ip addresses
pub static RESERVED_RANGES: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        UNSPECIFIED_ADDRESS,
        LOOPBACK,
        IPV4_MAPPED,
        IPV6_TO_IPV4_NETWORK,
        TEREDO_NETWORK,
        PRIVATE_NETWORK,
        LINK_LOCAL,
        MULTICAST,
        MULTICAST_LOOPBACK,
        MULTICAST_LOCAL,
        MULTICAST_SITE,
        MULTICAST_SITE_ORG,
        MULTICAST_GLOBAL,
        MULTICAST_LOCAL_NODES,
        MULTICAST_LOCAL_ROUTERS,
        MULTICAST_LOCAL_DHCP,
        MULTICAST_SITE_DHCP,
    ]
});

/// Absence of an address (only valid as source address)
/// [RFC 4291](https://tools.ietf.org/html/rfc4291)
pub const UNSPECIFIED_ADDRESS: &str = "::/128";

/// Loopback addresses on the local host
/// [RFC 4291](https://tools.ietf.org/html/rfc4291>)
pub const LOOPBACK: &str = "::1/128";

/// Common `localhost` address
/// [RFC 4291](https://tools.ietf.org/html/rfc4291)
pub const LOCALHOST: &str = LOOPBACK;

/// IPv4 mapped to IPv6 (not globally routable)
/// [RFC 4291](https://tools.ietf.org/html/rfc4291)
pub const IPV4_MAPPED: &str = "::ffff:0:0/96";

/// Documentation and example network
/// [RFC 3849](https://tools.ietf.org/html/rfc3849)
pub const DOCUMENTATION_NETWORK: &str = "2001::db8::/32";

/// 6to4 Address block
/// [RFC 3056](https://tools.ietf.org/html/rfc3056)
pub const IPV6_TO_IPV4_NETWORK: &str = "2002::/16";

/// Teredo addresses
/// [RFC 4380](https://tools.ietf.org/html/rfc4380)
pub const TEREDO_NETWORK: &str = "2001::/32";

/// Private network
/// [RFC 4193](https://tools.ietf.org/html/rfc4193)
pub const PRIVATE_NETWORK: &str = "fd00::/8";

/// Link-Local unicast networks (not globally routable)
/// [RFC 4291](https://tools.ietf.org/html/rfc4291)
pub const LINK_LOCAL: &str = "fe80::/10";

/// Multicast reserved block
/// [RFC 5771](https://tools.ietf.org/html/rfc5771)
pub const MULTICAST: &str = "ff00::/8";

/// Interface-Local multicast
pub const MULTICAST_LOOPBACK: &str = "ff01::/16";

/// Link-Local multicast
pub const MULTICAST_LOCAL: &str = "ff02::/16";

/// Site-Local multicast
pub const MULTICAST_SITE: &str = "ff05::/16";

/// Organization-Local multicast
pub const MULTICAST_SITE_ORG: &str = "ff08::/16";

/// Organization-Local multicast
pub const MULTICAST_GLOBAL: &str = "ff0e::/16";

/// All nodes on the local segment
pub const MULTICAST_LOCAL_NODES: &str = "ff02::1";

/// All routers on the local segment
pub const MULTICAST_LOCAL_ROUTERS: &str = "ff02::2";

/// All DHCP servers and relay agents on the local segment
pub const MULTICAST_LOCAL_DHCP: &str = "ff02::1:2";

/// All DHCP servers and relay agents on the local site
pub const MULTICAST_SITE_DHCP: &str = "ff05::1:3";

// RFC 1924 alphabet
const _RFC1924_ALPHABET: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z', '!', '#', '$', '%', '&', '(', ')', '*', '+', '-', ';', '<', '=', '>',
    '?', '@', '^', '_', '`', '{', '|', '}', '~',
];

static RFC1924_REV_MAP: Lazy<AHashMap<char, i32>> = Lazy::new(|| {
    let mut i = -1;
    _RFC1924_ALPHABET
        .iter()
        .map(|c| {
            i += 1;
            (*c, i)
        })
        .collect::<AHashMap<_, _>>()
});

/// Validate a hexidecimal IPV6 ip address
///
/// # Example
///
/// ```
/// use iptools::ipv6::validate_ip;
/// assert_eq!(validate_ip("::ffff:192.0.2.300"), false);
/// assert_eq!(validate_ip("1080:0:0:0:8:800:200c:417a"), true);
/// ```
pub fn validate_ip(ip: &str) -> bool {
    let is_hex = HEX_RE.is_match(ip);
    let is_dotted_quad = DOTTED_QUAD_RE.is_match(ip);
    if is_hex {
        ip.split("::").count() <= 2
    } else if is_dotted_quad {
        if ip.split("::").count() > 2 {
            return false;
        }
        let quads: Vec<&str> = ip
            .split(':')
            .last()
            .map_or(vec![], |last| last.split('.').collect());
        quads
            .iter()
            .all(|q| q.parse::<i32>().ok().map_or(false, |q| q <= 255))
    } else {
        false
    }
}

/// Convert a hexidecimal IPV6 address to a network byte order 128 bit integer
///
/// # Example
///
/// ```
/// use iptools::ipv6::ip2long;
/// assert_eq!(ip2long("::"), Ok(0));
/// assert_eq!(ip2long("::1"), Ok(1));
/// assert_eq!(ip2long("2001:db8:85a3::8a2e:370:7334"),Ok(0x20010db885a3000000008a2e03707334));
/// ```
pub fn ip2long(ip: &str) -> Result<u128> {
    let mut ip = ip.to_string();
    if !validate_ip(&ip) {
        return Err(Error::V6IP());
    }

    if ip.contains('.') {
        let mut chunks: Vec<&str> = ip.split(':').collect();
        let v4_int = crate::ipv4::ip2long(chunks.pop().ok_or(Error::V6IPConvert())?)?;
        let lower = format!("{:x}", ((v4_int >> 16) & 0xffff));
        let upper = format!("{:x}", (v4_int & 0xffff));
        chunks.push(&lower);
        chunks.push(&upper);
        ip = chunks.join(":");
    }

    let halves: Vec<&str> = ip.split("::").collect();
    let mut hextets: Vec<&str> = halves[0].split(':').collect();
    let h2 = if halves.len() == 2 {
        halves[1].split(':').collect()
    } else {
        Vec::new()
    };
    for _z in 0..8 - (hextets.len() + h2.len()) {
        hextets.push("0");
    }
    for h in h2 {
        hextets.push(h);
    }
    let mut long_ip = 0u128;
    let mut tmp = "0";
    for mut h in hextets.iter_mut() {
        if h.is_empty() {
            h = tmp.borrow_mut();
        }
        long_ip =
            (long_ip << 16) | u128::from_str_radix(h, 16).map_err(|_| Error::V6IPConvert())?;
    }
    Ok(long_ip)
}

/// Convert a network byte order 128 bit integer to a canonical IPV6 address
///
/// # Example
///
/// ```
/// use iptools::ipv6::long2ip;
/// assert_eq!(long2ip(2130706433, false), "::7f00:1".to_string());
/// assert_eq!(long2ip(42540766411282592856904266426630537217, false),"2001:db8::1:0:0:1".to_string());
/// ```
pub fn long2ip(long_ip: u128, rfc1924: bool) -> String {
    // TODO Optimize this function
    if rfc1924 {
        return long2rfc1924(long_ip);
    }

    let hex_str = format!("{:0>32x}", long_ip);
    let mut hextets = hex_str
        .as_bytes()
        .chunks(4)
        .map(|chunk| u32::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .map(|item| format!("{:x}", item))
        .collect::<Vec<String>>();

    let (mut dc_start, mut dc_len): (i32, i32) = (-1, 0);
    let (mut run_start, mut run_len): (i32, i32) = (-1, 0);

    for (idx, hextet) in hextets.iter().enumerate() {
        if "0" == hextet {
            run_len += 1;
            if -1 == run_start {
                run_start = idx as i32;
            }

            if run_len > dc_len {
                dc_len = run_len;
                dc_start = run_start;
            }
        } else {
            run_len = 0;
            run_start = -1;
        }
    }

    if dc_len > 1 {
        let dc_end = dc_start + dc_len;
        if dc_end == hextets.len() as i32 {
            hextets.push("".to_string());
        }

        hextets.drain(dc_start as usize..dc_end as usize);
        if dc_start > 0 {
            hextets.insert(dc_start as usize, "".to_string());
        } else {
            hextets.insert(0, "".to_string());
        }

        if dc_start == 0 {
            hextets.insert(0, "".to_string());
        }
    }
    hextets.join(":")
}

/// Convert a network byte order 128 bit integer to an rfc1924 IPV6 address
///
/// # Example
///
/// ```
/// use iptools::ipv6::long2rfc1924;
/// use iptools::ipv6::ip2long;
/// assert_eq!(long2rfc1924(ip2long("1080::8:800:200C:417A").unwrap()),"4)+k&C#VzJ4br>0wv%Yp");
/// assert_eq!(long2rfc1924(ip2long("::").unwrap()), "00000000000000000000");
/// ```
pub fn long2rfc1924(long_ip: u128) -> String {
    let mut o = vec![];
    let mut r = long_ip;
    while r > 85 {
        o.push(_RFC1924_ALPHABET[(r % 85) as usize]);
        r /= 85;
    }
    o.push(_RFC1924_ALPHABET[r as usize]);
    o.reverse();
    format!("{:0>20}", o.into_iter().collect::<String>())
}

/// Convert an RFC1924 IPV6 address to a network byte order 128 bit integer
///
/// # Example
///
/// ```
/// use iptools::ipv6::rfc19242long;
/// assert_eq!(rfc19242long("00000000000000000000"), Some(0));
/// assert_eq!(rfc19242long("4)+k&C#VzJ4br>0wv%Yp"),Some(21932261930451111902915077091070067066));
/// assert_eq!(rfc19242long("pizza"), None);
/// ```
pub fn rfc19242long(s: &str) -> Option<u128> {
    if !RE_RFC1924.is_match(s) {
        return None;
    }
    let mut x = 0u128;
    for c in s.chars() {
        if let Some(mul_result) = x.checked_mul(85) {
            x = mul_result + RFC1924_REV_MAP[&c] as u128;
        } else {
            return None;
        }
    }
    Some(x)
}

/// Validate a CIDR notation ip address
///
/// # Example
///
/// ```
/// use iptools::ipv6::validate_cidr;
/// assert_eq!(validate_cidr("fc00::/7"), true);
/// assert_eq!(validate_cidr("::ffff:0:0/96"), true);
/// assert_eq!(validate_cidr("::"), false);
/// assert_eq!(validate_cidr("::/129"), false);
/// ```
pub fn validate_cidr(cidr: &str) -> bool {
    if !CIDR_RE.is_match(cidr) {
        return false;
    }
    let ip_mask: Vec<&str> = cidr.split('/').collect();
    if !validate_ip(ip_mask[0])
        || ip_mask[1]
            .parse::<u128>()
            .map_or(true, |parsed_mask| parsed_mask > 128)
    {
        return false;
    }
    true
}

/// Convert a CIDR notation ip address into a tuple containing the network block start and end addresses
///
/// # Example
///
/// ```
/// use iptools::ipv6::cidr2block;
/// assert_eq!(cidr2block("2001:db8::/48"),
///           Ok(("2001:db8::".to_string(), "2001:db8:0:ffff:ffff:ffff:ffff:ffff".to_string())));
/// assert_eq!(cidr2block("::/0"),
///           Ok(("::".to_string(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string())));
/// ```
pub fn cidr2block(cidr: &str) -> Result<(String, String)> {
    if !validate_cidr(cidr) {
        return Err(Error::V6CIDR());
    }

    let ip_prefix: Vec<&str> = cidr.split('/').collect();
    let prefix = ip_prefix[1].parse::<u128>().map_err(|_| Error::V6CIDR())?;
    let ip = ip2long(ip_prefix[0])?;
    let shift: u32 = 128 - prefix as u32;
    let block_start: u128 = ip
        .checked_shr(shift)
        .unwrap_or(0)
        .checked_shl(shift)
        .unwrap_or(0);

    let mut mask = u128::MAX;
    if let Some(shift) = 1u128.checked_shl(shift) {
        if let Some(sub) = shift.checked_sub(1) {
            mask = sub;
        }
    }
    let block_end = block_start | mask;
    Ok((long2ip(block_start, false), long2ip(block_end, false)))
}

#[cfg(test)]
mod tests {
    use crate::ipv6::{
        cidr2block, ip2long, long2ip, long2rfc1924, rfc19242long, validate_cidr, validate_ip,
        MAX_IP, MIN_IP,
    };

    use pretty_assertions::assert_eq;

    #[test]
    fn test_validate_ip() {
        assert_eq!(validate_ip("::"), true);
        assert_eq!(validate_ip("::1"), true);
        assert_eq!(validate_ip("2001:db8:85a3::8a2e:370:7334"), true);
        assert_eq!(validate_ip("2001:db8:85a3:0:0:8a2e:370:7334"), true);
        assert_eq!(validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), true);
        assert_eq!(validate_ip("2001:db8::1:0:0:1"), true);
        assert_eq!(validate_ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), true);
        assert_eq!(validate_ip("::ffff:192.0.2.128"), true);
        assert_eq!(validate_ip("::ff::ff"), false);
        assert_eq!(validate_ip("::fffff"), false);
        assert_eq!(validate_ip("::ffff:192.0.2.300"), false);
        assert_eq!(validate_ip("1080:0:0:0:8:800:200c:417a"), true);
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
            ip2long("2001:db8:85a3:0:0:8a2e:370:7334"),
            Ok(0x20010db885a3000000008a2e03707334)
        );
        assert_eq!(
            ip2long("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
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
        assert_eq!(ip2long("ff::ff::ff").is_err(), true);
        assert_eq!(
            ip2long("1080:0:0:0:8:800:200C:417A"),
            Ok(21932261930451111902915077091070067066)
        );
    }

    #[test]
    fn test_long2ip() {
        assert_eq!(long2ip(2130706433, false), "::7f00:1".to_string());
        assert_eq!(
            long2ip(42540766411282592856904266426630537217, false),
            "2001:db8::1:0:0:1".to_string()
        );
        assert_eq!(long2ip(MIN_IP, false), "::".to_string());
        assert_eq!(
            long2ip(MAX_IP, false),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string()
        );
        assert_eq!(
            long2ip(ip2long("1080::8:800:200C:417A").unwrap(), true),
            "4)+k&C#VzJ4br>0wv%Yp".to_string()
        );
        assert_eq!(
            long2ip(ip2long("::").unwrap(), true),
            "00000000000000000000".to_string()
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
        assert_eq!(rfc19242long("~~~~~~~~~~~~~~~~~~~~"), None);
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
        assert_eq!(validate_cidr("::/128"), true);
        assert_eq!(validate_cidr("::/0"), true);
        assert_eq!(validate_cidr("fc00::/7"), true);
        assert_eq!(validate_cidr("::ffff:0:0/96"), true);
        assert_eq!(validate_cidr("::"), false);
        assert_eq!(validate_cidr("::/129"), false);
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
}
