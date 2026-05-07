// Copyright (c) 2025 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT

use core::fmt;
#[cfg(feature = "std")]
use lazy_regex::regex;

use crate::error::Error;
use crate::error::Result;

#[cfg(feature = "std")]
static IPV4_RE: &lazy_regex::Lazy<lazy_regex::Regex> = regex!(r"^(\d{1,3}\.){3}\d{1,3}$");

/// IETF and IANA reserved ip addresses
pub const RESERVED_RANGES: &[&str] = &[
    CURRENT_NETWORK,
    PRIVATE_NETWORK_10,
    SHARED_ADDRESS_SPACE,
    LOOPBACK,
    LINK_LOCAL,
    PRIVATE_NETWORK_172_16,
    IETF_PROTOCOL_RESERVED,
    DUAL_STACK_LITE,
    TEST_NET_1,
    IPV6_TO_IPV4_RELAY,
    PRIVATE_NETWORK_192_168,
    BENCHMARK_TESTS,
    TEST_NET_2,
    TEST_NET_3,
    MULTICAST,
    RESERVED,
    BROADCAST,
];

#[allow(dead_code)]
/// Last ip
pub const MAX_IP: u32 = u32::MAX;

/// First ip
pub const MIN_IP: u32 = 0;

/// Broadcast messages to the current network (only valid as source address)
/// [RFC 5735](https://tools.ietf.org/html/rfc5735)
pub const CURRENT_NETWORK: &str = "0.0.0.0/8";

/// Private network
/// [RFC 1918](https://tools.ietf.org/html/rfc1918)
pub const PRIVATE_NETWORK_10: &str = "10.0.0.0/8";

/// Carrier-grade NAT private network
/// [RFC 6598](https://tools.ietf.org/html/rfc6598)
pub const SHARED_ADDRESS_SPACE: &str = "100.64.0.0/10";

/// Loopback addresses on the local host
/// [RFC 5735](https://tools.ietf.org/html/rfc5735)
pub const LOOPBACK: &str = "127.0.0.0/8";

/// Common `localhost` address
/// [RFC 5735](https://tools.ietf.org/html/rfc5735)
pub const LOCALHOST: &str = "127.0.0.1";

/// Autoconfiguration when no IP address available
/// [RFC 3927](https://tools.ietf.org/html/rfc3927)
pub const LINK_LOCAL: &str = "169.254.0.0/16";

/// Private network
/// [RFC 1918](https://tools.ietf.org/html/rfc1918)
pub const PRIVATE_NETWORK_172_16: &str = "172.16.0.0/12";

/// IETF protocol assignments reserved block
/// [RFC 5735](https://tools.ietf.org/html/rfc5735)
pub const IETF_PROTOCOL_RESERVED: &str = "192.0.0.0/24";

/// Dual-Stack Lite link address
/// [RFC 6333](https://tools.ietf.org/html/rfc6333)
pub const DUAL_STACK_LITE: &str = "192.0.0.0/29";

/// Documentation and example network
/// [RFC 5737](https://tools.ietf.org/html/rfc5737)
pub const TEST_NET_1: &str = "192.0.2.0/24";

/// 6to4 anycast relay
/// [RFC 3068](https://tools.ietf.org/html/rfc3068)
pub const IPV6_TO_IPV4_RELAY: &str = "192.88.99.0/24";

/// Private network
/// [RFC 1918](https://tools.ietf.org/html/rfc1918)
pub const PRIVATE_NETWORK_192_168: &str = "192.168.0.0/16";

/// Inter-network communications testing
/// [RFC 2544](https://tools.ietf.org/html/rfc2544)
pub const BENCHMARK_TESTS: &str = "198.18.0.0/15";

/// Documentation and example network
/// [RFC 5737](https://tools.ietf.org/html/rfc5737)
pub const TEST_NET_2: &str = "198.51.100.0/24";

/// Documentation and example network
/// [RFC 5737](https://tools.ietf.org/html/rfc5737)
pub const TEST_NET_3: &str = "203.0.113.0/24";

/// Multicast reserved block
/// [RFC 5771](https://tools.ietf.org/html/rfc5771)
pub const MULTICAST: &str = "224.0.0.0/4";

/// Link local multicast
/// [RFC 5771](https://tools.ietf.org/html/rfc5771)
pub const MULTICAST_LOCAL: &str = "224.0.0.0/24";

/// Forwardable multicast
/// [RFC 5771](https://tools.ietf.org/html/rfc5771)
pub const MULTICAST_INTERNETWORK: &str = "224.0.1.0/24";

/// Former Class E address space. Reserved for future use
/// [RFC 1700](https://tools.ietf.org/html/rfc1700)
pub const RESERVED: &str = "240.0.0.0/4";

/// Broadcast messages to the current network
/// (only valid as destination address)
/// [RFC 919](https://tools.ietf.org/html/rfc919)
pub const BROADCAST: &str = "255.255.255.255";

const OCTET_ASCII_TABLE: [[u8; 3]; 256] = build_octet_ascii_table();
const OCTET_LEN_TABLE: [u8; 256] = build_octet_len_table();

#[cold]
fn push_generated_ascii_slow(out: &mut alloc::string::String, bytes: &[u8]) {
    for &byte in bytes {
        out.push(char::from(byte));
    }
}

#[inline]
fn generated_ascii_string(bytes: &[u8]) -> alloc::string::String {
    match core::str::from_utf8(bytes) {
        Ok(text) => alloc::string::String::from(text),
        Err(_) => {
            let mut out = alloc::string::String::with_capacity(bytes.len());
            push_generated_ascii_slow(&mut out, bytes);
            out
        }
    }
}

#[inline]
fn generated_ascii_vec_string(bytes: alloc::vec::Vec<u8>) -> alloc::string::String {
    match alloc::string::String::from_utf8(bytes) {
        Ok(text) => text,
        Err(err) => {
            let bytes = err.into_bytes();
            generated_ascii_string(&bytes)
        }
    }
}

#[inline]
fn fmt_generated_ascii(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    match core::str::from_utf8(bytes) {
        Ok(text) => f.write_str(text),
        Err(_) => fmt_generated_ascii_slow(f, bytes),
    }
}

#[cold]
fn fmt_generated_ascii_slow(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for &byte in bytes {
        fmt::Write::write_char(f, char::from(byte))?;
    }
    Ok(())
}

pub fn bin_u32(number: u32) -> alloc::string::String {
    let bits = usize::max(1, (32 - number.leading_zeros()) as usize);
    let mut buf = [0u8; 34];
    buf[0] = b'0';
    buf[1] = b'b';

    let mut i = 0usize;
    while i < bits {
        let shift = bits - 1 - i;
        buf[2 + i] = b'0' + ((number >> shift) & 1) as u8;
        i += 1;
    }

    generated_ascii_string(&buf[..2 + bits])
}

const fn build_octet_ascii_table() -> [[u8; 3]; 256] {
    let mut table = [[b'0'; 3]; 256];
    let mut i = 0;
    while i < 256 {
        let value = i as u16;
        table[i][0] = b'0' + ((value / 100) % 10) as u8;
        table[i][1] = b'0' + ((value / 10) % 10) as u8;
        table[i][2] = b'0' + (value % 10) as u8;
        i += 1;
    }
    table
}

const fn build_octet_len_table() -> [u8; 256] {
    let mut table = [1u8; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = if i >= 100 {
            3
        } else if i >= 10 {
            2
        } else {
            1
        };
        i += 1;
    }
    table
}

/// Validates a dotted-quad ip address using regex
///
/// The string is considered a valid dotted-quad address if it consists of
/// exactly four octets (0-255) separated by periods (.).
///
/// Note: This function uses regex matching. For better performance,
/// consider using `validate_ip()` which uses the optimized parser.
///
/// # Example
///
/// ```
/// use iptools::ipv4::validate_ip_re;
/// assert_eq!(validate_ip_re("127.0.0.1"), true);
/// assert_eq!(validate_ip_re("127.0.0.x"), false);
/// ```
#[cfg(feature = "std")]
pub fn validate_ip_re(ip: &str) -> bool {
    IPV4_RE.is_match(ip)
        && ip
            .split('.')
            .all(|q| !(q.len() > 1 && q.as_bytes()[0] == b'0') && q.parse::<u8>().is_ok())
}

/// Validates a dotted-quad ip address (optimized)
///
/// The string is considered a valid dotted-quad address if it consists of
/// exactly four octets (0-255) separated by periods (.).
///
/// This function uses the optimized `ip2long` parser for validation,
/// making it significantly faster than `validate_ip_re()` which uses regex.
///
/// # Example
///
/// ```
/// use iptools::ipv4::validate_ip;
/// assert_eq!(validate_ip("127.0.0.1"), true);
/// assert_eq!(validate_ip("127.0.0.x"), false);
/// ```
pub fn validate_ip(ip: &str) -> bool {
    ip2long(ip).is_ok()
}

/// Validate a [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) notation using regex
///
/// The string is considered a valid CIDR address if it consists of a valid
/// IPv4 address in dotted-quad format followed by a forward slash (/) and
/// a bit mask length (0-32).
///
/// Note: This function uses regex matching. For better performance,
/// consider using `validate_cidr()` which uses the optimized parser.
///
/// # Example
///
/// ```
/// use iptools::ipv4::validate_cidr_re;
/// assert_eq!(validate_cidr_re("127.0.0.1/32"), true);
/// assert_eq!(validate_cidr_re("127.0.0.1"), false);
/// ```
#[cfg(feature = "std")]
pub fn validate_cidr_re(cidr: &str) -> bool {
    let Some(slash_pos) = cidr.bytes().position(|b| b == b'/') else {
        return false;
    };

    let ip_part = &cidr[..slash_pos];
    let mask_bytes = &cidr.as_bytes()[slash_pos + 1..];

    // Exactly one slash.
    if mask_bytes.contains(&b'/') {
        return false;
    }

    // Validate prefix range (0-32) and strict dotted-quad IP.
    parse_prefix(mask_bytes, 32).is_some() && validate_ip_re(ip_part)
}

/// Validate a [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) notation (optimized)
///
/// The string is considered a valid CIDR address if it consists of a valid
/// IPv4 address in dotted-quad format followed by a forward slash (/) and
/// a bit mask length (0-32).
///
/// This function uses the optimized `ip2long` parser for validation,
/// making it significantly faster than `validate_cidr_re()` which uses regex.
///
/// # Example
///
/// ```
/// use iptools::ipv4::validate_cidr;
/// assert_eq!(validate_cidr("127.0.0.1/32"), true);
/// assert_eq!(validate_cidr("127.0.0.1"), false);
/// ```
pub fn validate_cidr(cidr: &str) -> bool {
    let bytes = cidr.as_bytes();
    let len = bytes.len();
    if !(9..=19).contains(&len) {
        return false;
    }

    let mut idx = 0usize;
    let mut octets_done = 0u8;
    let mut octet = 0u16;
    let mut octet_len = 0u8;

    while idx < len {
        let b = bytes[idx];
        if b == b'/' {
            break;
        }

        if b == b'.' {
            if octet_len == 0 || octets_done >= 3 {
                return false;
            }
            octets_done += 1;
            octet = 0;
            octet_len = 0;
            idx += 1;
            continue;
        }

        if !b.is_ascii_digit() {
            return false;
        }

        let digit = u16::from(b - b'0');
        if octet_len == 0 {
            octet = digit;
            octet_len = 1;
        } else {
            if octet_len == 1 && octet == 0 {
                return false;
            }
            octet = octet * 10 + digit;
            octet_len += 1;
            if octet_len > 3 || octet > 255 {
                return false;
            }
        }
        idx += 1;
    }

    if idx >= len || octets_done != 3 || octet_len == 0 {
        return false;
    }

    idx += 1;
    let prefix_len = len - idx;
    if prefix_len == 0 || prefix_len > 3 {
        return false;
    }

    let mut prefix = 0u32;
    while idx < len {
        let b = bytes[idx];
        if !b.is_ascii_digit() {
            return false;
        }
        prefix = (prefix * 10) + u32::from(b - b'0');
        if prefix > 32 {
            return false;
        }
        idx += 1;
    }

    true
}

/// Validate that a dotted-quad ip address is a valid [netmask](https://en.wikipedia.org/wiki/Subnetwork)
///
/// # Example
///
/// ```
/// use iptools::ipv4::validate_netmask;
/// assert_eq!(validate_netmask("255.255.255.255"), true);
/// assert_eq!(validate_netmask("128.0.0.1"), false);
/// ```
pub fn validate_netmask(netmask: &str) -> bool {
    parse_contiguous_netmask(netmask).is_some()
}

/// Validate a dotted-quad ip address including a netmask
///
/// The string is considered a valid dotted-quad address with netmask if it
/// consists of four octets (0-255) separated by periods (.) followed
/// by a forward slash (/) and a subnet bitmask which is expressed in
/// dotted-quad format.
///
/// # Example
///
/// ```
/// use iptools::ipv4::validate_subnet;
/// assert_eq!(validate_subnet("127.0.0.1/255.255.255.255"), true);
/// assert_eq!(validate_subnet("128.0.0.1"), false);
/// ```
pub fn validate_subnet(subnet: &str) -> bool {
    let Some(idx) = subnet.bytes().position(|b| b == b'/') else {
        return false;
    };
    let start = &subnet[..idx];
    let mask = &subnet[idx + 1..];
    !start.is_empty()
        && !mask.is_empty()
        && validate_ip(start)
        && parse_contiguous_netmask(mask).is_some()
}

// Legacy parser used by `ip2network`, which intentionally preserves historical
// shorthand behavior (1-4 octets).
#[inline(always)]
fn parse_ipv4_octets_legacy(ip: &str) -> Result<([u32; 4], usize)> {
    let mut octets = [0u32; 4];
    let mut idx = 0;
    let mut current: u32 = 0;
    let mut has_digit = false;

    for &b in ip.as_bytes() {
        if b == b'.' {
            if !has_digit || idx >= 3 {
                return Err(Error::V4IP());
            }
            octets[idx] = current;
            idx += 1;
            current = 0;
            has_digit = false;
        } else if b.is_ascii_digit() {
            current = (current * 10) + (b - b'0') as u32;
            if current > 255 {
                return Err(Error::V4IP());
            }
            has_digit = true;
        } else {
            return Err(Error::V4IP());
        }
    }

    if !has_digit {
        return Err(Error::V4IP());
    }
    octets[idx] = current;
    Ok((octets, idx + 1))
}

// Strict dotted-quad parser (exactly 4 octets, no multi-digit leading zeros).
#[inline(always)]
fn parse_ipv4_quad(ip: &str) -> Result<u32> {
    let bytes = ip.as_bytes();
    if bytes.len() < 7 || bytes.len() > 15 {
        return Err(Error::V4IP());
    }

    let mut out = 0u32;
    let mut octets_done = 0u8;
    let mut octet = 0u16;
    let mut octet_len = 0u8;

    for &b in bytes {
        if b == b'.' {
            if octet_len == 0 || octets_done >= 3 {
                return Err(Error::V4IP());
            }
            out = (out << 8) | u32::from(octet);
            octets_done += 1;
            octet = 0;
            octet_len = 0;
            continue;
        }

        if !b.is_ascii_digit() {
            return Err(Error::V4IP());
        }

        let digit = u16::from(b - b'0');
        if octet_len == 0 {
            octet = digit;
            octet_len = 1;
            continue;
        }

        if octet_len == 1 && octet == 0 {
            return Err(Error::V4IP());
        }

        octet = octet * 10 + digit;
        octet_len += 1;
        if octet_len > 3 || octet > 255 {
            return Err(Error::V4IP());
        }
    }

    if octets_done != 3 || octet_len == 0 {
        return Err(Error::V4IP());
    }

    Ok((out << 8) | u32::from(octet))
}

/// Convert a dotted-quad ip address to a network byte order 32 bit integer
///
/// # Example
///
/// ```
/// use iptools::ipv4::ip2long;
/// assert_eq!(ip2long("127.0.0.1"), Ok(2130706433));
/// assert!(ip2long("127").is_err());
/// assert_eq!(ip2long("127.0.0.256").is_err(), true);
/// ```
#[inline(always)]
pub fn ip2long(ip: &str) -> Result<u32> {
    parse_ipv4_quad(ip)
}

/// Convert a dotted-quad ip to base network number
///
/// This differs from `ip2long` in that partial addresses as treated as
/// all network instead of network plus host (eg. '127.1' expands to '127.1.0.0')
/// and shorthand forms are intentionally accepted for compatibility with the
/// historical `iptools` API. Use [`ip2long`] when you need strict dotted-quad
/// parsing.
///
/// # Example
///
/// ```
/// use iptools::ipv4::ip2network;
/// assert_eq!(ip2network("127.1").unwrap(), 2130771968);
/// assert_eq!(ip2network("127.1").unwrap(), ip2network("127.1.0.0").unwrap());
/// assert_eq!(ip2network("255.255.255.255").unwrap(), 4294967295);
/// assert_eq!(ip2network("ravioli"), None);
/// ```
pub fn ip2network(ip: &str) -> Option<u32> {
    let (octets, count) = parse_ipv4_octets_legacy(ip).ok()?;
    let mut out = 0u32;
    let mut i = 0usize;
    while i < count {
        out |= octets[i] << (24 - (i as u32 * 8));
        i += 1;
    }
    Some(out)
}

/// Convert a network byte order 32 bit integer to a dotted quad ip address
///
/// # Example
///
/// ```
/// use iptools::ipv4::long2ip;
/// assert_eq!(long2ip(2130706433), "127.0.0.1");
/// ```
pub fn long2ip(ip_dec: u32) -> alloc::string::String {
    let octets = [
        ((ip_dec >> 24) & 0xFF) as u8,
        ((ip_dec >> 16) & 0xFF) as u8,
        ((ip_dec >> 8) & 0xFF) as u8,
        (ip_dec & 0xFF) as u8,
    ];

    let mut buf = alloc::vec::Vec::with_capacity(15);

    for (i, &octet) in octets.iter().enumerate() {
        if i > 0 {
            buf.push(b'.');
        }
        let idx = octet as usize;
        let digits = OCTET_ASCII_TABLE[idx];
        match OCTET_LEN_TABLE[idx] {
            3 => {
                buf.push(digits[0]);
                buf.push(digits[1]);
                buf.push(digits[2]);
            }
            2 => {
                buf.push(digits[1]);
                buf.push(digits[2]);
            }
            _ => buf.push(digits[2]),
        }
    }

    generated_ascii_vec_string(buf)
}
/// Convert a dotted-quad IPv4 address to an eight-character lowercase hex string.
///
/// # Example
///
/// ```
/// use iptools::ipv4::ip2hex;
/// assert_eq!(ip2hex("0.0.0.1"), Ok("00000001".to_string()));
/// assert_eq!(ip2hex("127.0.0.1"), Ok("7f000001".to_string()));
/// ```
pub fn ip2hex(ip: &str) -> Result<alloc::string::String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let value = ip2long(ip)?;
    let mut buf = [0u8; 8];
    let mut shift = 28u32;
    let mut i = 0usize;
    while i < buf.len() {
        buf[i] = HEX[((value >> shift) & 0x0f) as usize];
        shift = shift.saturating_sub(4);
        i += 1;
    }

    Ok(generated_ascii_string(&buf))
}

/// Convert a hex encoded integer to a dotted-quad ip address
///
/// # Example
///
/// ```
/// use iptools::ipv4::hex2ip;
/// assert_eq!(hex2ip("00000001"), Ok("0.0.0.1".to_string()));
/// assert_eq!(hex2ip("7f000001"), Ok("127.0.0.1".to_string()));
/// ```
pub fn hex2ip(hex_str: &str) -> Result<alloc::string::String> {
    let exclude_prefix = hex_str.trim_start_matches("0x");
    let hex_ip = u32::from_str_radix(exclude_prefix, 16).map_err(|_| Error::Hex2IP())?;
    Ok(long2ip(hex_ip))
}

/// Convert a CIDR notation ip address into a tuple containing the network block start and end addresses
///
/// # Example
///
/// ```
/// use iptools::ipv4::cidr2block;
/// assert_eq!(cidr2block("127.0.0.1/32"), Ok(("127.0.0.1".to_string(), "127.0.0.1".to_string())));
/// assert_eq!(cidr2block("127.0.0.0/8"), Ok(("127.0.0.0".to_string(), "127.255.255.255".to_string())));
/// ```
pub fn cidr2block(cidr: &str) -> Result<(alloc::string::String, alloc::string::String)> {
    let (start, end) = cidr_bounds(cidr)?;
    Ok((long2ip(start), long2ip(end)))
}

/// Convert a dotted-quad netmask into a CIDR prefix
///
/// # Example
///
/// ```
/// use iptools::ipv4::netmask2prefix;
/// assert_eq!(netmask2prefix("255.0.0.0"), 8);
/// assert_eq!(netmask2prefix("255.128.0.0"), 9);
/// ```
pub fn netmask2prefix(mask: &str) -> u32 {
    parse_contiguous_netmask(mask)
        .map(|value| value.count_ones())
        .unwrap_or(0)
}

#[inline(always)]
fn parse_contiguous_netmask(mask: &str) -> Option<u32> {
    ip2long(mask).ok().and_then(|value| {
        let inv = !value;
        if (inv & inv.wrapping_add(1)) == 0 {
            Some(value)
        } else {
            None
        }
    })
}

/// Convert a dotted-quad ip address including a netmask into a tuple containing the network block start and end addresses
///
/// # Example
///
/// ```
/// use iptools::ipv4::subnet2block;
/// assert_eq!(subnet2block("127.0.0.1/255.255.255.255"), Some(("127.0.0.1".to_string(), "127.0.0.1".to_string())));
/// assert_eq!(subnet2block("127.0.0.0/255.0.0.0"), Some(("127.0.0.0".to_string(), "127.255.255.255".to_string())));
/// ```
pub fn subnet2block(subnet: &str) -> Option<(alloc::string::String, alloc::string::String)> {
    let idx = subnet.bytes().position(|b| b == b'/')?;
    let ip_part = &subnet[..idx];
    let mask_part = &subnet[idx + 1..];

    if ip_part.is_empty() || mask_part.is_empty() {
        return None;
    }

    let network = ip2long(ip_part).ok()?;
    let mask = parse_contiguous_netmask(mask_part)?;
    let prefix = mask.count_ones();
    Some(_block_from_ip_and_prefix(network, prefix))
}

/// Convert a CIDR notation IPv4 address into raw numeric start/end bounds.
///
/// This is the allocation-free counterpart to [`cidr2block`]. Use it when
/// callers need numeric bounds for range checks or storage and do not need
/// dotted-quad strings.
///
/// # Example
///
/// ```
/// use iptools::ipv4::cidr_bounds;
/// assert_eq!(cidr_bounds("127.0.0.1/24"), Ok((2130706432, 2130706687)));
/// ```
#[inline(always)]
pub fn cidr_bounds(cidr: &str) -> Result<(u32, u32)> {
    let Some(idx) = cidr.find('/') else {
        return Err(Error::V4CIDR());
    };

    let ip_str = &cidr[..idx];
    let prefix_str = &cidr.as_bytes()[idx + 1..];
    let Some(prefix) = parse_prefix(prefix_str, 32) else {
        return Err(Error::V4CIDR());
    };

    let ip = ip2long(ip_str)?;
    block_bounds(ip, prefix)
}

/// Convert a raw IPv4 address and CIDR prefix into raw numeric start/end bounds.
///
/// # Example
///
/// ```
/// use iptools::ipv4::{block_bounds, ip2long};
/// let ip = ip2long("10.0.1.2").unwrap();
/// assert_eq!(block_bounds(ip, 16), Ok((167772160, 167837695)));
/// ```
#[inline(always)]
pub fn block_bounds(ip: u32, prefix: u32) -> Result<(u32, u32)> {
    if prefix > 32 {
        return Err(Error::V4CIDR());
    }
    Ok(block_from_ip_and_prefix_raw(ip, prefix))
}

// Creates a tuple of (start, end) dotted-quad addresses from the given ip address and prefix length
fn _block_from_ip_and_prefix(
    ip: u32,
    prefix: u32,
) -> (alloc::string::String, alloc::string::String) {
    let (block_start, block_end) = block_from_ip_and_prefix_raw(ip, prefix);
    (long2ip(block_start), long2ip(block_end))
}

#[inline(always)]
fn block_from_ip_and_prefix_raw(ip: u32, prefix: u32) -> (u32, u32) {
    let netmask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let block_start = ip & netmask;
    let block_end = block_start | !netmask;
    (block_start, block_end)
}

#[inline(always)]
fn encode_long2ip(ip_dec: u32, buf: &mut [u8; 15]) -> usize {
    let octets = [
        ((ip_dec >> 24) & 0xFF) as u8,
        ((ip_dec >> 16) & 0xFF) as u8,
        ((ip_dec >> 8) & 0xFF) as u8,
        (ip_dec & 0xFF) as u8,
    ];

    let mut len = 0usize;
    for (i, &octet) in octets.iter().enumerate() {
        if i > 0 {
            buf[len] = b'.';
            len += 1;
        }
        let idx = octet as usize;
        let digits = OCTET_ASCII_TABLE[idx];
        match OCTET_LEN_TABLE[idx] {
            3 => {
                buf[len] = digits[0];
                buf[len + 1] = digits[1];
                buf[len + 2] = digits[2];
                len += 3;
            }
            2 => {
                buf[len] = digits[1];
                buf[len + 1] = digits[2];
                len += 2;
            }
            _ => {
                buf[len] = digits[2];
                len += 1;
            }
        }
    }
    len
}

#[inline(always)]
pub(crate) fn push_long2ip(out: &mut alloc::string::String, ip_dec: u32) {
    let mut buf = [0u8; 15];
    let len = encode_long2ip(ip_dec, &mut buf);
    for &byte in &buf[..len] {
        out.push(char::from(byte));
    }
}

pub(crate) fn fmt_long2ip(f: &mut fmt::Formatter<'_>, ip_dec: u32) -> fmt::Result {
    let mut buf = [0u8; 15];
    let len = encode_long2ip(ip_dec, &mut buf);
    fmt_generated_ascii(f, &buf[..len])
}

#[inline(always)]
fn parse_prefix(bytes: &[u8], max: u32) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 3 {
        return None;
    }

    let mut value = 0u32;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        value = (value * 10) + u32::from(b - b'0');
        if value > max {
            return None;
        }
    }
    Some(value)
}

#[cfg(test)]
mod tests;
