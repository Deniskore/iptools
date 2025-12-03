// Copyright (c) 2025 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT

use lazy_regex::regex;
use once_cell::sync::Lazy;

use crate::error::Error;
use crate::error::Result;

static IPV4_RE: &lazy_regex::Lazy<lazy_regex::Regex> = regex!(r"^(\d{1,3}\.){0,3}\d{1,3}$");

/// IETF and IANA reserved ip addresses
pub static RESERVED_RANGES: Lazy<alloc::vec::Vec<&str>> = Lazy::new(|| {
    alloc::vec![
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
    ]
});

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
/// [RFC 3972](https://tools.ietf.org/html/rfc3972)
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

pub fn bin_u32(number: u32) -> alloc::string::String {
    alloc::format!("0b{:b}", number)
}
/// Validates a dotted-quad ip address using regex
///
/// The string is considered a valid dotted-quad address if it consists of
/// one to four octets (0-255) seperated by periods (.).
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
pub fn validate_ip_re(ip: &str) -> bool {
    IPV4_RE.is_match(ip)
        && ip
            .split('.')
            .all(|q| q.parse::<u32>().is_ok_and(|q| q < 256))
}

/// Validates a dotted-quad ip address (optimized)
///
/// The string is considered a valid dotted-quad address if it consists of
/// one to four octets (0-255) seperated by periods (.).
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
pub fn validate_cidr_re(cidr: &str) -> bool {
    let Some(slash_pos) = cidr.bytes().position(|b| b == b'/') else {
        return false;
    };

    let ip_part = &cidr[..slash_pos];
    let mask_bytes = &cidr.as_bytes()[slash_pos + 1..];

    // Early validation: mask must be 1-2 digits
    if mask_bytes.is_empty() || mask_bytes.len() > 2 {
        return false;
    }

    // Parse prefix
    let mut prefix: u8 = 0;
    for &b in mask_bytes {
        if !b.is_ascii_digit() {
            return false;
        }
        prefix = prefix * 10 + (b - b'0');
    }

    // Validate prefix range (0-32) and IP (using regex validation)
    prefix <= 32 && validate_ip_re(ip_part)
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
    let mut idx = 0;

    // Parse IPv4 part (1–4 octets, 0–255 each), stopping at '/'
    let mut octet_count = 0;
    let mut current: u16 = 0;
    let mut has_digit = false;
    while idx < len {
        let b = bytes[idx];
        if b == b'/' {
            break;
        } else if b == b'.' {
            if !has_digit || octet_count >= 3 {
                return false;
            }
            octet_count += 1;
            current = 0;
            has_digit = false;
        } else if b.is_ascii_digit() {
            current = current * 10 + (b - b'0') as u16;
            if current > 255 {
                return false;
            }
            has_digit = true;
        } else {
            return false;
        }
        idx += 1;
    }

    // Need a '/' and at least one digit in the last octet
    if idx >= len || !has_digit {
        return false;
    }

    // Parse prefix (1–2 digits, 0–32)
    idx += 1; // skip '/'
    let remaining = len - idx;
    if remaining == 0 || remaining > 2 {
        return false;
    }

    let mut prefix: u8 = 0;
    while idx < len {
        let b = bytes[idx];
        if !b.is_ascii_digit() {
            return false;
        }
        prefix = prefix * 10 + (b - b'0');
        idx += 1;
    }

    prefix <= 32
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

/// Validate a dotted-quad ip adress including a netmask
///
/// The string is considered a valid dotted-quad address with netmask if it
/// consists of one to four octets (0-255) seperated by periods (.) followed
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
    subnet.contains('/') && {
        let mut parts = subnet.splitn(2, '/');
        let start = parts.next().unwrap_or("");
        let mask = parts.next().unwrap_or("");
        !mask.is_empty() && validate_ip(start) && validate_netmask(mask)
    }
}

// Fast parser shared by IPv4 helpers.
#[inline(always)]
fn parse_ipv4_octets(ip: &str) -> Result<([u32; 4], usize)> {
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

/// Convert a dotted-quad ip address to a network byte order 32 bit integer
///
/// # Example
///
/// ```
/// use iptools::ipv4::ip2long;
/// assert_eq!(ip2long("127"), Ok(2130706432));
/// assert_eq!(ip2long("127.0.0.256").is_err(), true);
/// ```
pub fn ip2long(ip: &str) -> Result<u32> {
    let (octets, count) = parse_ipv4_octets(ip)?;

    // Reconstruct based on your original shorthand logic:
    // 1 part  ("10")       -> 10.0.0.0
    // 2 parts ("10.1")     -> 10.0.0.1  (Gap filled with 0s)
    // 3 parts ("10.1.2")   -> 10.1.0.2
    // 4 parts ("10.1.2.3") -> 10.1.2.3
    match count {
        4 => Ok((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]),
        3 => Ok((octets[0] << 24) | (octets[1] << 16) | octets[2]),
        2 => Ok((octets[0] << 24) | octets[1]),
        1 => Ok(octets[0] << 24),
        _ => Err(Error::V4IP()),
    }
}

/// Convert a dotted-quad ip to base network number
///
/// This differs from `ip2long` in that partial addresses as treated as
/// all network instead of network plus host (eg. '127.1' expands to '127.1.0.0')
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
    let (octets, count) = parse_ipv4_octets(ip).ok()?;

    let mut netw: u32 = 0;
    for (i, &octet) in octets.iter().enumerate() {
        let val = if i < count { octet } else { 0 };
        netw = (netw << 8) | val;
    }
    Some(netw)
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

        if octet >= 100 {
            buf.push(b'0' + octet / 100);
            buf.push(b'0' + (octet % 100) / 10);
            buf.push(b'0' + octet % 10);
        } else if octet >= 10 {
            buf.push(b'0' + octet / 10);
            buf.push(b'0' + octet % 10);
        } else {
            buf.push(b'0' + octet);
        }
    }

    alloc::string::String::from_utf8(buf).unwrap()
}
///
/// # Example
///
/// ```
/// use iptools::ipv4::ip2hex;
/// assert_eq!(ip2hex("0.0.0.1"), Ok("00000001".to_string()));
/// assert_eq!(ip2hex("127.0.0.1"), Ok("7f000001".to_string()));
/// ```
pub fn ip2hex(ip: &str) -> Result<alloc::string::String> {
    Ok(alloc::format!("{:08x}", ip2long(ip)?))
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
/// assert_eq!(cidr2block("127/8"), Ok(("127.0.0.0".to_string(), "127.255.255.255".to_string())));
/// ```
pub fn cidr2block(cidr: &str) -> Result<(alloc::string::String, alloc::string::String)> {
    if let Some(idx) = cidr.find('/') {
        let ip_str = &cidr[..idx];
        let prefix_str = &cidr[idx + 1..];

        if let Ok(prefix) = prefix_str.parse::<u32>() {
            if prefix <= 32 {
                if let Some(network) = ip2network(ip_str) {
                    return Ok(_block_from_ip_and_prefix(network, prefix));
                }
            }
        }
    }
    Err(Error::V4CIDR())
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
    ip2network(mask).and_then(|value| {
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
/// assert_eq!(subnet2block("127/255"), Some(("127.0.0.0".to_string(), "127.255.255.255".to_string())));
/// ```
pub fn subnet2block(subnet: &str) -> Option<(alloc::string::String, alloc::string::String)> {
    if !validate_subnet(subnet) {
        return None;
    }

    let mut parts = subnet.splitn(2, '/');
    let ip_netmask_first = parts.next().unwrap_or("");
    let ip_netmask_second = parts.next().unwrap_or("");
    let prefix = netmask2prefix(ip_netmask_second);

    if let Some(network) = ip2network(ip_netmask_first) {
        return Some(_block_from_ip_and_prefix(network, prefix));
    }

    None
}

// Creates a tuple of (start, end) dotted-quad addresses from the given ip address and prefix length
fn _block_from_ip_and_prefix(
    ip: u32,
    prefix: u32,
) -> (alloc::string::String, alloc::string::String) {
    let shift = 32 - prefix;
    let block_start = ip
        .checked_shr(shift)
        .unwrap_or(0)
        .checked_shl(shift)
        .unwrap_or(0);

    let mut mask = u32::MAX;
    if let Some(shift) = 1u32.checked_shl(shift) {
        if let Some(sub) = shift.checked_sub(1) {
            mask = sub;
        }
    }
    let block_end = block_start | mask;
    (long2ip(block_start), long2ip(block_end))
}

#[cfg(test)]
mod tests;
