// Copyright (c) 2022 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT

use once_cell::sync::Lazy;
use regex::Regex;

use crate::error::Error;
use crate::error::Result;

static IPV4_RE: Lazy<&Regex> = Lazy::new(|| {
    static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
    RE.get_or_init(|| regex::Regex::new(r"^(\d{1,3}\.){0,3}\d{1,3}$").unwrap())
});

static CIDR_RE: Lazy<&Regex> = Lazy::new(|| {
    static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
    RE.get_or_init(|| regex::Regex::new(r"^(\d{1,3}\.){0,3}\d{1,3}/\d{1,2}$").unwrap())
});

/// IETF and IANA reserved ip addresses
pub static RESERVED_RANGES: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
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

pub fn bin_u32(number: u32) -> String {
    format!("0b{:b}", number)
}
/// Validates a dotted-quad ip address
///
/// The string is considered a valid dotted-quad address if it consists of
/// one to four octets (0-255) seperated by periods (.).
///
/// # Example
///
/// ```
/// use iptools::ipv4::validate_ip;
/// assert_eq!(validate_ip("127.0.0.1"), true);
/// assert_eq!(validate_ip("127.0.0.x"), false);
/// ```
pub fn validate_ip(ip: &str) -> bool {
    IPV4_RE.is_match(ip)
        && ip
            .split('.')
            .all(|q| q.parse::<u32>().map_or(false, |q| q < 256))
}

/// Validate a [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) notation
///
/// The string is considered a valid CIDR address if it consists of a valid
/// IPv4 address in dotted-quad format followed by a forward slash (/) and
/// a bit mask length (1-32).
///
/// # Example
///
/// ```
/// use iptools::ipv4::validate_cidr;
/// assert_eq!(validate_cidr("127.0.0.1/32"), true);
/// assert_eq!(validate_cidr("127.0.0.1"), false);
/// ```
pub fn validate_cidr(cidr: &str) -> bool {
    if CIDR_RE.is_match(cidr) {
        let ip_mask = cidr.split('/').collect::<Vec<_>>();
        if validate_ip(ip_mask[0]) {
            if let Ok(mask) = ip_mask[1].parse::<i32>() {
                if mask < 33 {
                    return true;
                }
            }
        }
    }
    false
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
    validate_ip(netmask)
        && ip2network(netmask).map_or(false, |ip| {
            let mask = format!("{:0>32}", bin_u32(ip).trim_start_matches("0b"));
            !mask.contains("01")
        })
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
        let start_mask: Vec<&str> = subnet.split('/').collect::<Vec<_>>();
        start_mask.len() == 2 && validate_ip(start_mask[0]) && validate_netmask(start_mask[1])
    }
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
    if !validate_ip(ip) {
        return Err(Error::V4IP());
    }
    let mut quads: Vec<i32> = ip.split('.').filter_map(|w| w.parse().ok()).collect();
    if quads.len() == 1 {
        quads.extend(vec![0, 0, 0]);
    } else if quads.len() < 4 {
        if let Some(quad) = quads.last() {
            let index = quads.iter().position(|i| i == quad).ok_or(Error::V4IP())?;
            for _i in 0..((quads.len() as i32) - 4).abs() {
                quads.insert(index, 0);
            }
        } else {
            return Err(Error::V4IP());
        }
    }

    let mut ip_i32: u32 = 0;
    for q in quads {
        ip_i32 = (ip_i32 << 8) | q as u32;
    }
    Ok(ip_i32)
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
    if !validate_ip(ip) {
        return None;
    }

    let quads: Vec<u32> = ip
        .split('.')
        .filter_map(|w| w.parse().ok())
        .take(4)
        .collect();

    if quads.len() < 4 {
        let mut netw: u32 = 0;
        for i in 0..4 {
            let val = quads.get(i).unwrap_or(&0);
            netw = (netw << 8) | val;
        }
        Some(netw)
    } else {
        Some(((quads[0]) << 24) | ((quads[1]) << 16) | ((quads[2]) << 8) | (quads[3]))
    }
}

/// Convert a network byte order 32 bit integer to a dotted quad ip address
///
/// # Example
///
/// ```
/// use iptools::ipv4::long2ip;
/// assert_eq!(long2ip(2130706433), "127.0.0.1");
/// ```
pub fn long2ip(ip_dec: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        ip_dec >> 24 & 255,
        ip_dec >> 16 & 255,
        ip_dec >> 8 & 255,
        ip_dec & 255
    )
}

/// Convert a dotted-quad ip address to a hex encoded number
///
/// # Example
///
/// ```
/// use iptools::ipv4::ip2hex;
/// assert_eq!(ip2hex("0.0.0.1"), Ok("00000001".to_string()));
/// assert_eq!(ip2hex("127.0.0.1"), Ok("7f000001".to_string()));
/// ```
pub fn ip2hex(ip: &str) -> Result<String> {
    Ok(format!("{:08x}", ip2long(ip)?))
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
pub fn hex2ip(hex_str: &str) -> Result<String> {
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
pub fn cidr2block(cidr: &str) -> Result<(String, String)> {
    if !validate_cidr(cidr) {
        return Err(Error::V4CIDR());
    }

    let ip_prefix: Vec<&str> = cidr.split('/').collect();
    if let Ok(prefix) = ip_prefix[1].parse::<u32>() {
        if let Some(network) = ip2network(ip_prefix[0]) {
            return Ok(_block_from_ip_and_prefix(network, prefix));
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
    if validate_netmask(mask) {
        if let Some(result) = ip2network(mask) {
            return bin_u32(result).matches('1').count() as u32;
        }
    }
    0
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
pub fn subnet2block(subnet: &str) -> Option<(String, String)> {
    if !validate_subnet(subnet) {
        return None;
    }

    let ip_netmask: Vec<&str> = subnet.split('/').collect();
    let prefix = netmask2prefix(ip_netmask[1]);

    if let Some(network) = ip2network(ip_netmask[0]) {
        return Some(_block_from_ip_and_prefix(network, prefix));
    }

    None
}

// Creates a tuple of (start, end) dotted-quad addresses from the given ip address and prefix length
fn _block_from_ip_and_prefix(ip: u32, prefix: u32) -> (String, String) {
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
mod tests {
    use crate::ipv4::{
        _block_from_ip_and_prefix, bin_u32, cidr2block, hex2ip, ip2hex, ip2long, ip2network,
        long2ip, netmask2prefix, subnet2block, validate_cidr, validate_ip, validate_netmask,
        validate_subnet, BROADCAST, LOOPBACK, MAX_IP, MIN_IP,
    };

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
        assert_eq!(ip2long("127.0.0.256").is_err(), true);
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
    fn test_validate_netmask() {
        assert_eq!(validate_netmask("0.0.0.0"), true);
        assert_eq!(validate_netmask("128.0.0.0"), true);
        assert_eq!(validate_netmask("255.0.0.0"), true);
        assert_eq!(validate_netmask("255.255.255.255"), true);
        assert_eq!(validate_netmask(BROADCAST), true);
        assert_eq!(validate_netmask("128.0.0.1"), false);
        assert_eq!(validate_netmask("1.255.255.0"), false);
        assert_eq!(validate_netmask("0.255.255.0"), false);
    }

    #[test]
    fn test_validate_subnet() {
        assert_eq!(validate_subnet("127.0.0.1/255.255.255.255"), true);
        assert_eq!(validate_subnet("127.0/255.0.0.0"), true);
        assert_eq!(validate_subnet("127.0/255"), true);
        assert_eq!(validate_subnet("127.0.0.256/255.255.255.255"), false);
        assert_eq!(validate_subnet("127.0.0.1/255.255.255.256"), false);
        assert_eq!(validate_subnet("127.0.0.0"), false);
        assert_eq!(
            validate_subnet("127.0.0.1/255.255.255.255/127.0.0.2"),
            false
        );
    }

    #[test]
    fn test_block_from_ip_and_prefix() {
        assert_eq!(
            _block_from_ip_and_prefix(4294967295, 32),
            ("255.255.255.255".to_string(), "255.255.255.255".to_string())
        );

        assert_eq!(
            _block_from_ip_and_prefix(4294967295, 24),
            ("255.255.255.0".to_string(), "255.255.255.255".to_string())
        );
        assert_eq!(
            _block_from_ip_and_prefix(4294967295, 16),
            ("255.255.0.0".to_string(), "255.255.255.255".to_string())
        );
        assert_eq!(
            _block_from_ip_and_prefix(4294967295, 8),
            ("255.0.0.0".to_string(), "255.255.255.255".to_string())
        );
        assert_eq!(
            _block_from_ip_and_prefix(4294967295, 1),
            ("128.0.0.0".to_string(), "255.255.255.255".to_string())
        );
        assert_eq!(
            _block_from_ip_and_prefix(4294967295, 0),
            ("0.0.0.0".to_string(), "255.255.255.255".to_string())
        );
        assert_eq!(
            _block_from_ip_and_prefix(0, 0),
            ("0.0.0.0".to_string(), "255.255.255.255".to_string())
        );
        assert_eq!(
            _block_from_ip_and_prefix(0, 32),
            ("0.0.0.0".to_string(), "0.0.0.0".to_string())
        );
        assert_eq!(
            _block_from_ip_and_prefix(0, 24),
            ("0.0.0.0".to_string(), "0.0.0.255".to_string())
        );
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
            cidr2block("127/0"),
            Ok(("0.0.0.0".to_string(), "255.255.255.255".to_string()))
        );
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
    }
}
