// Copyright (c) 2025 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT

use lazy_regex::regex;
use once_cell::sync::Lazy;
use tinyvec::ArrayVec;

use crate::error::Error;
use crate::error::Result;

static HEX_RE: &lazy_regex::Lazy<lazy_regex::Regex> =
    regex!(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$");

static DOTTED_QUAD_RE: &lazy_regex::Lazy<lazy_regex::Regex> =
    regex!(r"^([0-9a-f]{0,4}:){2,6}(\d{1,3}\.){0,3}\d{1,3}$");

// Regex for validating an IPv6 in hex notation
static RE_RFC1924: &lazy_regex::Lazy<lazy_regex::Regex> =
    regex!(r"^[0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~]{20}$");

// RFC 1924 reverse lookup
const _RFC1924_REV: bool = true;

/// Last ip
pub const MAX_IP: u128 = u128::MAX;

/// First ip
pub const MIN_IP: u128 = 0;

/// IETF and IANA reserved ip addresses
pub static RESERVED_RANGES: Lazy<alloc::vec::Vec<&str>> = Lazy::new(|| {
    alloc::vec![
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

static RFC1924_REV_TABLE: Lazy<[i8; 128]> = Lazy::new(|| {
    let mut table = [-1i8; 128];
    for (i, &c) in _RFC1924_ALPHABET.iter().enumerate() {
        if (c as usize) < 128 {
            table[c as usize] = i as i8;
        }
    }
    table
});

fn rfc1924_rev_lookup(c: char) -> Option<i32> {
    if (c as u32) < 128 {
        let val = RFC1924_REV_TABLE[c as usize];
        if val >= 0 {
            return Some(val as i32);
        }
    }
    None
}

/// Validate a hexidecimal IPV6 ip address using regex
///
/// Note: This function uses regex matching. For better performance,
/// consider using `validate_ip()` which uses the optimized parser.
///
/// # Example
///
/// ```
/// use iptools::ipv6::validate_ip_re;
/// assert_eq!(validate_ip_re("::ffff:192.0.2.300"), false);
/// assert_eq!(validate_ip_re("1080:0:0:0:8:800:200c:417a"), true);
/// ```
pub fn validate_ip_re(ip: &str) -> bool {
    let is_hex = HEX_RE.is_match(ip);
    let is_dotted_quad = DOTTED_QUAD_RE.is_match(ip);
    if is_hex {
        ip.split("::").count() <= 2
    } else if is_dotted_quad {
        if ip.split("::").count() > 2 {
            return false;
        }
        let quads: ArrayVec<[&str; 4]> =
            ip.split(':').next_back().map_or(ArrayVec::new(), |last| {
                last.split('.').collect::<ArrayVec<[&str; 4]>>()
            });
        quads
            .iter()
            .all(|q| q.parse::<i32>().ok().is_some_and(|q| q <= 255))
    } else {
        false
    }
}

/// Validate a hexidecimal IPV6 ip address (optimized)
///
/// This function uses the optimized `ip2long` parser for validation,
/// making it significantly faster than `validate_ip_re()` which uses regex.
///
/// Per [RFC 4291 2.2](https://datatracker.ietf.org/doc/html/rfc4291#section-2.2)
/// we reject syntactically ambiguous forms such as `:::1`. The original Python
/// `iptools` library still accepts that input, so you can verify the difference
/// locally with:
/// ```python
/// >>> from iptools import ipv6
/// >>> ipv6.validate_ip(':::1')
/// True
/// ```
///
/// # Example
///
/// ```
/// use iptools::ipv6::validate_ip;
/// assert_eq!(validate_ip("::ffff:192.0.2.300"), false);
/// assert_eq!(validate_ip("1080:0:0:0:8:800:200c:417a"), true);
/// ```
pub fn validate_ip(ip: &str) -> bool {
    ip2long(ip).is_ok()
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
    let bytes = ip.as_bytes();

    let (v6_src, v4_suffix) = match bytes.iter().rposition(|&b| b == b':') {
        Some(pos) => {
            let suffix = &bytes[pos + 1..];
            if suffix.contains(&b'.') {
                let src = if pos > 0 && bytes[pos - 1] == b':' {
                    &bytes[..pos + 1]
                } else {
                    &bytes[..pos]
                };
                (src, Some(suffix)) // IPv4-mapped like "::ffff:127.0.0.1"
            } else {
                (bytes, None) // Pure IPv6 like "2001:db8::1"
            }
        }
        None if bytes.contains(&b'.') => (&[][..], Some(bytes)), // Pure IPv4
        None => (bytes, None),                                   // Compressed IPv6 like "::"
    };

    let mut parts = [0u16; 8];
    let mut capacity = 8;

    if let Some(suffix) = v4_suffix {
        let v4_str = core::str::from_utf8(suffix).map_err(|_| Error::V6IP())?;
        let v4_int = crate::ipv4::ip2long(v4_str)?;
        parts[6] = (v4_int >> 16) as u16;
        parts[7] = v4_int as u16;
        capacity = 6;
    }

    if !v6_src.is_empty() {
        parse_ipv6_prefix(v6_src, &mut parts, capacity)?;
    } else if capacity == 8 && v4_suffix.is_none() {
        // Handle "::" case, valid for IPv6 (all zeros)
        if bytes != b"::" {
            return Err(Error::V6IP());
        }
    }

    Ok(groups_to_u128(&parts))
}

/// Parse IPv6 prefix with compression support
#[inline(always)]
fn parse_ipv6_prefix(src: &[u8], parts: &mut [u16; 8], capacity: usize) -> Result<()> {
    let mut i = 0;
    let mut head_idx = 0;
    let mut tail_idx = 0;
    let mut tail_buf = [0u16; 7];
    let mut compression_seen = false;

    // Parse head segments (before ::)
    while i < src.len() {
        // Look ahead for :: compression marker
        if i + 1 < src.len() && src[i] == b':' && src[i + 1] == b':' {
            if compression_seen {
                return Err(Error::V6IP()); // Multiple :: is invalid
            }
            compression_seen = true;
            i += 2;
            break;
        }

        // Parse a single hex segment
        let start = i;
        while i < src.len() && src[i] != b':' {
            i += 1;
        }

        if start != i {
            // Non-empty segment
            if head_idx >= capacity {
                return Err(Error::V6IP());
            }
            parts[head_idx] = parse_hex_u16(&src[start..i]).ok_or(Error::V6IPConvert())?;
            head_idx += 1;
        }

        if i < src.len() && src[i] == b':' {
            i += 1; // Skip colon
        }

        // Check for :: after skipping single colon (handles cases where :: follows a segment)
        if i < src.len() && src[i] == b':' {
            if compression_seen {
                return Err(Error::V6IP()); // Multiple :: is invalid
            }
            compression_seen = true;
            i += 1;
            break;
        }
    }

    // Parse tail segments (after ::)
    if compression_seen {
        while i < src.len() {
            let start = i;
            while i < src.len() && src[i] != b':' {
                i += 1;
            }

            if start == i {
                return Err(Error::V6IP()); // No empty segments in tail
            }

            if tail_idx >= tail_buf.len() {
                return Err(Error::V6IP());
            }
            tail_buf[tail_idx] = parse_hex_u16(&src[start..i]).ok_or(Error::V6IPConvert())?;
            tail_idx += 1;

            if i < src.len() && src[i] == b':' {
                i += 1;
            } else {
                break;
            }
        }

        // Place tail at end of address
        if head_idx + tail_idx > capacity {
            return Err(Error::V6IP());
        }
        if tail_idx > 0 {
            let insert_pos = capacity - tail_idx;
            parts[insert_pos..capacity].copy_from_slice(&tail_buf[..tail_idx]);
        }
        // Gap is already there from array initialization
    } else if head_idx != capacity {
        // No compression, must fill exactly capacity segments
        return Err(Error::V6IP());
    }

    Ok(())
}

/// Parse hex string to u16 (0-FFFF)
#[inline(always)]
fn parse_hex_u16(src: &[u8]) -> Option<u16> {
    let len = src.len();
    if len == 0 || len > 4 {
        return None;
    }

    let mut val = 0u16;
    for &b in src {
        val <<= 4;
        val += match b {
            b'0'..=b'9' => (b - b'0') as u16,
            b'a'..=b'f' => (b - b'a' + 10) as u16,
            b'A'..=b'F' => (b - b'A' + 10) as u16,
            _ => return None,
        };
    }
    Some(val)
}

/// Assemble u128 from 8 u16 groups
#[inline(always)]
fn groups_to_u128(groups: &[u16; 8]) -> u128 {
    groups
        .iter()
        .fold(0u128, |acc, &g| (acc << 16) | u128::from(g))
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
pub fn long2ip(long_ip: u128, rfc1924: bool) -> alloc::string::String {
    if rfc1924 {
        return long2rfc1924(long_ip);
    }

    // Extract hextets
    let hextets = [
        (long_ip >> 112) as u16,
        (long_ip >> 96) as u16,
        (long_ip >> 80) as u16,
        (long_ip >> 64) as u16,
        (long_ip >> 48) as u16,
        (long_ip >> 32) as u16,
        (long_ip >> 16) as u16,
        long_ip as u16,
    ];

    // Find longest zero run
    let (best_start, best_len) = {
        let mut best = (8usize, 0usize); // Invalid start means no compression
        let mut curr_start = 8usize;
        let mut curr_len = 0usize;

        for (i, &h) in hextets.iter().enumerate() {
            if h == 0 {
                if curr_start == 8 {
                    curr_start = i;
                }
                curr_len += 1;
            } else {
                if curr_len > best.1 {
                    best = (curr_start, curr_len);
                }
                curr_start = 8;
                curr_len = 0;
            }
        }

        // Check final run
        if curr_len > best.1 {
            best = (curr_start, curr_len);
        }

        if best.1 < 2 {
            (8, 0)
        } else {
            best
        }
    };

    // Use byte buffer for zero-allocation string building
    let mut buf = [0u8; 39];
    let mut pos = 0;

    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut i = 0;
    while i < 8 {
        // Handle compression
        if i == best_start {
            buf[pos..pos + 2].copy_from_slice(b"::");
            pos += 2;
            i = best_start + best_len;
            continue;
        }

        // Add separator
        if pos > 0 && buf[pos - 1] != b':' {
            buf[pos] = b':';
            pos += 1;
        }

        // Format hextet - optimized to avoid leading zeros
        let val = hextets[i];

        if val >= 0x1000 {
            buf[pos] = HEX[(val >> 12) as usize];
            buf[pos + 1] = HEX[((val >> 8) & 0xF) as usize];
            buf[pos + 2] = HEX[((val >> 4) & 0xF) as usize];
            buf[pos + 3] = HEX[(val & 0xF) as usize];
            pos += 4;
        } else if val >= 0x100 {
            buf[pos] = HEX[((val >> 8) & 0xF) as usize];
            buf[pos + 1] = HEX[((val >> 4) & 0xF) as usize];
            buf[pos + 2] = HEX[(val & 0xF) as usize];
            pos += 3;
        } else if val >= 0x10 {
            buf[pos] = HEX[((val >> 4) & 0xF) as usize];
            buf[pos + 1] = HEX[(val & 0xF) as usize];
            pos += 2;
        } else {
            buf[pos] = HEX[val as usize];
            pos += 1;
        }

        i += 1;
    }

    // Safe: buf contains only ASCII hex digits and colons, so this can never fail
    alloc::string::String::from_utf8(buf[..pos].to_vec()).unwrap()
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
pub fn long2rfc1924(long_ip: u128) -> alloc::string::String {
    let mut o: ArrayVec<[char; 20]> = ArrayVec::new();
    let mut r = long_ip;
    while r > 85 {
        o.push(_RFC1924_ALPHABET[(r % 85) as usize]);
        r /= 85;
    }
    o.push(_RFC1924_ALPHABET[r as usize]);
    o.reverse();
    alloc::format!("{:0>20}", o.into_iter().collect::<alloc::string::String>())
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
            let val = rfc1924_rev_lookup(c)?;
            x = mul_result + val as u128;
        } else {
            return None;
        }
    }
    Some(x)
}

/// Validate a CIDR notation ip address using regex
///
/// Note: This function uses regex matching. For better performance,
/// consider using `validate_cidr()` which uses the optimized parser.
///
/// # Example
///
/// ```
/// use iptools::ipv6::validate_cidr_re;
/// assert_eq!(validate_cidr_re("fc00::/7"), true);
/// assert_eq!(validate_cidr_re("::ffff:0:0/96"), true);
/// assert_eq!(validate_cidr_re("::"), false);
/// assert_eq!(validate_cidr_re("::/129"), false);
/// ```
pub fn validate_cidr_re(cidr: &str) -> bool {
    // Find the '/' separator
    let Some(slash_pos) = cidr.bytes().position(|b| b == b'/') else {
        return false;
    };

    let ip_part = &cidr[..slash_pos];
    let mask_bytes = &cidr.as_bytes()[slash_pos + 1..];

    // Early validation: mask must be 1-3 digits
    if mask_bytes.is_empty() || mask_bytes.len() > 3 {
        return false;
    }

    // Parse prefix manually (faster than parse::<u128>())
    let mut prefix: u16 = 0;
    for &b in mask_bytes {
        if !b.is_ascii_digit() {
            return false;
        }
        prefix = prefix * 10 + (b - b'0') as u16;
    }

    // Validate prefix range (0-128) and IP (using regex validation)
    prefix <= 128 && validate_ip_re(ip_part)
}

/// Validate a CIDR notation ip address (optimized)
///
/// This function uses the optimized `ip2long` parser for validation,
/// making it significantly faster than `validate_cidr_re()` which uses regex.
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
    // Find the '/' separator
    let Some(slash_pos) = cidr.bytes().position(|b| b == b'/') else {
        return false;
    };

    let ip_part = &cidr[..slash_pos];
    let mask_bytes = &cidr.as_bytes()[slash_pos + 1..];

    // Early validation: mask must be 1-3 digits
    if mask_bytes.is_empty() || mask_bytes.len() > 3 {
        return false;
    }

    // Parse prefix manually (faster than parse::<u128>())
    let mut prefix: u16 = 0;
    for &b in mask_bytes {
        if !b.is_ascii_digit() {
            return false;
        }
        prefix = prefix * 10 + (b - b'0') as u16;
    }

    // Validate prefix range (0-128) and IP (using ip2long for fast validation)
    prefix <= 128 && ip2long(ip_part).is_ok()
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
pub fn cidr2block(cidr: &str) -> Result<(alloc::string::String, alloc::string::String)> {
    if let Some(idx) = cidr.find('/') {
        let ip_str = &cidr[..idx];
        let prefix_str = &cidr[idx + 1..];

        if let Ok(prefix) = prefix_str.parse::<u128>() {
            if prefix <= 128 {
                if let Ok(ip) = ip2long(ip_str) {
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
                    return Ok((long2ip(block_start, false), long2ip(block_end, false)));
                }
            }
        }
    }
    Err(Error::V6CIDR())
}

#[cfg(test)]
mod tests;
