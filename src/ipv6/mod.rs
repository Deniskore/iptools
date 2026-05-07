// Copyright (c) 2025 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT

use core::fmt;
#[cfg(feature = "std")]
use lazy_regex::regex;

use crate::error::Error;
use crate::error::Result;

#[cfg(feature = "std")]
static HEX_RE: &lazy_regex::Lazy<lazy_regex::Regex> =
    regex!(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$");

#[cfg(feature = "std")]
static DOTTED_QUAD_RE: &lazy_regex::Lazy<lazy_regex::Regex> =
    regex!(r"^([0-9a-fA-F]{0,4}:){2,6}(\d{1,3}\.){3}\d{1,3}$");

// Kept for compatibility with earlier public API
#[allow(dead_code)]
#[cfg(feature = "std")]
static RE_RFC1924: &lazy_regex::Lazy<lazy_regex::Regex> =
    regex!(r"^[0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~]{20}$");

/// Last ip
pub const MAX_IP: u128 = u128::MAX;

/// First ip
pub const MIN_IP: u128 = 0;

/// IETF and IANA reserved ip addresses
pub const RESERVED_RANGES: &[&str] = &[
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
];

/// Absence of an address (only valid as source address)
/// [RFC 4291](https://tools.ietf.org/html/rfc4291)
pub const UNSPECIFIED_ADDRESS: &str = "::/128";

/// Loopback addresses on the local host
/// [RFC 4291](https://tools.ietf.org/html/rfc4291)
pub const LOOPBACK: &str = "::1/128";

/// Common `localhost` address
/// [RFC 4291](https://tools.ietf.org/html/rfc4291)
pub const LOCALHOST: &str = LOOPBACK;

/// IPv4 mapped to IPv6 (not globally routable)
/// [RFC 4291](https://tools.ietf.org/html/rfc4291)
pub const IPV4_MAPPED: &str = "::ffff:0:0/96";

/// Documentation and example network
/// [RFC 3849](https://tools.ietf.org/html/rfc3849)
pub const DOCUMENTATION_NETWORK: &str = "2001:db8::/32";

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
/// [RFC 4291](https://tools.ietf.org/html/rfc4291)
pub const MULTICAST: &str = "ff00::/8";

/// Interface-Local multicast
pub const MULTICAST_LOOPBACK: &str = "ff01::/16";

/// Link-Local multicast
pub const MULTICAST_LOCAL: &str = "ff02::/16";

/// Site-Local multicast
pub const MULTICAST_SITE: &str = "ff05::/16";

/// Organization-Local multicast
pub const MULTICAST_SITE_ORG: &str = "ff08::/16";

/// Global multicast
pub const MULTICAST_GLOBAL: &str = "ff0e::/16";

/// All nodes on the local segment
pub const MULTICAST_LOCAL_NODES: &str = "ff02::1";

/// All routers on the local segment
pub const MULTICAST_LOCAL_ROUTERS: &str = "ff02::2";

/// All DHCP servers and relay agents on the local segment
pub const MULTICAST_LOCAL_DHCP: &str = "ff02::1:2";

/// All DHCP servers and relay agents on the local site
pub const MULTICAST_SITE_DHCP: &str = "ff05::1:3";

const RFC1924_ALPHABET_BYTES: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

const fn build_rfc1924_rev_table() -> [i8; 128] {
    let mut table = [-1i8; 128];
    let mut i = 0;
    while i < RFC1924_ALPHABET_BYTES.len() {
        let byte = RFC1924_ALPHABET_BYTES[i] as usize;
        if byte < 128 {
            table[byte] = i as i8;
        }
        i += 1;
    }
    table
}

const RFC1924_REV_TABLE: [i8; 128] = build_rfc1924_rev_table();

#[inline]
fn push_generated_ascii(out: &mut alloc::string::String, bytes: &[u8]) {
    match core::str::from_utf8(bytes) {
        Ok(text) => out.push_str(text),
        Err(_) => push_generated_ascii_slow(out, bytes),
    }
}

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

enum Ipv6HextetParseError {
    DottedQuadTail,
    Invalid(Error),
}

/// Validate a hexadecimal IPV6 ip address using regex
///
/// Note: This function applies regex pre-filtering and then parses with
/// `ip2long()`. For better performance, consider using `validate_ip()`.
///
/// # Example
///
/// ```
/// use iptools::ipv6::validate_ip_re;
/// assert_eq!(validate_ip_re("::ffff:192.0.2.300"), false);
/// assert_eq!(validate_ip_re("1080:0:0:0:8:800:200c:417a"), true);
/// ```
#[cfg(feature = "std")]
pub fn validate_ip_re(ip: &str) -> bool {
    let is_hex = HEX_RE.is_match(ip);
    let is_dotted_quad = DOTTED_QUAD_RE.is_match(ip);
    (is_hex || is_dotted_quad) && ip2long(ip).is_ok()
}

/// Validate a hexadecimal IPV6 ip address (optimized)
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

/// Convert a hexadecimal IPV6 address to a network byte order 128 bit integer
///
/// # Example
///
/// ```
/// use iptools::ipv6::ip2long;
/// assert_eq!(ip2long("::"), Ok(0));
/// assert_eq!(ip2long("::1"), Ok(1));
/// assert_eq!(ip2long("2001:db8:85a3::8a2e:370:7334"),Ok(0x20010db885a3000000008a2e03707334));
/// ```
#[inline(always)]
pub fn ip2long(ip: &str) -> Result<u128> {
    let bytes = ip.as_bytes();
    match parse_ipv6_hextets(bytes) {
        Ok(value) => Ok(value),
        Err(Ipv6HextetParseError::DottedQuadTail) => parse_ipv6_mixed_dotted_quad(bytes),
        Err(Ipv6HextetParseError::Invalid(err)) => Err(err),
    }
}

#[inline(always)]
fn parse_ipv6_mixed_dotted_quad(bytes: &[u8]) -> Result<u128> {
    let Some(pos) = bytes.iter().rposition(|&b| b == b':') else {
        // Keep IPv6 parser strict on address family: bare IPv4 is not IPv6.
        return Err(Error::V6IP());
    };

    let suffix = &bytes[pos + 1..];
    let (v6_src, v4_suffix) = if suffix.contains(&b'.') {
        let src = if pos > 0 && bytes[pos - 1] == b':' {
            &bytes[..pos + 1]
        } else {
            &bytes[..pos]
        };
        (src, Some(suffix)) // IPv4-mapped like "::ffff:127.0.0.1"
    } else {
        // Dot was not in the final segment, let the IPv6 prefix parser reject it.
        (bytes, None)
    };

    let mut parts = [0u16; 8];
    let mut capacity = 8;

    if let Some(suffix) = v4_suffix {
        if v6_src.is_empty() {
            return Err(Error::V6IP());
        }
        // RFC-oriented dotted tail parser:
        // x:x:x:x:x:x:d.d.d.d must use exactly four decimal octets.
        let v4_int = parse_ipv4_dotted_quad_strict(suffix).ok_or(Error::V6IP())?;
        parts[6] = (v4_int >> 16) as u16;
        parts[7] = v4_int as u16;
        capacity = 6;
    }

    parse_ipv6_prefix(v6_src, &mut parts, capacity)?;

    Ok(groups_to_u128(&parts))
}

#[inline(always)]
fn parse_ipv6_hextets(src: &[u8]) -> core::result::Result<u128, Ipv6HextetParseError> {
    let len = src.len();
    if len == 0 {
        return Err(Ipv6HextetParseError::Invalid(Error::V6IP()));
    }

    let mut idx = 0usize;
    let mut head = 0u128;
    let mut tail = 0u128;
    let mut head_count = 0usize;
    let mut tail_count = 0usize;
    let mut compression_seen = false;

    while idx < len {
        if src[idx] == b':' {
            if idx + 1 < len && src[idx + 1] == b':' && !compression_seen {
                compression_seen = true;
                idx += 2;
                if idx == len {
                    break;
                }
                continue;
            }
            return Err(Ipv6HextetParseError::Invalid(Error::V6IP()));
        }

        let mut value = 0u16;
        let mut digits = 0usize;
        while idx < len {
            let b = src[idx];
            if b == b':' {
                break;
            }
            if b == b'.' {
                return Err(Ipv6HextetParseError::DottedQuadTail);
            }
            let Some(nibble) = hex_nibble(b) else {
                return Err(Ipv6HextetParseError::Invalid(Error::V6IPConvert()));
            };
            digits += 1;
            if digits > 4 {
                return Err(Ipv6HextetParseError::Invalid(Error::V6IPConvert()));
            }
            value = (value << 4) | u16::from(nibble);
            idx += 1;
        }

        if digits == 0 {
            return Err(Ipv6HextetParseError::Invalid(Error::V6IP()));
        }

        if compression_seen {
            if tail_count >= 8 {
                return Err(Ipv6HextetParseError::Invalid(Error::V6IP()));
            }
            tail = (tail << 16) | u128::from(value);
            tail_count += 1;
        } else {
            if head_count >= 8 {
                return Err(Ipv6HextetParseError::Invalid(Error::V6IP()));
            }
            head = (head << 16) | u128::from(value);
            head_count += 1;
        }

        if idx == len {
            break;
        }

        if idx + 1 < len && src[idx + 1] == b':' {
            if compression_seen {
                return Err(Ipv6HextetParseError::Invalid(Error::V6IP()));
            }
            compression_seen = true;
            idx += 2;
            if idx == len {
                break;
            }
        } else {
            idx += 1;
            if idx == len {
                return Err(Ipv6HextetParseError::Invalid(Error::V6IP()));
            }
        }
    }

    if compression_seen {
        if head_count + tail_count >= 8 {
            return Err(Ipv6HextetParseError::Invalid(Error::V6IP()));
        }
        let high = if head_count == 0 {
            0
        } else {
            head << ((8 - head_count) * 16)
        };
        Ok(high | tail)
    } else {
        if head_count != 8 {
            return Err(Ipv6HextetParseError::Invalid(Error::V6IP()));
        }
        Ok(head)
    }
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
            compression_seen = true;
            i += 2;
            break;
        }

        // Parse a single hex segment
        let start = i;
        while i < src.len() && src[i] != b':' {
            i += 1;
        }

        if start == i {
            // Empty segment not part of "::"
            return Err(Error::V6IP());
        }

        // Non-empty segment
        if head_idx >= capacity {
            return Err(Error::V6IP());
        }
        parts[head_idx] = parse_hex_u16(&src[start..i]).ok_or(Error::V6IPConvert())?;
        head_idx += 1;

        if i < src.len() && src[i] == b':' {
            i += 1; // Skip colon
            if i == src.len() {
                // A single trailing ':' is invalid.
                return Err(Error::V6IP());
            }
        }

        // Check for :: after skipping single colon (handles cases where :: follows a segment)
        if i < src.len() && src[i] == b':' {
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
                if i == src.len() {
                    // A single trailing ':' after tail segment is invalid.
                    return Err(Error::V6IP());
                }
            } else {
                break;
            }
        }

        // Place tail at end of address
        if head_idx + tail_idx >= capacity {
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

/// Parse strict dotted-quad IPv4 suffix for IPv6 text forms.
///
/// Accepts exactly 4 decimal octets in [0, 255], rejects shorthand
/// forms and multi-digit leading zeros.
///
/// This matches RFC 4291 section 2.2 (`x:x:x:x:x:x:d.d.d.d`) and
/// RFC 3986 `IPv4address` (`dec-octet "." dec-octet "." dec-octet "." dec-octet`).
#[inline(always)]
fn parse_ipv4_dotted_quad_strict(src: &[u8]) -> Option<u32> {
    let mut octets = [0u32; 4];
    let mut octet_idx = 0usize;
    let mut value = 0u32;
    let mut digits = 0usize;

    for &b in src {
        match b {
            b'0'..=b'9' => {
                if digits == 0 {
                    value = (b - b'0') as u32;
                    digits = 1;
                } else {
                    if digits == 1 && value == 0 {
                        // No leading zeros in multi-digit octets.
                        return None;
                    }
                    value = value * 10 + u32::from(b - b'0');
                    digits += 1;
                    if digits > 3 || value > 255 {
                        return None;
                    }
                }
            }
            b'.' => {
                if digits == 0 || octet_idx >= 3 {
                    return None;
                }
                octets[octet_idx] = value;
                octet_idx += 1;
                value = 0;
                digits = 0;
            }
            _ => return None,
        }
    }

    if digits == 0 || octet_idx != 3 {
        return None;
    }
    octets[3] = value;

    Some((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3])
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

#[inline(always)]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Assemble u128 from 8 u16 groups
#[inline(always)]
fn groups_to_u128(groups: &[u16; 8]) -> u128 {
    (u128::from(groups[0]) << 112)
        | (u128::from(groups[1]) << 96)
        | (u128::from(groups[2]) << 80)
        | (u128::from(groups[3]) << 64)
        | (u128::from(groups[4]) << 48)
        | (u128::from(groups[5]) << 32)
        | (u128::from(groups[6]) << 16)
        | u128::from(groups[7])
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

    let mut buf = [0u8; 39];
    let len = encode_long2ip(long_ip, &mut buf);
    generated_ascii_vec_string(buf[..len].to_vec())
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
    let mut buf = [b'0'; 20];
    let mut idx = 20;
    let mut value = long_ip;

    // Fill from the end to avoid reversing
    while value > 0 {
        let digit = (value % 85) as usize;
        value /= 85;
        idx -= 1;
        buf[idx] = RFC1924_ALPHABET_BYTES[digit];
    }

    generated_ascii_vec_string(buf.to_vec())
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
    if s.len() != 20 {
        return None;
    }

    let mut acc = 0u128;
    for b in s.bytes() {
        if b >= 128 {
            return None;
        }
        let val = RFC1924_REV_TABLE[b as usize];
        if val < 0 {
            return None;
        }
        acc = acc.checked_mul(85)?.checked_add(val as u128)?;
    }
    Some(acc)
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
#[cfg(feature = "std")]
pub fn validate_cidr_re(cidr: &str) -> bool {
    // Find the '/' separator
    let Some(slash_pos) = cidr.bytes().position(|b| b == b'/') else {
        return false;
    };

    let ip_part = &cidr[..slash_pos];
    let mask_bytes = &cidr.as_bytes()[slash_pos + 1..];

    // Exactly one slash.
    if mask_bytes.contains(&b'/') {
        return false;
    }

    // Validate prefix range (0-128) and IP (using regex validation)
    parse_prefix_0_128(mask_bytes).is_some() && validate_ip_re(ip_part)
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
    let bytes = cidr.as_bytes();

    // Find the '/' separator
    let Some(slash_pos) = bytes.iter().position(|&b| b == b'/') else {
        return false;
    };

    let ip_part = &cidr[..slash_pos];
    let mask_start = slash_pos + 1;
    let mask_bytes = &bytes[mask_start..];
    if mask_bytes.contains(&b'/') {
        return false;
    }

    // Validate IP (using ip2long for fast validation)
    parse_prefix_0_128(mask_bytes).is_some() && ip2long(ip_part).is_ok()
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
    let (start, end) = cidr_bounds(cidr)?;
    Ok((long2ip(start, false), long2ip(end, false)))
}

/// Convert a CIDR notation IPv6 address into raw numeric start/end bounds.
///
/// This is the allocation-free counterpart to [`cidr2block`]. Use it when
/// callers need numeric bounds for range checks or storage and do not need
/// canonical IPv6 strings.
///
/// # Example
///
/// ```
/// use iptools::ipv6::cidr_bounds;
/// assert_eq!(cidr_bounds("2001:db8::/126").unwrap().1, 0x20010db8000000000000000000000003);
/// ```
#[inline(always)]
pub fn cidr_bounds(cidr: &str) -> Result<(u128, u128)> {
    let Some(idx) = cidr.find('/') else {
        return Err(Error::V6CIDR());
    };

    let ip_str = &cidr[..idx];
    let prefix_bytes = &cidr.as_bytes()[idx + 1..];
    if prefix_bytes.contains(&b'/') {
        return Err(Error::V6CIDR());
    }
    let Some(prefix) = parse_prefix_0_128(prefix_bytes) else {
        return Err(Error::V6CIDR());
    };

    let ip = ip2long(ip_str)?;
    block_bounds(ip, prefix)
}

/// Convert a raw IPv6 address and CIDR prefix into raw numeric start/end bounds.
///
/// # Example
///
/// ```
/// use iptools::ipv6::{block_bounds, ip2long};
/// let ip = ip2long("2001:db8::1234").unwrap();
/// assert_eq!(block_bounds(ip, 32).unwrap().0, ip2long("2001:db8::").unwrap());
/// ```
#[inline(always)]
pub fn block_bounds(ip: u128, prefix: u8) -> Result<(u128, u128)> {
    if prefix > 128 {
        return Err(Error::V6CIDR());
    }
    Ok(block_from_ip_and_prefix_raw(ip, prefix))
}

fn block_from_ip_and_prefix_raw(ip: u128, prefix: u8) -> (u128, u128) {
    let shift = 128 - u32::from(prefix);
    if shift == 128 {
        return (0, u128::MAX);
    }
    let block_start = ip & (u128::MAX << shift);
    (block_start, block_start | ((1u128 << shift) - 1))
}

fn zero_run_bounds(hextets: &[u16; 8]) -> (usize, usize) {
    let mut best = (8usize, 0usize);
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

    if curr_len > best.1 {
        best = (curr_start, curr_len);
    }

    if best.1 < 2 { (8, 0) } else { best }
}

fn write_hextet(buf: &mut [u8; 39], len: usize, val: u16) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    if val >= 0x1000 {
        buf[len] = HEX[(val >> 12) as usize];
        buf[len + 1] = HEX[((val >> 8) & 0xF) as usize];
        buf[len + 2] = HEX[((val >> 4) & 0xF) as usize];
        buf[len + 3] = HEX[(val & 0xF) as usize];
        len + 4
    } else if val >= 0x100 {
        buf[len] = HEX[((val >> 8) & 0xF) as usize];
        buf[len + 1] = HEX[((val >> 4) & 0xF) as usize];
        buf[len + 2] = HEX[(val & 0xF) as usize];
        len + 3
    } else if val >= 0x10 {
        buf[len] = HEX[((val >> 4) & 0xF) as usize];
        buf[len + 1] = HEX[(val & 0xF) as usize];
        len + 2
    } else {
        buf[len] = HEX[val as usize];
        len + 1
    }
}

fn encode_long2ip(long_ip: u128, buf: &mut [u8; 39]) -> usize {
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
    let (best_start, best_len) = zero_run_bounds(&hextets);

    let mut len = 0usize;
    let mut i = 0usize;
    while i < 8 {
        if i == best_start {
            buf[len] = b':';
            buf[len + 1] = b':';
            len += 2;
            i += best_len;
            continue;
        }

        if len > 0 && buf[len - 1] != b':' {
            buf[len] = b':';
            len += 1;
        }

        len = write_hextet(buf, len, hextets[i]);
        i += 1;
    }

    len
}

pub(crate) fn push_long2ip(out: &mut alloc::string::String, long_ip: u128) {
    let mut buf = [0u8; 39];
    let len = encode_long2ip(long_ip, &mut buf);
    push_generated_ascii(out, &buf[..len]);
}

pub(crate) fn fmt_long2ip(f: &mut fmt::Formatter<'_>, long_ip: u128) -> fmt::Result {
    let mut buf = [0u8; 39];
    let len = encode_long2ip(long_ip, &mut buf);
    fmt_generated_ascii(f, &buf[..len])
}

#[inline(always)]
fn parse_prefix_0_128(bytes: &[u8]) -> Option<u8> {
    if bytes.is_empty() {
        return None;
    }
    let mut value: u16 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u16::from(b - b'0');
        if value > 128 {
            return None;
        }
    }
    Some(value as u8)
}

#[cfg(test)]
mod tests;
