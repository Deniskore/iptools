// Copyright (c) 2025 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT
use crate::error::{Error, Result};
use crate::ipv4;
use crate::ipv6;
use core::hash::{Hash, Hasher};
use core::iter::FusedIterator;
use core::marker::PhantomData;
use once_cell::sync::Lazy;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr};

static RESERVED_IPV4_BLOCKS: Lazy<alloc::vec::Vec<(u32, u32)>> = Lazy::new(|| {
    ipv4::RESERVED_RANGES
        .iter()
        .filter_map(|range| IpRange::<IPv4>::new(range, "").ok())
        .map(|range| range.bounds())
        .collect::<alloc::vec::Vec<(u32, u32)>>()
});

static RESERVED_IPV6_BLOCKS: Lazy<alloc::vec::Vec<(u128, u128)>> = Lazy::new(|| {
    ipv6::RESERVED_RANGES
        .iter()
        .filter_map(|range| IpRange::<IPv6>::new(range, "").ok())
        .map(|range| range.bounds())
        .collect::<alloc::vec::Vec<(u128, u128)>>()
});

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum IpVer {
    V4,
    V6,
    VUnknown,
}

#[derive(Debug, Clone, Copy)]
pub struct IPv4;

#[derive(Debug, Clone, Copy)]
pub struct IPv6;

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound(
        serialize = "T: serde::Serialize",
        deserialize = "T: serde::de::DeserializeOwned"
    ))
)]
struct RangeState<T> {
    start_ip: T,
    end_ip: T,
    len: T,
    next_ip: T,
    remaining: T,
}

/// A generic IP address range.
///
/// Use [`IPv4`] or [`IPv6`] markers to specify the IP version.
///
/// [`IpRange::new`] treats its inputs as inclusive numeric bounds (`start`
/// ≤ `end`). It does not interpret dotted netmasks passed via the `end`
/// parameter—use the CIDR form (e.g. `"10.0.0.0/24"`) when you want network
/// semantics or provide the literal closing address (`"10.0.0.0`,
/// `"10.0.0.255"`). The internal length counters are `u32` (IPv4) and `u128`
/// (IPv6), so attempting to create a range that spans every IPv4 address (all
/// 4,294,967,296 values) will overflow during length calculation. Any proper
/// subset fits (e.g., `0.0.0.0` → `255.255.255.254` plus a second block for the
/// last address), but the one extra element in the full space pushes the count
/// beyond what `u32` can hold.
///
/// # Examples
///
/// ```
/// use iptools::iprange::{IpRange, IPv4};
///
/// # fn main() -> iptools::error::Result<()> {
/// let range = IpRange::<IPv4>::new("192.168.0.0/24", "")?;
/// assert_eq!(range.len(), 256);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound(
        serialize = "T::Addr: serde::Serialize",
        deserialize = "T::Addr: serde::de::DeserializeOwned"
    ))
)]
pub struct IpRange<T: RangeFamily> {
    ip_range: RangeState<T::Addr>,
    #[cfg_attr(feature = "serde", serde(skip))]
    _marker: PhantomData<T>,
}

pub trait RangeFamily {
    type Addr: Copy + Ord + Hash + 'static;

    const VERSION: IpVer;

    fn zero() -> Self::Addr;
    fn validate_ip(ip: &str) -> bool;
    fn validate_cidr(cidr: &str) -> bool;
    fn parse_single(ip: &str) -> Result<Self::Addr>;
    fn parse_cidr(cidr: &str) -> Result<(Self::Addr, Self::Addr)>;
    fn format_addr(addr: Self::Addr) -> alloc::string::String;
    fn invalid_ip_error() -> Error;
    fn checked_add_one(value: Self::Addr) -> Option<Self::Addr>;
    fn wrapping_add_one(value: Self::Addr) -> Self::Addr;
    fn checked_sub_one(value: Self::Addr) -> Self::Addr;
    fn len(start: Self::Addr, end: Self::Addr) -> Self::Addr;
    fn remaining(end: Self::Addr, iter: Self::Addr) -> Self::Addr;
    fn size_hint(remaining: Self::Addr) -> (usize, Option<usize>);
    fn reserved_blocks() -> &'static [(Self::Addr, Self::Addr)];
    fn from_u128(value: u128) -> Self::Addr;
}

fn parse_endpoint<T: RangeFamily>(value: &str, want_start: bool) -> Result<T::Addr> {
    if T::validate_cidr(value) {
        let (start, end) = T::parse_cidr(value)?;
        return Ok(if want_start { start } else { end });
    }
    if T::validate_ip(value) {
        return T::parse_single(value);
    }
    Err(T::invalid_ip_error())
}

pub(crate) enum TargetRange {
    V4 {
        start: u32,
        end: u32,
        is_range: bool,
    },
    V6 {
        start: u128,
        end: u128,
        is_range: bool,
    },
}

impl TargetRange {
    fn parse(ip: &str) -> Result<Self> {
        if ip.contains('/') {
            if ip.contains(':') {
                let (start, end) = ipv6::cidr2block(ip)?;
                let start = ipv6::ip2long(&start)?;
                let end = ipv6::ip2long(&end)?;
                return Ok(Self::V6 {
                    start,
                    end,
                    is_range: true,
                });
            } else {
                let (start, end) = ipv4::cidr2block(ip)?;
                let start = ipv4::ip2long(&start)?;
                let end = ipv4::ip2long(&end)?;
                return Ok(Self::V4 {
                    start,
                    end,
                    is_range: true,
                });
            }
        }

        if ip.contains(':') {
            let addr = ipv6::ip2long(ip)?;
            return Ok(Self::V6 {
                start: addr,
                end: addr,
                is_range: false,
            });
        }

        let addr = ipv4::ip2long(ip).map_err(|_| Error::UnknownVersion())?;
        Ok(Self::V4 {
            start: addr,
            end: addr,
            is_range: false,
        })
    }

    #[cfg(test)]
    fn is_range(&self) -> bool {
        match self {
            Self::V4 { is_range, .. } => *is_range,
            Self::V6 { is_range, .. } => *is_range,
        }
    }
}

impl<T: RangeFamily> IpRange<T> {
    /// Creates a new IP range.
    ///
    /// `start` accepts a single IP (`"10.0.0.1"`) or a CIDR (`"10.0.0.0/24"`). `end` is optional
    /// (pass an empty string) when `start` already encodes the closing boundary via CIDR or when
    /// you're creating a single-IP range. When you do provide `end`, it must be the literal final
    /// address and **not** a dotted netmask or prefix length—the constructor does not try to infer
    /// masks from the second argument. If you have an address plus mask, convert it to CIDR or to
    /// the corresponding final IP before calling [`IpRange::new`].
    ///
    /// Note: Unlike the Python `iptools` library, reversed bounds are rejected
    /// rather than normalized.
    ///
    /// # Examples
    ///
    /// ```
    /// use iptools::{iprange::{IpRange, IPv4}, ipv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let r1 = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.5")?;
    /// let r2 = IpRange::<IPv4>::new("192.168.1.0/24", "")?;
    ///
    /// // If you have an address + dotted netmask pair, normalize it first.
    /// let block = ipv4::subnet2block("10.0.120.90/255.255.248.0").unwrap();
    /// let cidr = IpRange::<IPv4>::new("10.0.120.0/21", "")?;
    /// let explicit = IpRange::<IPv4>::new(&block.0, &block.1)?;
    /// assert_eq!(cidr.len(), explicit.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(start: &str, end: &str) -> Result<IpRange<T>> {
        let end_spec = if end.is_empty() { start } else { end };
        let start_ip = parse_endpoint::<T>(start, true)?;
        let end_ip = parse_endpoint::<T>(end_spec, false)?;

        // Unlike Python iptools, reversed bounds are rejected.
        if start_ip > end_ip {
            return Err(Error::V4Subnet());
        }
        let len = T::len(start_ip, end_ip);
        if len == T::zero() && start_ip != end_ip {
            return Err(Error::V4Subnet());
        }
        Ok(IpRange {
            ip_range: RangeState {
                start_ip,
                end_ip,
                len,
                next_ip: start_ip,
                remaining: len,
            },
            _marker: PhantomData,
        })
    }

    /// Returns the start and end IP addresses as strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let range = IpRange::<IPv4>::new("192.168.1.0/24", "")?;
    /// assert_eq!(range.get_range(), ("192.168.1.0".to_string(), "192.168.1.255".to_string()));
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_range(&self) -> (alloc::string::String, alloc::string::String) {
        (
            T::format_addr(self.ip_range.start_ip),
            T::format_addr(self.ip_range.end_ip),
        )
    }

    /// Returns the raw numeric bounds of this range.
    ///
    /// # Examples
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.5")?;
    /// assert_eq!(range.bounds().1 - range.bounds().0, 4);
    /// # Ok(())
    /// # }
    /// ```
    pub fn bounds(&self) -> (T::Addr, T::Addr) {
        (self.ip_range.start_ip, self.ip_range.end_ip)
    }

    pub fn get_version(&self) -> IpVer {
        T::VERSION
    }

    /// Returns the total number of IP addresses in this range.
    ///
    /// # Examples
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let range = IpRange::<IPv4>::new("192.168.1.0/24", "")?;
    /// assert_eq!(range.len(), 256);
    /// # Ok(())
    /// # }
    /// ```
    pub fn len(&self) -> T::Addr {
        self.ip_range.len
    }

    /// Returns true if the range contains no IP addresses.
    pub fn is_empty(&self) -> bool {
        self.ip_range.len == T::zero()
    }

    /// Returns the number of IP addresses remaining in the iteration.
    ///
    /// # Examples
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let mut range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.5")?;
    /// assert_eq!(range.remaining(), 5);
    /// range.next();
    /// assert_eq!(range.remaining(), 4);
    /// # Ok(())
    /// # }
    /// ```
    pub fn remaining(&self) -> T::Addr {
        self.ip_range.remaining
    }

    #[inline]
    fn convert_target(target: TargetRange) -> (T::Addr, T::Addr, bool) {
        match (T::VERSION, target) {
            (
                IpVer::V4,
                TargetRange::V4 {
                    start,
                    end,
                    is_range,
                },
            ) => (
                T::from_u128(start as u128),
                T::from_u128(end as u128),
                is_range,
            ),
            (
                IpVer::V4,
                TargetRange::V6 {
                    start,
                    end,
                    is_range,
                },
            ) => (T::from_u128(start), T::from_u128(end), is_range),
            (
                IpVer::V6,
                TargetRange::V6 {
                    start,
                    end,
                    is_range,
                },
            ) => (T::from_u128(start), T::from_u128(end), is_range),
            (
                IpVer::V6,
                TargetRange::V4 {
                    start,
                    end,
                    is_range,
                },
            ) => (
                T::from_u128(start as u128),
                T::from_u128(end as u128),
                is_range,
            ),
            _ => (T::zero(), T::zero(), false),
        }
    }

    /// Checks whether an IP address or CIDR block sits fully inside this range.
    ///
    /// `contains` performs a straight numeric comparison: the requested IP (or
    /// the start/end of a CIDR block) must fall between the range's inclusive
    /// bounds. Nothing else is inferred. If you created the range with a pair
    /// of strings, the second argument is treated as the literal closing address
    /// and not as a dotted netmask. When you want subnet semantics, build the
    /// range from a CIDR string or provide the concrete closing address. When
    /// you already have parsed numeric values (e.g., from [`std::net::Ipv4Addr`]
    /// or [`std::net::Ipv6Addr`]), use [`IpRange::contains_addr`] or
    /// [`IpRange::contains_range`] to skip the parsing overhead.
    ///
    /// Passing dotted netmasks to `IpRange::new` does **not** convert them to CIDR
    /// bounds. `"10.0.0.1", "255.255.255.0"` spans the numeric space between those
    /// literal addresses, not the `/24` network the mask implies. When you obtain
    /// "IP + netmask" pairs, turn the mask into a prefix (e.g., via
    /// [`ipv4::netmask2prefix`]) and build the range from CIDR or by computing the
    /// actual closing IP before calling `contains`.
    ///
    /// # Examples
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let range = IpRange::<IPv4>::new("192.168.1.0/24", "")?;
    /// assert!(range.contains("192.168.1.100")?);
    /// assert!(range.contains("192.168.1.0/25")?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ```
    /// use iptools::{iprange::{IpRange, IPv4}, ipv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let range = IpRange::<IPv4>::new("192.168.1.0/24", "")?;
    /// let addr = ipv4::ip2long("192.168.1.100")?;
    /// assert!(range.contains_addr(addr));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ```
    /// use iptools::{iprange::{IpRange, IPv4}, ipv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let prefix = ipv4::netmask2prefix("255.255.255.128");
    /// let cidr = format!("{}/{}", "198.51.100.17", prefix);
    /// let subnet = IpRange::<IPv4>::new(&cidr, "")?;
    /// assert!(subnet.contains("198.51.100.100")?);
    /// assert!(!subnet.contains("203.0.113.1")?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn contains(&self, ip: &str) -> Result<bool> {
        let target = TargetRange::parse(ip)?;
        let (start, end, is_range) = Self::convert_target(target);
        if is_range {
            Ok(self.contains_range(start, end))
        } else {
            Ok(self.contains_addr(start))
        }
    }

    /// Checks whether a numeric address sits inside this range.
    #[inline(always)]
    pub fn contains_addr(&self, addr: T::Addr) -> bool {
        self.ip_range.start_ip <= addr && addr <= self.ip_range.end_ip
    }

    /// Checks whether the inclusive numeric bounds sit inside this range.
    #[inline(always)]
    pub fn contains_range(&self, start: T::Addr, end: T::Addr) -> bool {
        if start > end {
            return false;
        }
        self.ip_range.start_ip <= start && end <= self.ip_range.end_ip
    }

    /// Checks if an IP address or range falls within reserved IP blocks (e.g., loopback, private).
    ///
    /// # Examples
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// assert!(IpRange::<IPv4>::is_reserved("127.0.0.1")?);
    /// assert!(IpRange::<IPv4>::is_reserved("192.168.1.1")?);
    /// assert!(!IpRange::<IPv4>::is_reserved("8.8.8.8")?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_reserved(ip: &str) -> Result<bool> {
        let target = TargetRange::parse(ip)?;
        let (start, end, _) = Self::convert_target(target);
        Ok(T::reserved_blocks()
            .iter()
            .any(|&(block_start, block_end)| block_start <= start && end <= block_end))
    }
}

/// Iterator over raw IP addresses.
pub struct AddrIterator<T: RangeFamily> {
    next: Option<T::Addr>,
    end: T::Addr,
    _marker: PhantomData<T>,
}

impl<T: RangeFamily> Iterator for AddrIterator<T> {
    type Item = T::Addr;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next?;
        self.next = if current == self.end {
            None
        } else {
            Some(T::wrapping_add_one(current))
        };
        Some(current)
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.next {
            None => (0, Some(0)),
            Some(current) => {
                let remaining = T::remaining(self.end, current);
                let inclusive = T::checked_add_one(remaining).unwrap_or(remaining);
                T::size_hint(inclusive)
            }
        }
    }
}

impl<T: RangeFamily> FusedIterator for AddrIterator<T> {}
impl ExactSizeIterator for AddrIterator<IPv4> {}

impl<T: RangeFamily> IpRange<T> {
    /// Returns an iterator over raw IP addresses.
    ///
    /// # Example
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.5")?;
    /// assert_eq!(range.addrs().count(), 5);
    /// # Ok(())
    /// # }
    /// ```
    pub fn addrs(&self) -> AddrIterator<T> {
        AddrIterator {
            next: Some(self.ip_range.start_ip),
            end: self.ip_range.end_ip,
            _marker: PhantomData,
        }
    }
}

impl<T: RangeFamily> Iterator for IpRange<T> {
    type Item = alloc::string::String;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.ip_range.remaining == T::zero() {
            return None;
        }

        let out = self.ip_range.next_ip;
        self.ip_range.next_ip = T::wrapping_add_one(out);
        self.ip_range.remaining = T::checked_sub_one(self.ip_range.remaining);
        Some(T::format_addr(out))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        T::size_hint(self.ip_range.remaining)
    }
}

impl<T: RangeFamily> FusedIterator for IpRange<T> {}
impl ExactSizeIterator for IpRange<IPv4> {}

impl<T: RangeFamily> PartialEq for IpRange<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ip_range.start_ip == other.ip_range.start_ip
            && self.ip_range.end_ip == other.ip_range.end_ip
    }
}

impl<T: RangeFamily> Eq for IpRange<T> {}

impl<T: RangeFamily> Hash for IpRange<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip_range.start_ip.hash(state);
        self.ip_range.end_ip.hash(state);
    }
}

impl RangeFamily for IPv4 {
    type Addr = u32;

    const VERSION: IpVer = IpVer::V4;

    fn zero() -> Self::Addr {
        0
    }

    fn validate_ip(ip: &str) -> bool {
        ipv4::validate_ip(ip)
    }

    fn validate_cidr(cidr: &str) -> bool {
        ipv4::validate_cidr(cidr)
    }

    fn parse_single(ip: &str) -> Result<Self::Addr> {
        ipv4::ip2long(ip)
    }

    fn parse_cidr(cidr: &str) -> Result<(Self::Addr, Self::Addr)> {
        let (start, end) = ipv4::cidr2block(cidr)?;
        Ok((ipv4::ip2long(&start)?, ipv4::ip2long(&end)?))
    }

    fn format_addr(addr: Self::Addr) -> alloc::string::String {
        ipv4::long2ip(addr)
    }

    fn invalid_ip_error() -> Error {
        Error::V4IP()
    }

    fn checked_add_one(value: Self::Addr) -> Option<Self::Addr> {
        value.checked_add(1)
    }

    fn wrapping_add_one(value: Self::Addr) -> Self::Addr {
        value.wrapping_add(1)
    }

    fn checked_sub_one(value: Self::Addr) -> Self::Addr {
        value.saturating_sub(1)
    }

    fn len(start: Self::Addr, end: Self::Addr) -> Self::Addr {
        end - start + 1
    }

    fn remaining(end: Self::Addr, iter: Self::Addr) -> Self::Addr {
        end.saturating_sub(iter)
    }

    fn size_hint(remaining: Self::Addr) -> (usize, Option<usize>) {
        let remaining_usize = remaining as usize;
        (remaining_usize, Some(remaining_usize))
    }

    fn reserved_blocks() -> &'static [(Self::Addr, Self::Addr)] {
        &RESERVED_IPV4_BLOCKS
    }

    fn from_u128(value: u128) -> Self::Addr {
        value as u32
    }
}

impl RangeFamily for IPv6 {
    type Addr = u128;

    const VERSION: IpVer = IpVer::V6;

    fn zero() -> Self::Addr {
        0
    }

    fn validate_ip(ip: &str) -> bool {
        ipv6::validate_ip(ip)
    }

    fn validate_cidr(cidr: &str) -> bool {
        ipv6::validate_cidr(cidr)
    }

    fn parse_single(ip: &str) -> Result<Self::Addr> {
        ipv6::ip2long(ip)
    }

    fn parse_cidr(cidr: &str) -> Result<(Self::Addr, Self::Addr)> {
        let (start, end) = ipv6::cidr2block(cidr)?;
        Ok((ipv6::ip2long(&start)?, ipv6::ip2long(&end)?))
    }

    fn format_addr(addr: Self::Addr) -> alloc::string::String {
        ipv6::long2ip(addr, false)
    }

    fn invalid_ip_error() -> Error {
        Error::V6IP()
    }

    fn checked_add_one(value: Self::Addr) -> Option<Self::Addr> {
        value.checked_add(1)
    }

    fn wrapping_add_one(value: Self::Addr) -> Self::Addr {
        value.wrapping_add(1)
    }

    fn checked_sub_one(value: Self::Addr) -> Self::Addr {
        value.saturating_sub(1)
    }

    fn len(start: Self::Addr, end: Self::Addr) -> Self::Addr {
        end - start + 1
    }

    fn remaining(end: Self::Addr, iter: Self::Addr) -> Self::Addr {
        end.saturating_sub(iter)
    }

    fn size_hint(remaining: Self::Addr) -> (usize, Option<usize>) {
        // For IPv6, ranges can be massive (up to 2^128)
        // Cap at usize::MAX for size_hint
        if remaining > usize::MAX as u128 {
            (usize::MAX, None)
        } else {
            let remaining_usize = remaining as usize;
            (remaining_usize, Some(remaining_usize))
        }
    }

    fn reserved_blocks() -> &'static [(Self::Addr, Self::Addr)] {
        &RESERVED_IPV6_BLOCKS
    }

    fn from_u128(value: u128) -> Self::Addr {
        value
    }
}

#[cfg(feature = "std")]
impl IpRange<IPv4> {
    /// Checks whether a [`std::net::Ipv4Addr`] lies inside this IPv4 range.
    pub fn contains_ipv4(&self, addr: StdIpv4Addr) -> bool {
        self.contains_addr(u32::from(addr))
    }

    /// Checks whether the inclusive [`std::net::Ipv4Addr`] bounds lie inside this range.
    pub fn contains_ipv4_bounds(&self, start: StdIpv4Addr, end: StdIpv4Addr) -> bool {
        self.contains_range(u32::from(start), u32::from(end))
    }

    /// Checks whether a [`std::net::IpAddr`] lies inside this IPv4 range.
    pub fn contains_ipaddr(&self, addr: StdIpAddr) -> bool {
        match addr {
            StdIpAddr::V4(v4) => self.contains_ipv4(v4),
            StdIpAddr::V6(_) => false,
        }
    }
}

#[cfg(feature = "std")]
impl IpRange<IPv6> {
    /// Checks whether a [`std::net::Ipv6Addr`] lies inside this IPv6 range.
    pub fn contains_ipv6(&self, addr: StdIpv6Addr) -> bool {
        self.contains_addr(u128::from(addr))
    }

    /// Checks whether the inclusive [`std::net::Ipv6Addr`] bounds lie inside this range.
    pub fn contains_ipv6_bounds(&self, start: StdIpv6Addr, end: StdIpv6Addr) -> bool {
        self.contains_range(u128::from(start), u128::from(end))
    }

    /// Checks whether a [`std::net::IpAddr`] lies inside this IPv6 range.
    pub fn contains_ipaddr(&self, addr: StdIpAddr) -> bool {
        match addr {
            StdIpAddr::V6(v6) => self.contains_ipv6(v6),
            StdIpAddr::V4(_) => false,
        }
    }
}

#[cfg(test)]
mod tests;
