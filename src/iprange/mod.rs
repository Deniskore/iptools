// Copyright (c) 2025 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT
use crate::error::{Error, Result};
use crate::ipv4;
use crate::ipv6;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::iter::FusedIterator;
use core::marker::PhantomData;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::net::{IpAddr as StdIpAddr, Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr};
#[cfg(feature = "std")]
use std::sync::OnceLock;

#[cfg(feature = "std")]
static RESERVED_IPV4_BLOCKS: OnceLock<alloc::vec::Vec<(u32, u32)>> = OnceLock::new();
#[cfg(feature = "std")]
static RESERVED_IPV6_BLOCKS: OnceLock<alloc::vec::Vec<(u128, u128)>> = OnceLock::new();

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

/// Parsed target bounds used by [`RangeFamily`] containment helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ParsedTarget<Addr> {
    start: Addr,
    end: Addr,
    is_range: bool,
}

impl<Addr> ParsedTarget<Addr> {
    #[inline(always)]
    fn new(start: Addr, end: Addr, is_range: bool) -> Self {
        Self {
            start,
            end,
            is_range,
        }
    }
}

pub(crate) type ParsedTargetResult<Addr> = Result<Option<ParsedTarget<Addr>>>;

mod private {
    use super::{ParsedTargetResult, RangeFamily};

    pub(crate) trait Sealed: Sized {
        fn parse_target(ip: &str) -> ParsedTargetResult<<Self as RangeFamily>::Addr>
        where
            Self: RangeFamily;

        fn is_reserved_range(
            start: <Self as RangeFamily>::Addr,
            end: <Self as RangeFamily>::Addr,
        ) -> bool
        where
            Self: RangeFamily;
    }
}

/// A generic IP address range.
///
/// Use [`IPv4`] or [`IPv6`] markers to specify the IP version.
///
/// [`IpRange::new`] creates inclusive numeric ranges. When the second argument
/// is present, it is a closing address, not a netmask. Use CIDR input or convert
/// dotted netmask input with [`ipv4::subnet2block`] before constructing a range.
///
/// The internal length counters are `u32` (IPv4) and `u128` (IPv6). A range that
/// spans the entire address space cannot be represented because its length is
/// one larger than the address type can hold, so construction returns an error.
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

#[allow(private_bounds)]
pub trait RangeFamily: private::Sealed {
    type Addr: Copy + Ord + Hash + 'static;

    const VERSION: IpVer;

    fn zero() -> Self::Addr;
    fn validate_ip(ip: &str) -> bool;
    fn validate_cidr(cidr: &str) -> bool;
    fn parse_single(ip: &str) -> Result<Self::Addr>;
    fn parse_cidr(cidr: &str) -> Result<(Self::Addr, Self::Addr)>;
    fn block_bounds(addr: Self::Addr, prefix: u8) -> Result<(Self::Addr, Self::Addr)>;
    fn format_addr(addr: Self::Addr) -> alloc::string::String;
    fn invalid_ip_error() -> Error;
    fn invalid_range_error() -> Error;
    fn checked_add_one(value: Self::Addr) -> Option<Self::Addr>;
    fn wrapping_add_one(value: Self::Addr) -> Self::Addr;
    fn wrapping_add_usize(value: Self::Addr, n: usize) -> Self::Addr;
    fn checked_sub_one(value: Self::Addr) -> Self::Addr;
    fn len(start: Self::Addr, end: Self::Addr) -> Self::Addr;
    fn remaining(end: Self::Addr, iter: Self::Addr) -> Self::Addr;
    fn inclusive_size_hint(distance_to_end: Self::Addr) -> (usize, Option<usize>);
    fn size_hint(remaining: Self::Addr) -> (usize, Option<usize>);
}

const IPV4_MAPPED_START: u128 = 0x0000_0000_0000_0000_0000_FFFF_0000_0000;
const IPV4_MAPPED_END: u128 = 0x0000_0000_0000_0000_0000_FFFF_FFFF_FFFF;

fn parse_endpoint<T: RangeFamily>(value: &str, want_start: bool) -> Result<T::Addr> {
    if value.as_bytes().contains(&b'/') {
        let (start, end) = T::parse_cidr(value)?;
        return Ok(if want_start { start } else { end });
    }
    T::parse_single(value).map_err(|_| T::invalid_ip_error())
}

#[inline]
fn parse_v4_target(target: &str) -> Result<(u32, u32, bool)> {
    if target.as_bytes().contains(&b'/') {
        let (start, end) = ipv4::cidr_bounds(target)?;
        Ok((start, end, true))
    } else {
        let addr = ipv4::ip2long(target)?;
        Ok((addr, addr, false))
    }
}

#[inline]
fn parse_v6_target(target: &str) -> Result<(u128, u128, bool)> {
    if target.as_bytes().contains(&b'/') {
        let (start, end) = ipv6::cidr_bounds(target)?;
        Ok((start, end, true))
    } else {
        let addr = ipv6::ip2long(target)?;
        Ok((addr, addr, false))
    }
}

#[inline]
fn reserved_v4_bounds(range: &str) -> Option<(u32, u32)> {
    if range.as_bytes().contains(&b'/') {
        ipv4::cidr_bounds(range).ok()
    } else {
        let addr = ipv4::ip2long(range).ok()?;
        Some((addr, addr))
    }
}

#[inline]
fn reserved_v6_bounds(range: &str) -> Option<(u128, u128)> {
    if range.as_bytes().contains(&b'/') {
        ipv6::cidr_bounds(range).ok()
    } else {
        let addr = ipv6::ip2long(range).ok()?;
        Some((addr, addr))
    }
}

#[inline]
fn is_reserved_v4_range(start: u32, end: u32) -> bool {
    #[cfg(feature = "std")]
    let blocks = RESERVED_IPV4_BLOCKS.get_or_init(|| {
        ipv4::RESERVED_RANGES
            .iter()
            .filter_map(|&range| reserved_v4_bounds(range))
            .collect()
    });

    #[cfg(feature = "std")]
    return blocks
        .iter()
        .any(|&(block_start, block_end)| block_start <= start && end <= block_end);

    #[cfg(not(feature = "std"))]
    ipv4::RESERVED_RANGES.iter().any(|&range| {
        reserved_v4_bounds(range)
            .is_some_and(|(block_start, block_end)| block_start <= start && end <= block_end)
    })
}

#[inline]
fn is_reserved_v6_range(start: u128, end: u128) -> bool {
    #[cfg(feature = "std")]
    let blocks = RESERVED_IPV6_BLOCKS.get_or_init(|| {
        ipv6::RESERVED_RANGES
            .iter()
            .filter_map(|&range| reserved_v6_bounds(range))
            .collect()
    });

    #[cfg(feature = "std")]
    return blocks
        .iter()
        .any(|&(block_start, block_end)| block_start <= start && end <= block_end);

    #[cfg(not(feature = "std"))]
    ipv6::RESERVED_RANGES.iter().any(|&range| {
        reserved_v6_bounds(range)
            .is_some_and(|(block_start, block_end)| block_start <= start && end <= block_end)
    })
}

#[cfg(test)]
#[allow(dead_code)]
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

#[cfg(test)]
impl TargetRange {
    fn parse(ip: &str) -> Result<Self> {
        let bytes = ip.as_bytes();
        if bytes.contains(&b':') {
            let (start, end, is_range) = parse_v6_target(ip)?;
            return Ok(Self::V6 {
                start,
                end,
                is_range,
            });
        }

        let (start, end, is_range) = if bytes.contains(&b'/') {
            parse_v4_target(ip)?
        } else {
            parse_v4_target(ip).map_err(|_| Error::UnknownVersion())?
        };
        Ok(Self::V4 {
            start,
            end,
            is_range,
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
    /// `start` accepts a single IP (`"10.0.0.1"`) or a CIDR (`"10.0.0.0/24"`).
    /// Pass an empty `end` when `start` already describes the whole range or
    /// when you want a single-address range.
    ///
    /// When `end` is non-empty, the two arguments are inclusive bounds: `start`
    /// is the lower endpoint and `end` is the upper endpoint. The constructor
    /// does **not** treat `end` as a dotted netmask. For example,
    /// `IpRange::<IPv4>::new("10.42.120.90", "255.255.252.0")` spans every
    /// address from `10.42.120.90` through `255.255.252.0`; it does not create
    /// the subnet `10.42.120.90/255.255.252.0`. If you have an address plus
    /// netmask, convert it to CIDR or concrete block bounds first.
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
    /// let block = ipv4::subnet2block("10.42.120.90/255.255.252.0").unwrap();
    /// let cidr = IpRange::<IPv4>::new("10.42.120.0/22", "")?;
    /// let explicit = IpRange::<IPv4>::new(&block.0, &block.1)?;
    /// assert_eq!(cidr.len(), explicit.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(start: &str, end: &str) -> Result<IpRange<T>> {
        let (start_ip, end_ip) = if end.is_empty() {
            if start.as_bytes().contains(&b'/') {
                T::parse_cidr(start)?
            } else {
                let ip = T::parse_single(start)?;
                (ip, ip)
            }
        } else {
            (
                parse_endpoint::<T>(start, true)?,
                parse_endpoint::<T>(end, false)?,
            )
        };

        // Unlike Python iptools, reversed bounds are rejected.
        Self::from_bounds(start_ip, end_ip)
    }

    /// Creates a new IP range from inclusive raw numeric bounds.
    ///
    /// This skips all string parsing and is the fastest constructor when
    /// callers already have numeric addresses.
    ///
    /// # Examples
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let range = IpRange::<IPv4>::from_bounds(0x0a00_0000, 0x0a00_00ff)?;
    /// assert_eq!(range.len(), 256);
    /// # Ok(())
    /// # }
    /// ```
    #[inline(always)]
    pub fn from_bounds(start_ip: T::Addr, end_ip: T::Addr) -> Result<IpRange<T>> {
        // Unlike Python iptools, reversed bounds are rejected.
        if start_ip > end_ip {
            return Err(T::invalid_range_error());
        }
        let len = T::len(start_ip, end_ip);
        if len == T::zero() && start_ip != end_ip {
            return Err(T::invalid_range_error());
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

    /// Creates a new IP range from a raw numeric address and CIDR prefix.
    ///
    /// This computes the containing CIDR block without parsing or formatting
    /// any strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let range = IpRange::<IPv4>::from_addr_prefix(0x0a00_0102, 16)?;
    /// assert_eq!(range.bounds(), (0x0a00_0000, 0x0a00_ffff));
    /// # Ok(())
    /// # }
    /// ```
    #[inline(always)]
    pub fn from_addr_prefix(addr: T::Addr, prefix: u8) -> Result<IpRange<T>> {
        let (start_ip, end_ip) = T::block_bounds(addr, prefix)?;
        Self::from_bounds(start_ip, end_ip)
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

    /// Returns the next address as a numeric value without string allocation.
    #[inline(always)]
    pub fn next_addr(&mut self) -> Option<T::Addr> {
        if self.ip_range.remaining == T::zero() {
            return None;
        }

        let out = self.ip_range.next_ip;
        self.ip_range.next_ip = T::wrapping_add_one(out);
        self.ip_range.remaining = T::checked_sub_one(self.ip_range.remaining);
        Some(out)
    }

    /// Iterates over raw numeric addresses without allocating intermediate strings.
    #[inline(always)]
    pub fn for_each_addr<F>(&self, mut f: F)
    where
        F: FnMut(T::Addr),
    {
        if self.ip_range.len == T::zero() {
            return;
        }

        let end = self.ip_range.end_ip;
        let mut current = self.ip_range.start_ip;
        loop {
            f(current);
            if current == end {
                break;
            }
            current = T::wrapping_add_one(current);
        }
    }

    #[inline]
    fn parse_target_for_family(ip: &str) -> ParsedTargetResult<T::Addr> {
        <T as private::Sealed>::parse_target(ip)
    }

    /// Checks whether an IP address or CIDR block sits fully inside this range.
    ///
    /// `contains` performs a straight numeric comparison against this range's
    /// existing inclusive bounds. The requested IP, or both endpoints of the
    /// requested CIDR block, must fall inside the range. Nothing else is
    /// inferred from how the range was constructed.
    ///
    /// When you already have parsed numeric values (e.g., from [`std::net::Ipv4Addr`]
    /// or [`std::net::Ipv6Addr`]), use [`IpRange::contains_addr`] or
    /// [`IpRange::contains_range`] to skip the parsing overhead.
    /// For strict same-family string parsing with mismatch-as-error semantics,
    /// use `contains_strict` on `IpRange<IPv4>` or `IpRange<IPv6>`.
    /// Valid targets from the other IP family return `Ok(false)`, except that
    /// IPv4 ranges accept IPv4-mapped IPv6 targets such as `::ffff:192.0.2.1`.
    ///
    /// This matters when the range was created from two strings. For example,
    /// `IpRange::<IPv4>::new("10.42.120.90", "255.255.252.0")` means every
    /// address from `10.42.120.90` through `255.255.252.0`, so it contains
    /// `192.168.44.10`. To model `10.42.120.90/255.255.252.0`, convert the
    /// subnet to its real block bounds as shown below. The same inclusive-bound
    /// rule applies to IPv6: `IpRange::<IPv6>::new("fd00:10::", "fd00:ffff::")`
    /// contains `fd00:8000::1`; use CIDR input such as `"fd00:10::/64"` when
    /// you want IPv6 subnet semantics.
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
    ///
    /// ```
    /// use iptools::{iprange::{IpRange, IPv4}, ipv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let bounded_range = IpRange::<IPv4>::new("10.42.120.90", "255.255.252.0")?;
    /// assert!(bounded_range.contains("192.168.44.10")?);
    ///
    /// let block = ipv4::subnet2block("10.42.120.90/255.255.252.0").unwrap();
    /// let subnet = IpRange::<IPv4>::new(&block.0, &block.1)?;
    /// assert!(!subnet.contains("192.168.44.10")?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv6};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let bounded_range = IpRange::<IPv6>::new("fd00:10::", "fd00:ffff::")?;
    /// assert!(bounded_range.contains("fd00:8000::1")?);
    ///
    /// let subnet = IpRange::<IPv6>::new("fd00:10::/64", "")?;
    /// assert!(!subnet.contains("fd00:8000::1")?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn contains(&self, ip: &str) -> Result<bool> {
        let Some(target) = Self::parse_target_for_family(ip)? else {
            return Ok(false);
        };
        if target.is_range {
            Ok(self.contains_range(target.start, target.end))
        } else {
            Ok(self.contains_addr(target.start))
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
        let Some(target) = Self::parse_target_for_family(ip)? else {
            return Ok(false);
        };
        Ok(<T as private::Sealed>::is_reserved_range(
            target.start,
            target.end,
        ))
    }
}

/// Iterator over raw IP addresses.
pub struct AddrIterator<T: RangeFamily> {
    next: Option<T::Addr>,
    end: T::Addr,
    _marker: PhantomData<T>,
}

/// Lightweight adapter over numeric addresses with on-demand string formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddrView<T: RangeFamily> {
    addr: T::Addr,
    _marker: PhantomData<T>,
}

impl<T: RangeFamily> AddrView<T> {
    #[inline(always)]
    fn new(addr: T::Addr) -> Self {
        Self {
            addr,
            _marker: PhantomData,
        }
    }

    /// Returns the raw numeric address value.
    #[inline(always)]
    pub fn raw(self) -> T::Addr {
        self.addr
    }

    /// Formats the address into its canonical textual representation.
    #[inline(always)]
    pub fn to_ip_string(self) -> alloc::string::String {
        T::format_addr(self.addr)
    }
}

impl fmt::Display for AddrView<IPv4> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ipv4::fmt_long2ip(f, self.addr)
    }
}

impl fmt::Display for AddrView<IPv6> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ipv6::fmt_long2ip(f, self.addr)
    }
}

/// Iterator over [`AddrView`] values.
pub struct AddrViewIterator<T: RangeFamily> {
    inner: AddrIterator<T>,
}

impl<T: RangeFamily> Iterator for AddrViewIterator<T> {
    type Item = AddrView<T>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(AddrView::new)
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }

    #[inline(always)]
    fn count(self) -> usize {
        self.inner.count()
    }

    #[inline(always)]
    fn last(self) -> Option<Self::Item> {
        self.inner.last().map(AddrView::new)
    }

    #[inline(always)]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.inner.nth(n).map(AddrView::new)
    }

    #[inline(always)]
    fn fold<B, F>(self, init: B, mut f: F) -> B
    where
        F: FnMut(B, Self::Item) -> B,
    {
        self.inner
            .fold(init, |acc, addr| f(acc, AddrView::new(addr)))
    }
}

impl<T: RangeFamily> FusedIterator for AddrViewIterator<T> {}
impl ExactSizeIterator for AddrViewIterator<IPv4> {}

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
            Some(current) => T::inclusive_size_hint(T::remaining(self.end, current)),
        }
    }

    #[inline(always)]
    fn count(self) -> usize {
        match self.next {
            None => 0,
            Some(current) => {
                let (lo, _) = T::inclusive_size_hint(T::remaining(self.end, current));
                lo
            }
        }
    }

    #[inline(always)]
    fn last(self) -> Option<Self::Item> {
        self.next.map(|_| self.end)
    }

    #[inline(always)]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        let current = self.next?;
        let remaining = T::remaining(self.end, current);
        let (_, upper) = T::inclusive_size_hint(remaining);
        if let Some(count) = upper {
            if n >= count {
                self.next = None;
                return None;
            }
        }
        let target = T::wrapping_add_usize(current, n);
        if target < current || target > self.end {
            self.next = None;
            return None;
        }
        self.next = if target == self.end {
            None
        } else {
            Some(T::wrapping_add_one(target))
        };
        Some(target)
    }

    #[inline(always)]
    fn fold<B, F>(self, init: B, mut f: F) -> B
    where
        F: FnMut(B, Self::Item) -> B,
    {
        let Some(mut current) = self.next else {
            return init;
        };

        let end = self.end;
        let mut acc = init;
        loop {
            acc = f(acc, current);
            if current == end {
                break;
            }
            current = T::wrapping_add_one(current);
        }
        acc
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
    #[inline(always)]
    pub fn addrs(&self) -> AddrIterator<T> {
        AddrIterator {
            next: Some(self.ip_range.start_ip),
            end: self.ip_range.end_ip,
            _marker: PhantomData,
        }
    }

    /// Returns an iterator over [`AddrView`] wrappers (numeric value + on-demand formatting).
    ///
    /// # Example
    ///
    /// ```
    /// use iptools::iprange::{IpRange, IPv4};
    ///
    /// # fn main() -> iptools::error::Result<()> {
    /// let range = IpRange::<IPv4>::new("10.0.0.1", "10.0.0.2")?;
    /// let views = range.addrs_view().collect::<Vec<_>>();
    /// assert_eq!(views[0].raw(), 167772161);
    /// assert_eq!(views[1].to_ip_string(), "10.0.0.2");
    /// # Ok(())
    /// # }
    /// ```
    #[inline(always)]
    pub fn addrs_view(&self) -> AddrViewIterator<T> {
        AddrViewIterator {
            inner: self.addrs(),
        }
    }
}

impl<T: RangeFamily> Iterator for IpRange<T> {
    type Item = alloc::string::String;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.next_addr().map(T::format_addr)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        T::size_hint(self.ip_range.remaining)
    }

    #[inline(always)]
    fn count(self) -> usize {
        let (lo, _) = T::size_hint(self.ip_range.remaining);
        lo
    }

    #[inline(always)]
    fn last(self) -> Option<Self::Item> {
        if self.ip_range.remaining == T::zero() {
            None
        } else {
            Some(T::format_addr(self.ip_range.end_ip))
        }
    }

    #[inline(always)]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        if self.ip_range.remaining == T::zero() {
            return None;
        }
        let current = self.ip_range.next_ip;
        let remaining = self.ip_range.remaining;
        let (_, upper) = T::size_hint(remaining);
        if let Some(count) = upper {
            if n >= count {
                self.ip_range.remaining = T::zero();
                return None;
            }
        }
        let target = T::wrapping_add_usize(current, n);
        if target < current || target > self.ip_range.end_ip {
            self.ip_range.remaining = T::zero();
            return None;
        }
        self.ip_range.next_ip = T::wrapping_add_one(target);
        self.ip_range.remaining = T::remaining(self.ip_range.end_ip, target);
        Some(T::format_addr(target))
    }

    #[inline(always)]
    fn fold<B, F>(self, init: B, mut f: F) -> B
    where
        F: FnMut(B, Self::Item) -> B,
    {
        if self.ip_range.remaining == T::zero() {
            return init;
        }

        let end = self.ip_range.end_ip;
        let mut current = self.ip_range.next_ip;
        let mut acc = init;
        loop {
            acc = f(acc, T::format_addr(current));
            if current == end {
                break;
            }
            current = T::wrapping_add_one(current);
        }
        acc
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

impl private::Sealed for IPv4 {
    fn parse_target(ip: &str) -> ParsedTargetResult<u32> {
        let bytes = ip.as_bytes();
        if bytes.contains(&b':') {
            let (start, end, is_range) = parse_v6_target(ip)?;
            if start >= IPV4_MAPPED_START && end <= IPV4_MAPPED_END {
                Ok(Some(ParsedTarget::new(
                    (start & u128::from(u32::MAX)) as u32,
                    (end & u128::from(u32::MAX)) as u32,
                    is_range,
                )))
            } else {
                Ok(None)
            }
        } else {
            let (start, end, is_range) = parse_v4_target(ip)?;
            Ok(Some(ParsedTarget::new(start, end, is_range)))
        }
    }

    fn is_reserved_range(start: u32, end: u32) -> bool {
        is_reserved_v4_range(start, end)
    }
}

impl RangeFamily for IPv4 {
    type Addr = u32;

    const VERSION: IpVer = IpVer::V4;

    #[inline(always)]
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
        ipv4::cidr_bounds(cidr)
    }

    #[inline(always)]
    fn block_bounds(addr: Self::Addr, prefix: u8) -> Result<(Self::Addr, Self::Addr)> {
        ipv4::block_bounds(addr, u32::from(prefix))
    }

    fn format_addr(addr: Self::Addr) -> alloc::string::String {
        ipv4::long2ip(addr)
    }

    fn invalid_ip_error() -> Error {
        Error::V4IP()
    }

    #[inline(always)]
    fn invalid_range_error() -> Error {
        Error::V4Subnet()
    }

    fn checked_add_one(value: Self::Addr) -> Option<Self::Addr> {
        value.checked_add(1)
    }

    #[inline(always)]
    fn wrapping_add_one(value: Self::Addr) -> Self::Addr {
        value.wrapping_add(1)
    }

    #[inline(always)]
    fn wrapping_add_usize(value: Self::Addr, n: usize) -> Self::Addr {
        value.wrapping_add(n as u32)
    }

    fn checked_sub_one(value: Self::Addr) -> Self::Addr {
        value.saturating_sub(1)
    }

    #[inline(always)]
    fn len(start: Self::Addr, end: Self::Addr) -> Self::Addr {
        end.wrapping_sub(start).wrapping_add(1)
    }

    #[inline(always)]
    fn remaining(end: Self::Addr, iter: Self::Addr) -> Self::Addr {
        end.saturating_sub(iter)
    }

    fn inclusive_size_hint(distance_to_end: Self::Addr) -> (usize, Option<usize>) {
        let count = u64::from(distance_to_end) + 1;
        if count > usize::MAX as u64 {
            (usize::MAX, None)
        } else {
            let count = count as usize;
            (count, Some(count))
        }
    }

    fn size_hint(remaining: Self::Addr) -> (usize, Option<usize>) {
        let remaining_usize = remaining as usize;
        (remaining_usize, Some(remaining_usize))
    }
}

impl private::Sealed for IPv6 {
    fn parse_target(ip: &str) -> ParsedTargetResult<u128> {
        let bytes = ip.as_bytes();
        if bytes.contains(&b':') {
            let (start, end, is_range) = parse_v6_target(ip)?;
            Ok(Some(ParsedTarget::new(start, end, is_range)))
        } else {
            match parse_v4_target(ip) {
                Ok(_) => Ok(None),
                Err(err) => Err(err),
            }
        }
    }

    fn is_reserved_range(start: u128, end: u128) -> bool {
        is_reserved_v6_range(start, end)
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
        ipv6::cidr_bounds(cidr)
    }

    fn block_bounds(addr: Self::Addr, prefix: u8) -> Result<(Self::Addr, Self::Addr)> {
        ipv6::block_bounds(addr, prefix)
    }

    fn format_addr(addr: Self::Addr) -> alloc::string::String {
        ipv6::long2ip(addr, false)
    }

    fn invalid_ip_error() -> Error {
        Error::V6IP()
    }

    fn invalid_range_error() -> Error {
        Error::V6Subnet()
    }

    fn checked_add_one(value: Self::Addr) -> Option<Self::Addr> {
        value.checked_add(1)
    }

    #[inline(always)]
    fn wrapping_add_one(value: Self::Addr) -> Self::Addr {
        value.wrapping_add(1)
    }

    #[inline(always)]
    fn wrapping_add_usize(value: Self::Addr, n: usize) -> Self::Addr {
        value.wrapping_add(n as u128)
    }

    fn checked_sub_one(value: Self::Addr) -> Self::Addr {
        value.saturating_sub(1)
    }

    fn len(start: Self::Addr, end: Self::Addr) -> Self::Addr {
        end.wrapping_sub(start).wrapping_add(1)
    }

    #[inline(always)]
    fn remaining(end: Self::Addr, iter: Self::Addr) -> Self::Addr {
        end.saturating_sub(iter)
    }

    fn inclusive_size_hint(distance_to_end: Self::Addr) -> (usize, Option<usize>) {
        match distance_to_end.checked_add(1) {
            Some(count) => Self::size_hint(count),
            None => (usize::MAX, None),
        }
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
}

impl IpRange<IPv4> {
    /// Fast-path strict containment for IPv4 string targets (single IP or CIDR).
    ///
    /// This avoids cross-family auto-detection and parses only IPv4 syntax.
    /// Unlike [`IpRange::contains`], family-mismatched input returns an error.
    #[inline]
    pub fn contains_strict(&self, target: &str) -> Result<bool> {
        let (start, end, is_range) = parse_v4_target(target)?;
        if is_range {
            Ok(self.contains_range(start, end))
        } else {
            Ok(self.contains_addr(start))
        }
    }

    /// Iterates over formatted IPv4 addresses using one reused scratch string.
    ///
    /// The `&str` passed to the callback is valid only for the duration of that
    /// callback invocation. Use this when you need textual addresses but want
    /// to avoid allocating a new `String` for every address.
    pub fn for_each_ip_str<F>(&self, mut f: F)
    where
        F: FnMut(&str),
    {
        let mut text = alloc::string::String::with_capacity(15);
        self.for_each_addr(|addr| {
            text.clear();
            ipv4::push_long2ip(&mut text, addr);
            f(text.as_str());
        });
    }
}

impl IpRange<IPv6> {
    /// Fast-path strict containment for IPv6 string targets (single IP or CIDR).
    ///
    /// This avoids cross-family auto-detection and parses only IPv6 syntax.
    /// Unlike [`IpRange::contains`], family-mismatched input returns an error.
    #[inline]
    pub fn contains_strict(&self, target: &str) -> Result<bool> {
        let (start, end, is_range) = parse_v6_target(target)?;
        if is_range {
            Ok(self.contains_range(start, end))
        } else {
            Ok(self.contains_addr(start))
        }
    }

    /// Iterates over formatted IPv6 addresses using one reused scratch string.
    ///
    /// The `&str` passed to the callback is valid only for the duration of that
    /// callback invocation. Use this when you need textual addresses but want
    /// to avoid allocating a new `String` for every address.
    pub fn for_each_ip_str<F>(&self, mut f: F)
    where
        F: FnMut(&str),
    {
        let mut text = alloc::string::String::with_capacity(39);
        self.for_each_addr(|addr| {
            text.clear();
            ipv6::push_long2ip(&mut text, addr);
            f(text.as_str());
        });
    }
}

#[cfg(feature = "std")]
impl IpRange<IPv4> {
    /// Checks whether a [`std::net::Ipv4Addr`] lies inside this IPv4 range.
    #[inline(always)]
    pub fn contains_ipv4(&self, addr: StdIpv4Addr) -> bool {
        let addr = u32::from(addr);
        let start = self.ip_range.start_ip;
        addr.wrapping_sub(start) < self.ip_range.len
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
    #[inline(always)]
    pub fn contains_ipv6(&self, addr: StdIpv6Addr) -> bool {
        let addr = u128::from(addr);
        let start = self.ip_range.start_ip;
        addr.wrapping_sub(start) < self.ip_range.len
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
