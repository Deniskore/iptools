// Copyright (c) 2020 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT

use crate::iprange::Error::{UnknownVersion, V4Subnet, V4CIDR, V6CIDR};
use crate::iprange::IpVer::*;
use crate::ipv4;
use crate::ipv6;
use core::fmt;
use std::fmt::Display;
use std::hash::{Hash, Hasher};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    V4CIDR(),
    V6CIDR(),
    V4Subnet(),
    UnknownVersion(),
}

impl Clone for Error {
    fn clone(&self) -> Self {
        use self::Error::*;

        match self {
            V4CIDR() => V4CIDR(),
            V6CIDR() => V6CIDR(),
            V4Subnet() => V4Subnet(),
            UnknownVersion() => UnknownVersion(),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        use self::Error::*;

        match *self {
            V4CIDR() => "Couldn't validate CIDR ipv4::cidr2block",
            V6CIDR() => "Couldn't validate CIDR ipv6::cidr2block",
            V4Subnet() => "Couldn't validate subnet ipv4::cidr2block",
            UnknownVersion() => "Couldn't detect IP version",
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        use self::Error::*;

        match *self {
            V4CIDR() => write!(f, "Couldn't validate CIDR ipv4::cidr2block",),
            V6CIDR() => write!(f, "Couldn't validate CIDR ipv6::cidr2block"),
            V4Subnet() => write!(f, "Couldn't validate subnet ipv4::cidr2block"),
            UnknownVersion() => write!(f, "Couldn't detect IP version"),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum IpVer {
    IPVUnknown,
    IPV4,
    IPV6,
}

#[derive(Debug, Clone)]
pub struct IpRange {
    ip_version: IpVer,
    start_ip: u128,
    end_ip: u128,
    length: u128,
    iter_ip: u128,
}

impl Iterator for IpRange {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.iter_ip == self.end_ip {
            return None;
        }
        if let Some(ip) = self.iter_ip.checked_add(1) {
            if ip <= self.end_ip {
                self.iter_ip = ip;
            } else {
                return None;
            }
            if ip > self.start_ip && ip <= self.end_ip {
                self.start_ip = self.iter_ip;
            }

            return match self.ip_version {
                IPV4 => Some(ipv4::long2ip(ip as u32)),
                IPV6 => Some(ipv6::long2ip(ip, false)),
                IPVUnknown => None,
            };
        }
        None
    }
}

impl Hash for IpRange {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.start_ip.hash(state);
        self.end_ip.hash(state);
    }
}

impl PartialEq for IpRange {
    fn eq(&self, other: &Self) -> bool {
        self.start_ip == other.start_ip && self.end_ip == other.end_ip
    }
}

// Converts a string address to a numeric value
fn _address2long(address: &str, ip_ver: IpVer) -> Option<u128> {
    match ip_ver {
        IPV4 => {
            if let Some(ip_long) = ipv4::ip2long(address) {
                Some(ip_long as u128)
            } else {
                None
            }
        }
        IPV6 => Some(ipv6::ip2long(address).unwrap()),
        _ => None,
    }
}

/// Provides range of ip addresses.
/// Converts a CIDR notation address, ip address and subnet, tuple of ip addresses or start and end addresses into iterable object
impl IpRange {
    pub fn new(_start: &str, _end: &str) -> Result<IpRange> {
        let mut start = _start.to_string();
        let mut end = _end.to_string();
        let mut ip_ver: IpVer = IPVUnknown;

        if _end.is_empty() {
            end = start.clone();
        }

        if ipv4::validate_cidr(_start) {
            let result = ipv4::cidr2block(_start);
            match result {
                Some(result) => {
                    ip_ver = IPV4;
                    start = result.0;
                    end = result.1;
                }
                None => {
                    return Err(V4CIDR());
                }
            }
        } else if ipv6::validate_cidr(_start) {
            let result = ipv6::cidr2block(_start);
            match result {
                Some(result) => {
                    ip_ver = IPV6;
                    start = result.0;
                    end = result.1;
                }
                None => {
                    return Err(V6CIDR());
                }
            }
        } else if ipv4::validate_subnet(_start) {
            let result = ipv4::subnet2block(_start);
            match result {
                Some(result) => {
                    ip_ver = IPV4;
                    start = result.0;
                    end = result.1;
                }
                None => {
                    return Err(V4Subnet());
                }
            }
        } else if ipv4::validate_ip(_start) {
            ip_ver = IPV4
        } else if ipv6::validate_ip(_start) {
            ip_ver = IPV6;
        }

        if ip_ver == IPVUnknown {
            return Err(UnknownVersion());
        }

        let start_ip = _address2long(&start, ip_ver.clone()).unwrap();
        let end_ip = _address2long(&end, ip_ver.clone()).unwrap();

        let iter_ip = start_ip.checked_sub(1).unwrap_or(start_ip);

        Ok(IpRange {
            ip_version: ip_ver,
            start_ip,
            end_ip,
            length: end_ip - start_ip + 1,
            iter_ip,
        })
    }

    /// Get current range as pair of strings
    pub fn get_range(&self) -> Option<(String, String)> {
        match self.ip_version {
            IPV4 => Some((
                ipv4::long2ip(self.start_ip as u32),
                ipv4::long2ip(self.end_ip as u32),
            )),
            IPV6 => Some((
                ipv6::long2ip(self.start_ip, false),
                ipv6::long2ip(self.end_ip, false),
            )),
            _ => None,
        }
    }
    /// Get current range as pair of u128
    pub fn get_range_long(&self) -> (u128, u128) {
        (self.start_ip, self.end_ip)
    }

    /// Get version for current range
    pub fn get_version(&self) -> IpVer {
        self.ip_version.clone()
    }

    /// Get length for inited range
    pub fn len(&self) -> u128 {
        self.length
    }

    /// Get length of current IP range
    pub fn len_cur(&self) -> u128 {
        if self.iter_ip == self.end_ip {
            return self.end_ip - self.iter_ip + 1;
        }
        self.end_ip - self.iter_ip
    }

    /// Check that the address is in the current range
    pub fn contains(&self, ip: &str) -> Result<bool> {
        let mut is_valid = false;
        let mut is_range = false;
        let mut addr = 0u128;
        let mut start_ip = 0u128;
        let mut end_ip = 0u128;
        if ipv4::validate_cidr(ip) {
            is_range = true;
            let tuple = ipv4::cidr2block(ip).unwrap();
            start_ip = _address2long(&tuple.0, IPV4).unwrap();
            end_ip = _address2long(&tuple.1, IPV4).unwrap();
            is_valid = true;
        } else if ipv6::validate_cidr(ip) {
            is_valid = true;
            is_range = true;
            let tuple = ipv6::cidr2block(ip).unwrap();
            start_ip = _address2long(&tuple.0, IPV6).unwrap();
            end_ip = _address2long(&tuple.1, IPV6).unwrap();
        } else if ipv6::validate_ip(ip) {
            is_valid = true;
            addr = _address2long(ip, IPV6).unwrap();
        } else if ipv4::validate_ip(ip) {
            is_valid = true;
            addr = _address2long(ip, IPV4).unwrap();
        }

        if !is_valid {
            return Err(UnknownVersion());
        }

        if !is_range {
            match self.ip_version {
                IPV4 => {
                    Ok(self.start_ip as u32 <= addr as u32 && addr as u32 <= self.end_ip as u32)
                }
                IPV6 => Ok(self.start_ip <= addr && addr <= self.end_ip),
                IPVUnknown => Err(UnknownVersion()),
            }
        } else {
            match self.ip_version {
                IPV4 => Ok(self.start_ip as u32 <= start_ip as u32
                    && start_ip as u32 <= self.end_ip as u32
                    && end_ip as u32 <= self.end_ip as u32),
                IPV6 => Ok(self.start_ip <= start_ip
                    && start_ip <= self.end_ip
                    && end_ip <= self.end_ip),
                IPVUnknown => Err(UnknownVersion()),
            }
        }
    }

    /// Check if ip addr is reserved/private
    pub fn is_reserved(ip: &str) -> Result<bool> {
        for i in ipv4::RESERVED_RANGES.lock().unwrap().iter() {
            if IpRange::new(*i, "")?.contains(ip)? {
                return Ok(true);
            }
        }

        for i in ipv6::RESERVED_RANGES.lock().unwrap().iter() {
            if IpRange::new(*i, "")?.contains(ip)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::iprange::IpRange;
    use crate::iprange::IpVer::{IPV4, IPV6};

    #[test]
    fn test_initialization() {
        assert_eq!(IpRange::new("127.0.0.1", "").unwrap().get_version(), IPV4);
        assert_eq!(
            IpRange::new("127.0.0.2", "127.255.255.255")
                .unwrap()
                .get_version(),
            IPV4
        );
        assert_eq!(IpRange::new("::1", "::2").unwrap().get_version(), IPV6);

        assert_eq!(IpRange::new("::1", "").unwrap().get_version(), IPV6);
    }

    #[test]
    fn test_get_range() {
        let x = IpRange::new("127.0.0.1/24", "").unwrap();
        let xx = IpRange::new("255.255.1.1/16", "").unwrap();
        let xxx = IpRange::new("127.0.0.1", "127.0.0.255").unwrap();
        assert_eq!(
            x.get_range(),
            Some(("127.0.0.0".to_string(), "127.0.0.255".to_string()))
        );
        assert_eq!(
            xx.get_range(),
            Some(("255.255.0.0".to_string(), "255.255.255.255".to_string()))
        );
        assert_eq!(
            xxx.get_range(),
            Some(("127.0.0.1".to_string(), "127.0.0.255".to_string()))
        );
    }

    #[test]
    fn test_len() {
        assert_eq!(IpRange::new("127.0.0.3", "127.0.0.4").unwrap().len(), 2);
        assert_eq!(
            IpRange::new("127.0.0.3", "127.0.255.4").unwrap().len(),
            65282
        );
        assert_eq!(
            IpRange::new("127.0.0.1", "255.255.255.255").unwrap().len(),
            2164260863
        );
        assert_eq!(IpRange::new("::1", "::2").unwrap().len(), 2);
        assert_eq!(
            IpRange::new("fe80::/10", "").unwrap().len(),
            332306998946228968225951765070086144
        );
    }

    #[test]
    fn test_contains() {
        let range = IpRange::new("127.0.0.3", "127.0.0.5").unwrap();
        assert_eq!(range.contains("127.0.0.3").unwrap(), true);
        assert_eq!(range.contains("127.0.0.4").unwrap(), true);
        assert_eq!(range.contains("127.0.0.5").unwrap(), true);
        assert_eq!(range.contains("::1").unwrap(), false);
        assert_eq!(range.contains("0:0:0:0:0:fff:7f00:4").unwrap(), true);
        assert_eq!(range.contains("0:0:0:0:0:fff:7f00:4/127").unwrap(), true);
        assert_eq!(range.contains("127.0.0.6").unwrap(), false);
        assert_eq!(range.contains("127.0.0.2").unwrap(), false);
    }

    #[test]
    fn test_equal() {
        assert_eq!(
            IpRange::new("127.0.0.0/8", "").unwrap(),
            IpRange::new("127.0.0.0", "127.255.255.255").unwrap()
        );
        assert_ne!(
            IpRange::new("127.0.0.0/8", "").unwrap(),
            IpRange::new("127.0.0.0", "127.255.255.254").unwrap()
        );
        assert_eq!(
            IpRange::new("::1/64", "").unwrap(),
            IpRange::new("::", "::ffff:ffff:ffff:ffff").unwrap()
        );
        assert_ne!(
            IpRange::new("::1/64", "").unwrap(),
            IpRange::new("::2", "::ffff:ffff:ffff:ffff").unwrap()
        );
    }

    #[test]
    fn test_next() {
        let mut a = IpRange::new("127/31", "").unwrap();
        assert_eq!(a.next().unwrap(), "127.0.0.0");
        assert_eq!(a.next().unwrap(), "127.0.0.1");
        assert_eq!(a.next(), None);
        let mut b = IpRange::new("::1", "::3").unwrap();
        assert_eq!(b.next().unwrap(), "::1");
        assert_eq!(b.next().unwrap(), "::2");
        assert_eq!(b.next().unwrap(), "::3");
        assert_eq!(b.next(), None);
        let mut c = IpRange::new("255.255.255.255", "").unwrap();
        assert_eq!(c.next().unwrap(), "255.255.255.255");
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_len_cur() {
        let mut a = IpRange::new("127/31", "").unwrap();
        assert_eq!(a.len_cur(), 2);
        a.next();
        assert_eq!(a.len_cur(), 1);
        a.next();
        assert_eq!(a.len_cur(), 1);
        let mut b = IpRange::new("::1", "::3").unwrap();
        assert_eq!(b.len_cur(), 3);
        b.next();
        b.next();
        assert_eq!(b.len_cur(), 1);
        b.next();
        b.next();
        assert_eq!(b.len_cur(), 1);
        let mut c = IpRange::new("255.255.255.255", "").unwrap();
        assert_eq!(c.len_cur(), 1);
        c.next();
        assert_eq!(c.len_cur(), 1);
    }

    #[test]
    fn test_is_reserved() {
        assert_eq!(IpRange::is_reserved("127.0.0.1").unwrap(), true);
        assert_eq!(IpRange::is_reserved(crate::ipv4::BROADCAST).unwrap(), true);
        assert_eq!(IpRange::is_reserved(crate::ipv4::LOOPBACK).unwrap(), true);
        assert_eq!(
            IpRange::is_reserved(crate::ipv4::IPV6_TO_IPV4_RELAY).unwrap(),
            true
        );
        assert_eq!(IpRange::is_reserved("8.8.8.8").unwrap(), false);
        assert_eq!(IpRange::is_reserved(crate::ipv6::LOOPBACK).unwrap(), true);

        assert_eq!(IpRange::is_reserved("123456").ok(), None);
    }

    #[test]
    fn test_constructor() {
        assert_eq!(IpRange::new("Bolognese", "").ok(), None);
    }

    #[test]
    #[should_panic]
    fn test_should_panic() {
        IpRange::new("12345678", "").unwrap();
    }
}
