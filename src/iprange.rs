// Copyright (c) 2022 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT

use crate::error::{Error, Result};
use crate::iprange::Error::UnknownVersion;
use crate::iprange::IpVer::*;
use crate::ipv4;
use crate::ipv6;
use std::hash::{Hash, Hasher};

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum IpVer {
    V4,
    V6,
    VUnknown,
}

#[derive(Debug, Clone)]
pub struct IPv4 {
    start_ip: u32,
    end_ip: u32,
    len: u32,
    iter_ip: u32,
}

#[derive(Debug, Clone)]
pub struct IPv6 {
    start_ip: u128,
    end_ip: u128,
    len: u128,
    iter_ip: u128,
}

impl IPv4 {
    fn new(start: u32, end: u32, iter_ip: u32) -> IPv4 {
        IPv4 {
            start_ip: start,
            end_ip: end,
            len: end - start + 1,
            iter_ip,
        }
    }
}

impl IPv6 {
    fn new(start: u128, end: u128, iter_ip: u128) -> IPv6 {
        IPv6 {
            start_ip: start,
            end_ip: end,
            len: end - start + 1,
            iter_ip,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpRange<T> {
    ip_version: IpVer,
    ip_range: T,
}

impl Iterator for IpRange<IPv4> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ip_range.iter_ip >= self.ip_range.end_ip {
            return None;
        }
        self.ip_range.iter_ip = self.ip_range.iter_ip.checked_add(1)?;
        Some(ipv4::long2ip(self.ip_range.iter_ip))
    }
}

impl Iterator for IpRange<IPv6> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ip_range.iter_ip >= self.ip_range.end_ip {
            return None;
        }
        self.ip_range.iter_ip = self.ip_range.iter_ip.checked_add(1)?;
        Some(ipv6::long2ip(self.ip_range.iter_ip, false))
    }
}

impl Hash for IPv4 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.start_ip.hash(state);
        self.end_ip.hash(state);
    }
}

impl Hash for IPv6 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.start_ip.hash(state);
        self.end_ip.hash(state);
    }
}

impl PartialEq for IpRange<IPv4> {
    fn eq(&self, other: &Self) -> bool {
        self.ip_range.start_ip == other.ip_range.start_ip
            && self.ip_range.end_ip == other.ip_range.end_ip
    }
}

impl PartialEq for IpRange<IPv6> {
    fn eq(&self, other: &Self) -> bool {
        self.ip_range.start_ip == other.ip_range.start_ip
            && self.ip_range.end_ip == other.ip_range.end_ip
    }
}

fn address2long_v4(address: &str) -> Result<u32> {
    ipv4::ip2long(address)
}

fn address2long_v6(address: &str) -> Result<u128> {
    ipv6::ip2long(address)
}

impl IpRange<IPv4> {
    pub fn new(start: &str, end: &str) -> Result<IpRange<IPv4>> {
        let mut end = end.to_string();

        if end.is_empty() {
            end = start.to_string();
        }

        let start_ip = if ipv4::validate_cidr(start) {
            let tuple = ipv4::cidr2block(start)?;
            address2long_v4(&tuple.0)?
        } else {
            address2long_v4(start)?
        };

        let end_ip = if end.is_empty() {
            start_ip
        } else if ipv4::validate_cidr(&end) {
            let tuple = ipv4::cidr2block(&end)?;
            address2long_v4(&tuple.1)?
        } else {
            address2long_v4(&end)?
        };

        if start_ip > end_ip {
            return Err(Error::V4Subnet());
        }

        let iter_ip = start_ip.checked_sub(1).unwrap_or(start_ip);

        Ok(IpRange {
            ip_version: V4,
            ip_range: IPv4::new(start_ip, end_ip, iter_ip),
        })
    }

    pub fn get_range(&self) -> Option<(String, String)> {
        Some((
            ipv4::long2ip(self.ip_range.start_ip),
            ipv4::long2ip(self.ip_range.end_ip),
        ))
    }

    pub fn get_range_long(&self) -> (u32, u32) {
        (self.ip_range.start_ip, self.ip_range.end_ip)
    }

    pub fn get_version(&self) -> IpVer {
        self.ip_version.clone()
    }

    pub fn len(&self) -> u32 {
        self.ip_range.len
    }

    pub fn is_empty(&self) -> bool {
        self.ip_range.len == 0
    }

    pub fn len_cur(&self) -> u32 {
        if self.ip_range.iter_ip == self.ip_range.end_ip {
            return self.ip_range.end_ip - self.ip_range.iter_ip + 1;
        }
        self.ip_range.end_ip - self.ip_range.iter_ip
    }

    pub fn contains(&self, ip: &str) -> Result<bool> {
        let mut is_valid = false;
        let mut is_range = false;
        let mut addr = 0u128;
        let mut start_ip = 0u128;
        let mut end_ip = 0u128;
        if ipv4::validate_cidr(ip) {
            is_range = true;
            let tuple = ipv4::cidr2block(ip)?;
            start_ip = address2long_v4(&tuple.0)? as u128;
            end_ip = address2long_v4(&tuple.1)? as u128;
            is_valid = true;
        } else if ipv6::validate_cidr(ip) {
            is_valid = true;
            is_range = true;
            let tuple = ipv6::cidr2block(ip)?;
            start_ip = address2long_v6(&tuple.0)?;
            end_ip = address2long_v6(&tuple.1)?;
        } else if ipv6::validate_ip(ip) {
            is_valid = true;
            addr = address2long_v6(ip)?;
        } else if ipv4::validate_ip(ip) {
            is_valid = true;
            addr = address2long_v4(ip)? as u128;
        }

        if !is_valid {
            return Err(UnknownVersion());
        }

        if !is_range {
            match self.ip_version {
                V4 => Ok(
                    self.ip_range.start_ip <= addr as u32 && addr as u32 <= self.ip_range.end_ip
                ),
                V6 => {
                    Ok(self.ip_range.start_ip as u128 <= addr
                        && addr <= self.ip_range.end_ip as u128)
                }
                VUnknown => Err(UnknownVersion()),
            }
        } else {
            match self.ip_version {
                V4 => Ok(self.ip_range.start_ip <= start_ip as u32
                    && start_ip as u32 <= self.ip_range.end_ip
                    && end_ip as u32 <= self.ip_range.end_ip),
                V6 => Ok(self.ip_range.start_ip as u128 <= start_ip
                    && start_ip <= self.ip_range.end_ip as u128
                    && end_ip <= self.ip_range.end_ip as u128),
                VUnknown => Err(UnknownVersion()),
            }
        }
    }

    fn is_reserved_ipv4(ip: &str) -> Result<bool> {
        for i in ipv4::RESERVED_RANGES.iter() {
            if IpRange::<IPv4>::new(i, "")?.contains(ip)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn is_reserved(ip: &str) -> Result<bool> {
        IpRange::is_reserved_ipv4(ip)
    }
}

impl IpRange<IPv6> {
    pub fn new(start: &str, end: &str) -> Result<IpRange<IPv6>> {
        let mut end = end.to_string();

        if end.is_empty() {
            end = start.to_string();
        }

        let start_ip = if ipv6::validate_cidr(start) {
            let tuple = ipv6::cidr2block(start)?;
            address2long_v6(&tuple.0)?
        } else {
            address2long_v6(start)?
        };

        let end_ip = if end.is_empty() {
            start_ip
        } else if ipv6::validate_cidr(&end) {
            let tuple = ipv6::cidr2block(&end)?;
            address2long_v6(&tuple.1)?
        } else {
            address2long_v6(&end)?
        };

        if start_ip > end_ip {
            return Err(Error::V4Subnet());
        }

        let iter_ip = start_ip.checked_sub(1).unwrap_or(start_ip);

        Ok(IpRange {
            ip_version: V6,
            ip_range: IPv6::new(start_ip, end_ip, iter_ip),
        })
    }

    pub fn get_range(&self) -> Option<(String, String)> {
        Some((
            ipv6::long2ip(self.ip_range.start_ip, false),
            ipv6::long2ip(self.ip_range.end_ip, false),
        ))
    }

    pub fn get_range_long(&self) -> (u128, u128) {
        (self.ip_range.start_ip, self.ip_range.end_ip)
    }

    pub fn get_version(&self) -> IpVer {
        self.ip_version.clone()
    }

    pub fn len(&self) -> u128 {
        self.ip_range.len
    }

    pub fn is_empty(&self) -> bool {
        self.ip_range.len == 0
    }

    pub fn len_cur(&self) -> u128 {
        if self.ip_range.iter_ip == self.ip_range.end_ip {
            return self.ip_range.end_ip - self.ip_range.iter_ip + 1;
        }
        self.ip_range.end_ip - self.ip_range.iter_ip
    }

    pub fn contains(&self, ip: &str) -> Result<bool> {
        let mut is_valid = false;
        let mut is_range = false;
        let mut addr = 0u128;
        let mut start_ip = 0u128;
        let mut end_ip = 0u128;
        if ipv4::validate_cidr(ip) {
            is_range = true;
            let tuple = ipv4::cidr2block(ip)?;
            start_ip = address2long_v4(&tuple.0)? as u128;
            end_ip = address2long_v4(&tuple.1)? as u128;
            is_valid = true;
        } else if ipv6::validate_cidr(ip) {
            is_valid = true;
            is_range = true;
            let tuple = ipv6::cidr2block(ip)?;
            start_ip = address2long_v6(&tuple.0)?;
            end_ip = address2long_v6(&tuple.1)?;
        } else if ipv6::validate_ip(ip) {
            is_valid = true;
            addr = address2long_v6(ip)?;
        } else if ipv4::validate_ip(ip) {
            is_valid = true;
            addr = address2long_v4(ip)? as u128;
        }

        if !is_valid {
            return Err(UnknownVersion());
        }

        if !is_range {
            match self.ip_version {
                V4 => Ok(self.ip_range.start_ip as u32 <= addr as u32
                    && addr as u32 <= self.ip_range.end_ip as u32),
                V6 => Ok(self.ip_range.start_ip <= addr && addr <= self.ip_range.end_ip),
                VUnknown => Err(UnknownVersion()),
            }
        } else {
            match self.ip_version {
                V4 => Ok(self.ip_range.start_ip as u32 <= start_ip as u32
                    && start_ip as u32 <= self.ip_range.end_ip as u32
                    && end_ip as u32 <= self.ip_range.end_ip as u32),
                V6 => Ok(self.ip_range.start_ip <= start_ip
                    && start_ip <= self.ip_range.end_ip
                    && end_ip <= self.ip_range.end_ip),
                VUnknown => Err(UnknownVersion()),
            }
        }
    }

    fn is_reserved_ipv6(ip: &str) -> Result<bool> {
        for i in ipv6::RESERVED_RANGES.iter() {
            if IpRange::<IPv6>::new(i, "")?.contains(ip)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn is_reserved(ip: &str) -> Result<bool> {
        IpRange::is_reserved_ipv6(ip)
    }
}

#[cfg(test)]
mod tests {
    use crate::iprange::IpVer::{V4, V6};
    use crate::iprange::{IPv4, IPv6, IpRange};

    use pretty_assertions::assert_eq;

    #[test]
    fn test_initialization() {
        assert_eq!(
            IpRange::<IPv4>::new("127.0.0.1", "").unwrap().get_version(),
            V4
        );
        assert_eq!(
            IpRange::<IPv4>::new("127.0.0.2", "127.255.255.255")
                .unwrap()
                .get_version(),
            V4
        );
        assert_eq!(
            IpRange::<IPv6>::new("::1", "::2").unwrap().get_version(),
            V6
        );

        assert_eq!(IpRange::<IPv6>::new("::1", "").unwrap().get_version(), V6);
    }

    #[test]
    fn test_get_range() {
        let x = IpRange::<IPv4>::new("127.0.0.1/24", "").unwrap();
        let xx = IpRange::<IPv4>::new("255.255.1.1/16", "").unwrap();
        let xxx = IpRange::<IPv4>::new("127.0.0.1", "127.0.0.255").unwrap();
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
        assert_eq!(
            IpRange::<IPv4>::new("127.0.0.3", "127.0.0.4")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            IpRange::<IPv4>::new("127.0.0.3", "127.0.255.4")
                .unwrap()
                .len(),
            65282
        );
        assert_eq!(
            IpRange::<IPv4>::new("127.0.0.1", "255.255.255.255")
                .unwrap()
                .len(),
            2164260863
        );
        assert_eq!(IpRange::<IPv6>::new("::1", "::2").unwrap().len(), 2);
        assert_eq!(
            IpRange::<IPv6>::new("fe80::/10", "").unwrap().len(),
            332306998946228968225951765070086144
        );
    }

    #[test]
    fn test_contains() {
        let range = IpRange::<IPv4>::new("127.0.0.3", "127.0.0.5").unwrap();
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
            IpRange::<IPv4>::new("127.0.0.0/8", "").unwrap(),
            IpRange::<IPv4>::new("127.0.0.0", "127.255.255.255").unwrap()
        );
        assert_ne!(
            IpRange::<IPv4>::new("127.0.0.0/8", "").unwrap(),
            IpRange::<IPv4>::new("127.0.0.0", "127.255.255.254").unwrap()
        );
        assert_eq!(
            IpRange::<IPv6>::new("::1/64", "").unwrap(),
            IpRange::<IPv6>::new("::", "::ffff:ffff:ffff:ffff").unwrap()
        );
        assert_ne!(
            IpRange::<IPv6>::new("::1/64", "").unwrap(),
            IpRange::<IPv6>::new("::2", "::ffff:ffff:ffff:ffff").unwrap()
        );
    }

    #[test]
    fn test_next() {
        let mut a = IpRange::<IPv4>::new("127/31", "").unwrap();
        assert_eq!(a.next().unwrap(), "127.0.0.0");
        assert_eq!(a.next().unwrap(), "127.0.0.1");
        assert_eq!(a.next(), None);
        let mut b = IpRange::<IPv6>::new("::1", "::3").unwrap();
        assert_eq!(b.next().unwrap(), "::1");
        assert_eq!(b.next().unwrap(), "::2");
        assert_eq!(b.next().unwrap(), "::3");
        assert_eq!(b.next(), None);
        let mut c = IpRange::<IPv4>::new("255.255.255.255", "").unwrap();
        assert_eq!(c.next().unwrap(), "255.255.255.255");
        assert_eq!(c.next(), None);
    }

    #[test]
    fn test_len_cur() {
        let mut a = IpRange::<IPv4>::new("127/31", "").unwrap();
        assert_eq!(a.len_cur(), 2);
        a.next();
        assert_eq!(a.len_cur(), 1);
        a.next();
        assert_eq!(a.len_cur(), 1);
        let mut b = IpRange::<IPv6>::new("::1", "::3").unwrap();
        assert_eq!(b.len_cur(), 3);
        b.next();
        b.next();
        assert_eq!(b.len_cur(), 1);
        b.next();
        b.next();
        assert_eq!(b.len_cur(), 1);
        let mut c = IpRange::<IPv4>::new("255.255.255.255", "").unwrap();
        assert_eq!(c.len_cur(), 1);
        c.next();
        assert_eq!(c.len_cur(), 1);
    }

    #[test]
    fn test_is_reserved() {
        assert_eq!(IpRange::<IPv4>::is_reserved("127.0.0.1").unwrap(), true);
        assert_eq!(
            IpRange::<IPv4>::is_reserved(crate::ipv4::BROADCAST).unwrap(),
            true
        );
        assert_eq!(
            IpRange::<IPv4>::is_reserved(crate::ipv4::LOOPBACK).unwrap(),
            true
        );
        assert_eq!(
            IpRange::<IPv4>::is_reserved(crate::ipv4::IPV6_TO_IPV4_RELAY).unwrap(),
            true
        );
        assert_eq!(IpRange::<IPv4>::is_reserved("8.8.8.8").unwrap(), false);
        assert_eq!(
            IpRange::<IPv6>::is_reserved(crate::ipv6::LOOPBACK).unwrap(),
            true
        );

        assert_eq!(IpRange::<IPv4>::is_reserved("123456").ok(), None);
        assert_eq!(IpRange::<IPv6>::is_reserved("123456").ok(), None);
    }

    #[test]
    fn test_constructor() {
        assert_eq!(IpRange::<IPv4>::new("Bolognese", "").ok(), None);
        assert_eq!(IpRange::<IPv6>::new("Bolognese", "").ok(), None);
    }

    #[test]
    #[should_panic]
    fn test_should_panic() {
        IpRange::<IPv4>::new("12345678", "").unwrap();
        IpRange::<IPv6>::new("12345678", "").unwrap();
    }
}
