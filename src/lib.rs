// Copyright (c) 2025 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT
//! # Iptools
//!
//! This is a port of package [iptools](https://github.com/bd808/python-iptools) from Python.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std as alloc;

pub mod error;
pub mod iprange;
pub mod ipv4;
pub mod ipv6;

#[cfg(target_arch = "wasm32")]
pub mod wasm {
    use crate::{iprange, ipv4, ipv6};
    use alloc::{string::String, vec::Vec};
    use core::fmt::Debug;
    use js_sys::BigInt;
    use wasm_bindgen::prelude::*;

    fn js_err(err: impl Debug) -> JsValue {
        JsValue::from_str(&format!("{:?}", err))
    }

    #[wasm_bindgen]
    pub fn ipv4_validate_ip(ip: &str) -> bool {
        ipv4::validate_ip(ip)
    }

    #[wasm_bindgen]
    pub fn ipv4_validate_ip_re(ip: &str) -> bool {
        ipv4::validate_ip_re(ip)
    }

    #[wasm_bindgen]
    pub fn ipv4_validate_cidr(cidr: &str) -> bool {
        ipv4::validate_cidr(cidr)
    }

    #[wasm_bindgen]
    pub fn ipv4_validate_cidr_re(cidr: &str) -> bool {
        ipv4::validate_cidr_re(cidr)
    }

    #[wasm_bindgen]
    pub fn ipv4_validate_netmask(netmask: &str) -> bool {
        ipv4::validate_netmask(netmask)
    }

    #[wasm_bindgen]
    pub fn ipv4_validate_subnet(subnet: &str) -> bool {
        ipv4::validate_subnet(subnet)
    }

    #[wasm_bindgen]
    pub fn ipv4_ip2long(ip: &str) -> Result<u32, JsValue> {
        ipv4::ip2long(ip).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn ipv4_long2ip(ip_long: u32) -> String {
        ipv4::long2ip(ip_long)
    }

    #[wasm_bindgen]
    pub fn ipv4_ip2hex(ip: &str) -> Result<String, JsValue> {
        ipv4::ip2hex(ip).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn ipv4_hex2ip(hex: &str) -> Result<String, JsValue> {
        ipv4::hex2ip(hex).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn ipv4_ip2network(ip: &str) -> Result<u32, JsValue> {
        ipv4::ip2network(ip).ok_or_else(|| JsValue::from_str("Invalid IP"))
    }

    #[wasm_bindgen]
    pub fn ipv4_cidr2block(cidr: &str) -> Result<Vec<String>, JsValue> {
        ipv4::cidr2block(cidr)
            .map(|(start, end)| vec![start, end])
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn ipv4_subnet2block(subnet: &str) -> Result<Vec<String>, JsValue> {
        ipv4::subnet2block(subnet)
            .map(|(start, end)| vec![start, end])
            .ok_or_else(|| JsValue::from_str("Invalid subnet"))
    }

    #[wasm_bindgen]
    pub fn ipv4_netmask2prefix(netmask: &str) -> u32 {
        ipv4::netmask2prefix(netmask)
    }

    #[wasm_bindgen]
    pub fn ipv4_bin_u32(number: u32) -> String {
        ipv4::bin_u32(number)
    }

    // IPv6 Functions
    #[wasm_bindgen]
    pub fn ipv6_validate_ip(ip: &str) -> bool {
        ipv6::validate_ip(ip)
    }

    #[wasm_bindgen]
    pub fn ipv6_validate_ip_re(ip: &str) -> bool {
        ipv6::validate_ip_re(ip)
    }

    #[wasm_bindgen]
    pub fn ipv6_validate_cidr(cidr: &str) -> bool {
        ipv6::validate_cidr(cidr)
    }

    #[wasm_bindgen]
    pub fn ipv6_validate_cidr_re(cidr: &str) -> bool {
        ipv6::validate_cidr_re(cidr)
    }

    #[wasm_bindgen]
    pub fn ipv6_ip2long(ip: &str) -> Result<BigInt, JsValue> {
        ipv6::ip2long(ip)
            .map(BigInt::from)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub fn ipv6_long2ip(long_ip: &BigInt, rfc1924: bool) -> Result<String, JsValue> {
        u128::try_from(long_ip.clone())
            .map(|n| ipv6::long2ip(n, rfc1924))
            .map_err(|_| JsValue::from_str("BigInt out of range for IPv6"))
    }

    #[wasm_bindgen]
    pub fn ipv6_long2rfc1924(long_ip: &BigInt) -> Result<String, JsValue> {
        u128::try_from(long_ip.clone())
            .map(|n| ipv6::long2rfc1924(n))
            .map_err(|_| JsValue::from_str("BigInt out of range for IPv6"))
    }

    #[wasm_bindgen]
    pub fn ipv6_rfc19242long(rfc1924: &str) -> Result<BigInt, JsValue> {
        ipv6::rfc19242long(rfc1924)
            .map(BigInt::from)
            .ok_or_else(|| JsValue::from_str("Invalid RFC1924 format"))
    }

    #[wasm_bindgen]
    pub fn ipv6_cidr2block(cidr: &str) -> Result<Vec<String>, JsValue> {
        ipv6::cidr2block(cidr)
            .map(|(start, end)| vec![start, end])
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
    }

    #[wasm_bindgen]
    pub struct Ipv4Range {
        inner: iprange::IpRange<iprange::IPv4>,
    }

    #[wasm_bindgen]
    impl Ipv4Range {
        #[wasm_bindgen(constructor)]
        pub fn new(start: &str, end: Option<String>) -> Result<Ipv4Range, JsValue> {
            let end_value = end.unwrap_or_default();
            let end_ref = if end_value.is_empty() {
                ""
            } else {
                end_value.as_str()
            };
            iprange::IpRange::<iprange::IPv4>::new(start, end_ref)
                .map(|inner| Ipv4Range { inner })
                .map_err(js_err)
        }

        pub fn len(&self) -> u32 {
            self.inner.len()
        }

        pub fn remaining(&self) -> u32 {
            self.inner.remaining()
        }

        pub fn range(&self) -> Vec<String> {
            let (start, end) = self.inner.get_range();
            vec![start, end]
        }

        pub fn contains(&self, target: &str) -> Result<bool, JsValue> {
            self.inner.contains(target).map_err(js_err)
        }

        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        pub fn iter(&self) -> Ipv4RangeIter {
            Ipv4RangeIter {
                inner: self.inner.addrs(),
            }
        }

        pub fn is_reserved(target: &str) -> Result<bool, JsValue> {
            iprange::IpRange::<iprange::IPv4>::is_reserved(target).map_err(js_err)
        }
    }

    #[wasm_bindgen]
    pub struct Ipv4RangeIter {
        inner: iprange::AddrIterator<iprange::IPv4>,
    }

    #[wasm_bindgen]
    impl Ipv4RangeIter {
        pub fn next(&mut self) -> Option<Ipv4RangeItem> {
            self.inner.next().map(|addr| Ipv4RangeItem {
                ip: ipv4::long2ip(addr),
                long: addr,
            })
        }
    }

    #[wasm_bindgen]
    pub struct Ipv4RangeItem {
        ip: String,
        long: u32,
    }

    #[wasm_bindgen]
    impl Ipv4RangeItem {
        #[wasm_bindgen(getter)]
        pub fn ip(&self) -> String {
            self.ip.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn long(&self) -> u32 {
            self.long
        }
    }

    #[wasm_bindgen]
    pub struct Ipv6Range {
        inner: iprange::IpRange<iprange::IPv6>,
    }

    #[wasm_bindgen]
    impl Ipv6Range {
        #[wasm_bindgen(constructor)]
        pub fn new(start: &str, end: Option<String>) -> Result<Ipv6Range, JsValue> {
            let end_value = end.unwrap_or_default();
            let end_ref = if end_value.is_empty() {
                ""
            } else {
                end_value.as_str()
            };
            iprange::IpRange::<iprange::IPv6>::new(start, end_ref)
                .map(|inner| Ipv6Range { inner })
                .map_err(js_err)
        }

        pub fn len(&self) -> BigInt {
            BigInt::from(self.inner.len())
        }

        pub fn remaining(&self) -> BigInt {
            BigInt::from(self.inner.remaining())
        }

        pub fn range(&self) -> Vec<String> {
            let (start, end) = self.inner.get_range();
            vec![start, end]
        }

        pub fn contains(&self, target: &str) -> Result<bool, JsValue> {
            self.inner.contains(target).map_err(js_err)
        }

        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        pub fn iter(&self) -> Ipv6RangeIter {
            Ipv6RangeIter {
                inner: self.inner.addrs(),
            }
        }

        pub fn is_reserved(target: &str) -> Result<bool, JsValue> {
            iprange::IpRange::<iprange::IPv6>::is_reserved(target).map_err(js_err)
        }
    }

    #[wasm_bindgen]
    pub struct Ipv6RangeIter {
        inner: iprange::AddrIterator<iprange::IPv6>,
    }

    #[wasm_bindgen]
    impl Ipv6RangeIter {
        pub fn next(&mut self) -> Option<Ipv6RangeItem> {
            self.inner.next().map(|addr| Ipv6RangeItem {
                ip: ipv6::long2ip(addr, false),
                long: addr,
            })
        }
    }

    #[wasm_bindgen]
    pub struct Ipv6RangeItem {
        ip: String,
        long: u128,
    }

    #[wasm_bindgen]
    impl Ipv6RangeItem {
        #[wasm_bindgen(getter)]
        pub fn ip(&self) -> String {
            self.ip.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn long(&self) -> BigInt {
            BigInt::from(self.long)
        }
    }
}
