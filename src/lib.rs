// Copyright (c) 2025 Denis Avvakumov
// Licensed under the MIT license,  https://opensource.org/licenses/MIT
//! # Iptools
//!
//! This is a port of package [iptools](https://github.com/bd808/python-iptools) from Python.

#![forbid(unsafe_code)]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(not(any(test, feature = "std")))]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std as alloc;

pub mod error;
pub mod iprange;
pub mod ipv4;
pub mod ipv6;
