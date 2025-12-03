![Build Status](https://github.com/deniskore/iptools/actions/workflows/rust.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/iptools.svg)](https://crates.io/crates/iptools)
[![API reference](https://docs.rs/iptools/badge.svg)](https://docs.rs/iptools)

# Iptools

This is a port of package [iptools](https://github.com/bd808/python-iptools) from Python with a lot of optimizations.

## Key Features

1. 100% safe Rust with `#![forbid(unsafe_code)]`
2. Minimum dependencies
3. Optimized for speed, with better performance than the `ipnet` and `ipnetwork` crates and the standard library implementation (Benched on AArch64 and x86_64)
4. WebAssembly support (see [WASM.md](WASM.md))
5. `no_std` support with optional serde serialization for `IpRange`/`IpVer`

## Which crate should I choose?

**Recommendation**: choose `iptools` when you need string-based APIs, reserved-block detection, WebAssembly builds, or when execution speed is a priority. Reach for `ipnet` if you need subnet aggregation, address arithmetic traits, or tighter integration with `IpAddr`. Use `ipnetwork` when you only require lightweight CIDR parsing/iteration and prefer its smaller, std-only API surface.

## Getting Started
Add the following dependency to your Cargo manifest:
```toml
[dependencies]
iptools = "0.4.1"
```

### `no_std` support
To use `iptools` in a `no_std` environment, disable the default features:
```toml
[dependencies]
iptools = { version = "0.4.1", default-features = false }
```

## Example of usage
```rust
use iptools::iprange::{IpRange, IPv4};

let first_range = match IpRange::<IPv4>::new("127.0.0.1/16", "") {
    Ok(range) => range,
    Err(err) => {
        eprintln!("Error: {}", err);
        return;
    }
};
let second_range = match IpRange::<IPv4>::new("127.0.0.1", "127.0.0.255") {
    Ok(range) => range,
    Err(err) => {
        eprintln!("Error: {}", err);
        return;
    }
};

// Print range bounds (tuple: start, end)
println!("{:?} {:?}", first_range.get_range(), second_range.get_range());

// Use the IpRange as an iterator. Clone the range to iterate without consuming the original
let mut iter = first_range.clone();
println!("Next IPs: {:?} {:?}", iter.next(), iter.next()); // Option<String>

// Print current length (total addresses in the range)
println!("Initial length: {}", first_range.len());

// Remaining addresses to iterate from a cloned iterator
let mut iter2 = first_range.clone();
println!("Remaining before iteration: {}", iter2.remaining());
iter2.next();
println!("Remaining after consuming one IP: {}", iter2.remaining());

// Check whether an IP or CIDR is contained in the range
match first_range.contains("127.0.0.3") {
    Ok(contains) => println!("Contains 127.0.0.3? {}", contains),
    Err(err) => eprintln!("Error: {}", err),
}

// Iterate over addresses (string iterator)
for ip in first_range.clone().take(3) {
	println!("IP: {}", ip);
}
```

### IPv6 validation differences
The Rust port follows the canonical compression rules from
[RFC 4291 §2.2](https://datatracker.ietf.org/doc/html/rfc4291#section-2.2).
That means non-conforming strings such as `:::1` are rejected even though
Python `iptools` crate accepted them. You can see the
difference locally:

```bash
python3 -c "from iptools import ipv6; print(ipv6.validate_ip(':::1'))"
```

### Reversed range bounds difference
The Rust port rejects reversed bounds when constructing ranges (e.g. `"10.0.0.2"`, `"10.0.0.1"` returns an error). Python `iptools` normalizes and silently swaps those endpoints.

## Supported Rust Versions
Rust 1.78.0+

## License

This project is licensed under the [MIT license](LICENSE).
