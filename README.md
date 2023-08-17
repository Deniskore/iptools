![Build Status](https://github.com/deniskore/iptools/actions/workflows/rust.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/iptools.svg)](https://crates.io/crates/iptools)
[![API reference](https://docs.rs/iptools/badge.svg)](https://docs.rs/iptools)

# Iptools

This is a port of package [iptools](https://github.com/bd808/python-iptools) from Python.

## Getting Started
Add the following dependency to your Cargo manifest:
```
[dependencies]
iptools = "0.2.4"
```

## Example of usage
```rust
let first_range = IpRange::new("127.0.0.1/16", "").unwrap();
let second_range = IpRange::new("127.0.0.1", "127.0.0.255").unwrap();
// Print range (tuple)
println!("{:?} {:?}", first_range.get_range(), second_range.get_range());
// Ip address range iterator
println!("{:?} {:?}", first_range.next(), second_range.next());
// Print current length of range (next() iterator reduces the length of range)
println!("{}", first_range.len_cur());
// Print initial range
println!("{}", first_range.len());
// Сheck if the current range contains an ip address
println!("{:?}", first_range.contains("127.0.0.3"));
```

## Supported Rust Versions
Rust 1.61.0+

## License

This project is licensed under the [MIT license](LICENSE).
