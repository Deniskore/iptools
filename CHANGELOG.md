# Changelog

## [0.5.0] - 2026-02-28

### Added
- `IpRange::<T>::next_addr()` for allocation-free numeric iteration.
- `IpRange::<T>::for_each_addr()` for allocation-free address traversal.
- `IpRange::<T>::from_bounds()` and `IpRange::<T>::from_addr_prefix()` numeric constructors.
- `IpRange::<T>::addrs_view()` plus `AddrView`/`AddrViewIterator` for on-demand formatting.
- `IpRange::<IPv4>::contains_strict()` and `IpRange::<IPv6>::contains_strict()` fast paths.
- `RS_PY_COMPAT.md` documenting behavior differences from Python `iptools`.

### Changed
- Version bump to `0.5.0` due to intentional behavior changes in existing APIs.
- IPv4 text handling is now strict dotted-quad for core validators/converters:
  - `validate_ip`, `ip2long`, `validate_cidr`, `cidr2block`, `subnet2block`.
  - Shorthand forms like `127`, `127.1` are rejected in those APIs.
- IPv4 multi-digit leading-zero octets are rejected in strict parsers.
- IPv6 parsing now rejects malformed compression forms (e.g. `:::1`, `1:::1`) and strictens mixed dotted tails.
- IPv6 parsing no longer accepts bare IPv4 text as IPv6 input.
- Cross-family IPv4 range checks only downcast IPv4-mapped IPv6 (`::ffff:a.b.c.d`); non-mapped IPv6 no longer truncates into IPv4 space.
- Regex-backed `*_re` validators are now available only with the default `std` feature; optimized validators remain available in `no_std`.
- `ipv6::DOCUMENTATION_NETWORK` corrected to `2001:db8::/32` (RFC 3849).

### Fixed
- `validate_ip_re`/`validate_cidr_re` parity with optimized IPv6 validators on mixed-tail and malformed compression edge cases.
