# Rust `iptools` vs Python `iptools`

Compared to Python `iptools` (0.7.0), this Rust crate differs in the
following behaviors.

## RFC-backed IPv6 differences

- Rust rejects malformed zero-compression forms such as `:::1`, `1:::1`, and
  `2001:::1`; Python `iptools` accepts them.
  RFC basis: [RFC 4291 Section 2.2](https://datatracker.ietf.org/doc/html/rfc4291#section-2.2)
  says `::` can appear at most once.
- Rust accepts case-insensitive hex in mixed IPv6 form, e.g.
  `::FFFF:192.0.2.128`; Python `iptools` rejects uppercase in that pattern.
  RFC basis: [RFC 4291 Section 2.2](https://datatracker.ietf.org/doc/html/rfc4291#section-2.2)
  allows uppercase or lowercase hex digits.
  [RFC 5952 Section 4.3](https://datatracker.ietf.org/doc/html/rfc5952#section-4.3)
  recommends lowercase for canonical text, but uppercase is still valid.
- Rust accepts IPv6 CIDR with dotted-quad tails, e.g.
  `::ffff:192.0.2.128/96`; Python `iptools` rejects these.
  RFC basis: [RFC 4291 Section 2.2](https://datatracker.ietf.org/doc/html/rfc4291#section-2.2)
  allows mixed `x:x:x:x:x:x:d.d.d.d` text, and
  [Section 2.3](https://datatracker.ietf.org/doc/html/rfc4291#section-2.3)
  defines prefixes as `ipv6-address/prefix-length`.
- Rust accepts IPv6 CIDR prefixes with leading-zero width (for example
  `"f::ddb:a/0089"`); Python `iptools` rejects these.
- Rust rejects shortened mixed tails like `::ffff:1.2.3`; Python `iptools`
  accepts them.
  RFC basis: [RFC 4291 Section 2.2](https://datatracker.ietf.org/doc/html/rfc4291#section-2.2)
  mixed form is explicitly
  `x:x:x:x:x:x:d.d.d.d` (four decimal octets, each `0..255`).

## Policy differences between packages (Rust vs Python)

- Rust requires strict dotted-quad IPv4 text for `validate_ip`, `ip2long`,
  `validate_cidr`, `cidr2block`, and `subnet2block` (exactly 4 octets). Python
  `iptools` accepts shorthand forms such as `"127"` and `"127.1"`.
- Rust rejects IPv4 octets with multi-digit leading zeros (for example
  `"01.2.3.4"`); Python `iptools` accepts them.
- Rust rejects mixed tails with multi-digit leading-zero octets such as
  `::ffff:01.2.3.4`; Python `iptools` accepts them.
  Note: RFC 4291 does not explicitly define leading-zero policy for the
  embedded dotted-quad fields; Rust intentionally uses strict dotted-decimal
  parsing (aligned with Python `ipaddress` behavior).
- Rust rejects reversed range bounds in `IpRange::new` (for example
  `"10.0.0.2"`, `"10.0.0.1"`); Python `iptools` normalizes and swaps endpoints.
- Rust `IpRange::new` does not accept IPv4 subnet notation in the first
  argument (for example `"127/255.255.255.0"`); Python `iptools` accepts it.
- Rust `IpRange::<IPv6>::contains` treats valid bare IPv4 text as a family
  mismatch and returns `Ok(false)`. Use `contains_addr` for numeric IPv4-in-IPv6
  low-bit checks.
- Rust accepts IPv4 CIDR prefixes with leading zeros (for example
  `"192.0.2.1/030"`); Python `iptools` restricts the prefix field to one or two
  digits.
