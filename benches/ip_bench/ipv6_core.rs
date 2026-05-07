// IPv6 core utilities and comparable parsing APIs

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_ip2long() -> u128 {
    ipv6::ip2long(black_box("2001:db8::1234")).unwrap()
}


#[divan::bench(sample_count = 100000)]
fn std_ipv6_ip2long() -> u128 {
    let ip: Ipv6Addr = black_box("2001:db8::1234".parse()).unwrap();
    u128::from(black_box(ip))
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_long2ip() -> String {
    ipv6::long2ip(black_box(0x20010db8000000000000000000001234u128), false)
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_long2ip_no_compress() -> String {
    ipv6::long2ip(black_box(0x123456789abcdef00123456789abcdefu128), false)
}

#[divan::bench(sample_count = 100000)]
fn std_ipv6_long2ip() -> String {
    Ipv6Addr::from(black_box(0x20010db8000000000000000000001234u128)).to_string()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_validate_ip() -> bool {
    ipv6::validate_ip(black_box("2001:db8::1234"))
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_validate_cidr() -> bool {
    ipv6::validate_cidr(black_box("2001:db8::/32"))
}

#[divan::bench(sample_count = 100000)]
fn ipnet_ipv6_validate_cidr() -> bool {
    IpNetIpv6::from_str(black_box("2001:db8::/32")).is_ok()
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv6_validate_cidr() -> bool {
    IpNetworkIpv6::from_str(black_box("2001:db8::/32")).is_ok()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_cidr2block() -> (String, String) {
    ipv6::cidr2block(black_box("2001:db8::/32")).unwrap()
}


#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv6_cidr2block() -> (String, String) {
    let net = IpNetworkIpv6::from_str(black_box("2001:db8::/32")).unwrap();
    let start = net.network();
    let end = net.broadcast();
    (start.to_string(), end.to_string())
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_cidr_bounds() -> (u128, u128) {
    ipv6::cidr_bounds(black_box("2001:db8::/32")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_block_bounds() -> (u128, u128) {
    ipv6::block_bounds(
        black_box(0x20010db8000000000000000000001234u128),
        black_box(32),
    )
    .unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_long2rfc1924() -> String {
    ipv6::long2rfc1924(black_box(0x20010db8000000000000000000001234u128))
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_rfc19242long() -> u128 {
    ipv6::rfc19242long(black_box("4)+k&C#VzJ4br>0wv%Yp")).unwrap()
}
