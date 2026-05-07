// IPv4 core utilities and comparable parsing APIs

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_long2ip() -> String {
    ipv4::long2ip(black_box(0xc0a8_0001))
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_bin_u32() -> String {
    ipv4::bin_u32(black_box(0xc0a8_0001))
}

#[divan::bench(sample_count = 100000)]
fn std_ipv4_long2ip() -> String {
    Ipv4Addr::from(black_box(0xc0a8_0001u32)).to_string()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_ip2long() -> u32 {
    ipv4::ip2long(black_box("192.168.0.1")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_ip2hex() -> String {
    ipv4::ip2hex(black_box("192.168.0.1")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn std_ipv4_ip2long() -> u32 {
    let ip: Ipv4Addr = black_box("192.168.0.1".parse()).unwrap();
    u32::from(black_box(ip))
}
#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_validate_ip() -> bool {
    ipv4::validate_ip(black_box("192.168.0.1"))
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_validate_cidr() -> bool {
    ipv4::validate_cidr(black_box("192.168.0.1/24"))
}

#[divan::bench(sample_count = 100000)]
fn ipnet_ipv4_validate_cidr() -> bool {
    IpNetIpv4::from_str(black_box("192.168.0.1/24")).is_ok()
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv4_validate_cidr() -> bool {
    IpNetworkIpv4::from_str(black_box("192.168.0.1/24")).is_ok()
}

#[divan::bench(sample_count = 100000)]
fn ipnet_ipv4_parse() -> u32 {
    let net: IpNetIpv4 = black_box("192.168.0.1/24".parse()).unwrap();
    u32::from(black_box(net).addr())
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv4_parse() -> u32 {
    let net: IpNetworkIpv4 = black_box("192.168.0.1/24".parse()).unwrap();
    u32::from(black_box(net).ip())
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_validate_netmask() -> bool {
    ipv4::validate_netmask(black_box("255.255.255.0"))
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_validate_subnet() -> bool {
    ipv4::validate_subnet(black_box("192.168.0.1/255.255.255.0"))
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_cidr2block() -> (String, String) {
    ipv4::cidr2block(black_box("192.168.0.1/24")).unwrap()
}


#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv4_cidr2block() -> (String, String) {
    let net = IpNetworkIpv4::from_str(black_box("192.168.0.1/24")).unwrap();
    let start = net.network();
    let end = net.broadcast();
    (start.to_string(), end.to_string())
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_cidr_bounds() -> (u32, u32) {
    ipv4::cidr_bounds(black_box("192.168.0.1/24")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_block_bounds() -> (u32, u32) {
    ipv4::block_bounds(black_box(0xc0a8_0001), black_box(24)).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_netmask2prefix() -> u32 {
    ipv4::netmask2prefix(black_box("255.255.255.0"))
}
