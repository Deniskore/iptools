use divan::{black_box, Bencher};
use ipnet::{Ipv4Net as IpNetIpv4, Ipv6Net as IpNetIpv6};
use ipnetwork::{Ipv4Network as IpNetworkIpv4, Ipv6Network as IpNetworkIpv6};
use iptools::{
    iprange::{IPv4 as IPv4Range, IPv6 as IPv6Range, IpRange},
    ipv4, ipv6,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

fn main() {
    divan::main();
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_long2ip() -> String {
    ipv4::long2ip(black_box(0xc0a8_0001))
}

#[divan::bench(sample_count = 100000)]
fn std_ipv4_long2ip() -> String {
    Ipv4Addr::from(black_box(0xc0a8_0001u32)).to_string()
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
fn iptools_ipv4_netmask2prefix() -> u32 {
    ipv4::netmask2prefix(black_box("255.255.255.0"))
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv4_ip2long() -> u32 {
    ipv4::ip2long(black_box("192.168.0.1")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_ip2long() -> u128 {
    ipv6::ip2long(black_box("2001:db8::1234")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn std_ipv4_ip2long() -> u32 {
    let ip: Ipv4Addr = black_box("192.168.0.1".parse()).unwrap();
    u32::from(black_box(ip))
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
fn iptools_ipv6_cidr2block() -> (String, String) {
    ipv6::cidr2block(black_box("2001:db8::/32")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_long2rfc1924() -> String {
    ipv6::long2rfc1924(black_box(0x20010db8000000000000000000001234u128))
}

#[divan::bench(sample_count = 100000)]
fn iptools_ipv6_rfc19242long() -> u128 {
    ipv6::rfc19242long(black_box("4)+k&C#VzJ4br>0wv%Yp")).unwrap()
}

// ipnet/ipnetwork don't fully match iptools API for many behaviors
// (netmask->prefix, ip2long, long2ip, RFC1924 conversions)

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
fn ipnet_ipv4_validate_cidr() -> bool {
    IpNetIpv4::from_str(black_box("192.168.0.1/24")).is_ok()
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv4_validate_cidr() -> bool {
    IpNetworkIpv4::from_str(black_box("192.168.0.1/24")).is_ok()
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
fn ipnetwork_ipv4_cidr2block() -> (String, String) {
    let net = IpNetworkIpv4::from_str(black_box("192.168.0.1/24")).unwrap();
    let start = net.network();
    let end = net.broadcast();
    (start.to_string(), end.to_string())
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv6_cidr2block() -> (String, String) {
    let net = IpNetworkIpv6::from_str(black_box("2001:db8::/32")).unwrap();
    let start = net.network();
    let end = net.broadcast();
    (start.to_string(), end.to_string())
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_contains(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/8", "").unwrap();
    let addr = "10.10.10.10".parse::<Ipv4Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(range.contains_ipv4(addr));
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnet_ipv4_contains(bencher: Bencher) {
    let net: IpNetIpv4 = "10.0.0.0/8".parse().unwrap();
    let addr = "10.10.10.10".parse::<Ipv4Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(net.contains(&addr));
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv4_contains(bencher: Bencher) {
    let net: IpNetworkIpv4 = "10.0.0.0/8".parse().unwrap();
    let addr = "10.10.10.10".parse::<Ipv4Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(net.contains(addr));
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_get_range(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/16", "").unwrap();
    bencher.bench_local(|| {
        let bounds = range.get_range();
        black_box(bounds);
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnet_ipv4_get_range(bencher: Bencher) {
    let net: IpNetIpv4 = "10.0.0.0/16".parse().unwrap();
    bencher.bench_local(|| {
        let start = net.network().to_string();
        let end = net.broadcast().to_string();
        black_box((start, end));
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv4_get_range(bencher: Bencher) {
    let net: IpNetworkIpv4 = "10.0.0.0/16".parse().unwrap();
    bencher.bench_local(|| {
        let start = net.network().to_string();
        let end = net.broadcast().to_string();
        black_box((start, end));
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_len(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/16", "").unwrap();
    bencher.bench_local(|| black_box(range.len()));
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv4_size(bencher: Bencher) {
    let net: IpNetworkIpv4 = "10.0.0.0/16".parse().unwrap();
    bencher.bench_local(|| black_box(net.size()));
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_iter_string_addr(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let count = range.clone().fold(0usize, |count, ip| {
            black_box(ip);
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_iter_string_addr(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let count = range.clone().fold(0usize, |count, ip| {
            black_box(ip);
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn ipnet_ipv4_iter_addr(bencher: Bencher) {
    let net: IpNetIpv4 = "10.0.0.0/22".parse().unwrap();
    bencher.bench_local(|| {
        // hosts() skips network+broadcast, so two addresses are excluded
        let count = net.hosts().fold(0usize, |count, ip| {
            black_box(ip);
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn ipnet_ipv4_iter_string_addr(bencher: Bencher) {
    let net: IpNetIpv4 = "10.0.0.0/22".parse().unwrap();
    bencher.bench_local(|| {
        // hosts() skips network+broadcast, so two addresses are excluded
        let count = net.hosts().fold(0usize, |count, ip| {
            black_box(ip.to_string());
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn ipnet_ipv6_iter_addr(bencher: Bencher) {
    let net: IpNetIpv6 = "2001:db8::/116".parse().unwrap();
    bencher.bench_local(|| {
        let count = net.hosts().fold(0usize, |count, ip| {
            black_box(ip);
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn ipnet_ipv6_iter_string_addr(bencher: Bencher) {
    let net: IpNetIpv6 = "2001:db8::/116".parse().unwrap();
    bencher.bench_local(|| {
        let count = net.hosts().fold(0usize, |count, ip| {
            black_box(ip.to_string());
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn ipnetwork_ipv4_iter_addr(bencher: Bencher) {
    let net: IpNetworkIpv4 = "10.0.0.0/22".parse().unwrap();
    bencher.bench_local(|| {
        let count = net.iter().fold(0usize, |count, ip| {
            black_box(ip);
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn ipnetwork_ipv4_iter_string_addr(bencher: Bencher) {
    let net: IpNetworkIpv4 = "10.0.0.0/22".parse().unwrap();
    bencher.bench_local(|| {
        let count = net.iter().fold(0usize, |count, ip| {
            black_box(ip.to_string());
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn ipnetwork_ipv6_iter_addr(bencher: Bencher) {
    let net: IpNetworkIpv6 = "2001:db8::/116".parse().unwrap();
    bencher.bench_local(|| {
        let count = net.iter().fold(0usize, |count, ip| {
            black_box(ip);
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn ipnetwork_ipv6_iter_string_addr(bencher: Bencher) {
    let net: IpNetworkIpv6 = "2001:db8::/116".parse().unwrap();
    bencher.bench_local(|| {
        let count = net.iter().fold(0usize, |count, ip| {
            black_box(ip.to_string());
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_iter_addr(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let count = range.addrs().fold(0usize, |count, addr| {
            black_box(addr);
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_iter_addr(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let count = range.addrs().fold(0usize, |count, addr| {
            black_box(addr);
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_contains(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::/32", "").unwrap();
    let addr = "2001:db8::dead:beef".parse::<Ipv6Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(range.contains_ipv6(addr));
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnet_ipv6_contains(bencher: Bencher) {
    let net: IpNetIpv6 = "2001:db8::/32".parse().unwrap();
    let addr = "2001:db8::dead:beef".parse::<Ipv6Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(net.contains(&addr));
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv6_contains(bencher: Bencher) {
    let net: IpNetworkIpv6 = "2001:db8::/32".parse().unwrap();
    let addr = "2001:db8::dead:beef".parse::<Ipv6Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(net.contains(addr));
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_get_range(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::/48", "").unwrap();
    bencher.bench_local(|| {
        let bounds = range.get_range();
        black_box(bounds);
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnet_ipv6_get_range(bencher: Bencher) {
    let net: IpNetIpv6 = "2001:db8::/48".parse().unwrap();
    bencher.bench_local(|| {
        let start = net.network().to_string();
        let end = net.broadcast().to_string();
        black_box((start, end));
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv6_get_range(bencher: Bencher) {
    let net: IpNetworkIpv6 = "2001:db8::/48".parse().unwrap();
    bencher.bench_local(|| {
        let start = net.network().to_string();
        let end = net.broadcast().to_string();
        black_box((start, end));
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_len(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::/64", "").unwrap();
    bencher.bench_local(|| black_box(range.len()));
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv6_size(bencher: Bencher) {
    let net: IpNetworkIpv6 = "2001:db8::/64".parse().unwrap();
    bencher.bench_local(|| black_box(net.size()));
}
