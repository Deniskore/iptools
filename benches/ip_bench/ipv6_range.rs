// IPv6 range containment, bounds, and construction comparisons

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_contains(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::/32", "").unwrap();
    let addr = "2001:db8::dead:beef".parse::<Ipv6Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(black_box(&range).contains_ipv6(black_box(addr)));
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_contains_generic_str(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::/32", "").unwrap();
    bencher.bench_local(|| {
        black_box(
            black_box(&range)
                .contains(black_box("2001:db8::dead:beef"))
                .unwrap(),
        );
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_contains_strict(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::/32", "").unwrap();
    bencher.bench_local(|| {
        black_box(
            black_box(&range)
                .contains_strict(black_box("2001:db8::dead:beef"))
                .unwrap(),
        );
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_contains_generic_cidr_str(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::/32", "").unwrap();
    bencher.bench_local(|| {
        black_box(
            black_box(&range)
                .contains(black_box("2001:db8:dead::/48"))
                .unwrap(),
        );
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_contains_strict_cidr(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::/32", "").unwrap();
    bencher.bench_local(|| {
        black_box(
            black_box(&range)
                .contains_strict(black_box("2001:db8:dead::/48"))
                .unwrap(),
        );
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnet_ipv6_contains(bencher: Bencher) {
    let net: IpNetIpv6 = "2001:db8::/32".parse().unwrap();
    let addr = "2001:db8::dead:beef".parse::<Ipv6Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(black_box(&net).contains(black_box(&addr)));
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv6_contains(bencher: Bencher) {
    let net: IpNetworkIpv6 = "2001:db8::/32".parse().unwrap();
    let addr = "2001:db8::dead:beef".parse::<Ipv6Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(black_box(&net).contains(black_box(addr)));
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
fn iptools_iprange_ipv6_new_cidr_empty() -> IpRange<IPv6Range> {
    IpRange::<IPv6Range>::new(black_box("2001:db8::/64"), black_box("")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_new_single_empty() -> IpRange<IPv6Range> {
    IpRange::<IPv6Range>::new(black_box("2001:db8::1"), black_box("")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_from_bounds() -> IpRange<IPv6Range> {
    IpRange::<IPv6Range>::from_bounds(
        black_box(0x20010db8000000000000000000000000u128),
        black_box(0x20010db800000000000000000000ffffu128),
    )
    .unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv6_from_addr_prefix() -> IpRange<IPv6Range> {
    IpRange::<IPv6Range>::from_addr_prefix(
        black_box(0x20010db8000000000000000000001234u128),
        black_box(112),
    )
    .unwrap()
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv6_size(bencher: Bencher) {
    let net: IpNetworkIpv6 = "2001:db8::/64".parse().unwrap();
    bencher.bench_local(|| black_box(net.size()));
}
