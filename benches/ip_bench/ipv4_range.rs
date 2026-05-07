// IPv4 range containment, bounds, and construction comparisons

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_contains(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/8", "").unwrap();
    let addr = "10.10.10.10".parse::<Ipv4Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(black_box(&range).contains_ipv4(black_box(addr)));
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_contains_generic_str(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/8", "").unwrap();
    bencher.bench_local(|| {
        black_box(black_box(&range).contains(black_box("10.10.10.10")).unwrap());
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_contains_strict(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/8", "").unwrap();
    bencher.bench_local(|| {
        black_box(
            black_box(&range)
                .contains_strict(black_box("10.10.10.10"))
                .unwrap(),
        );
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_contains_generic_cidr_str(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/8", "").unwrap();
    bencher.bench_local(|| {
        black_box(
            black_box(&range)
                .contains(black_box("10.10.0.0/16"))
                .unwrap(),
        );
    });
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_contains_strict_cidr(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/8", "").unwrap();
    bencher.bench_local(|| {
        black_box(
            black_box(&range)
                .contains_strict(black_box("10.10.0.0/16"))
                .unwrap(),
        );
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnet_ipv4_contains(bencher: Bencher) {
    let net: IpNetIpv4 = "10.0.0.0/8".parse().unwrap();
    let addr = "10.10.10.10".parse::<Ipv4Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(black_box(&net).contains(black_box(&addr)));
    });
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv4_contains(bencher: Bencher) {
    let net: IpNetworkIpv4 = "10.0.0.0/8".parse().unwrap();
    let addr = "10.10.10.10".parse::<Ipv4Addr>().unwrap();
    bencher.bench_local(|| {
        black_box(black_box(&net).contains(black_box(addr)));
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
fn iptools_iprange_ipv4_new_cidr_empty() -> IpRange<IPv4Range> {
    IpRange::<IPv4Range>::new(black_box("10.0.0.0/16"), black_box("")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_new_single_empty() -> IpRange<IPv4Range> {
    IpRange::<IPv4Range>::new(black_box("10.0.0.1"), black_box("")).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_from_bounds() -> IpRange<IPv4Range> {
    IpRange::<IPv4Range>::from_bounds(black_box(0x0a00_0000), black_box(0x0a00_ffff)).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn iptools_iprange_ipv4_from_addr_prefix() -> IpRange<IPv4Range> {
    IpRange::<IPv4Range>::from_addr_prefix(black_box(0x0a00_0102), black_box(16)).unwrap()
}

#[divan::bench(sample_count = 100000)]
fn ipnetwork_ipv4_size(bencher: Bencher) {
    let net: IpNetworkIpv4 = "10.0.0.0/16".parse().unwrap();
    bencher.bench_local(|| black_box(net.size()));
}
