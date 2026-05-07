// IPv4 iterator and formatting comparisons

// Iterator shortcut APIs

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_iter_count(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let local = black_box(range.clone());
        black_box(local.count());
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_iter_nth(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let mut local = black_box(range.clone());
        black_box(local.nth(black_box(900)));
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_iter_last(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let local = black_box(range.clone());
        black_box(local.last());
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_addrs_count(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let iter = black_box(range.addrs());
        black_box(iter.count());
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_addrs_nth(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let mut iter = black_box(range.addrs());
        black_box(iter.nth(black_box(900)));
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_addrs_last(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let iter = black_box(range.addrs());
        black_box(iter.last());
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_view_count(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let iter = black_box(range.addrs_view());
        black_box(iter.count());
    });
}
// Address iteration counterparts

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
fn iptools_iprange_ipv4_next_addr(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let mut local = range.clone();
        let mut count = 0usize;
        while let Some(addr) = local.next_addr() {
            black_box(addr);
            count += 1;
        }
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_iter_view_addr(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let count = range.addrs_view().fold(0usize, |count, view| {
            black_box(view.raw());
            count + 1
        });
        black_box(count);
    });
}
// String formatting iteration counterparts

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
fn iptools_iprange_ipv4_for_each_ip_str(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let mut count = 0usize;
        range.for_each_ip_str(|ip| {
            black_box(ip);
            count += 1;
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
fn iptools_iprange_ipv4_iter_view_string(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let count = range.addrs_view().fold(0usize, |count, view| {
            black_box(view.to_ip_string());
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv4_iter_view_display(bencher: Bencher) {
    let range = IpRange::<IPv4Range>::new("10.0.0.0/22", "").unwrap();
    bencher.bench_local(|| {
        let mut sink = String::with_capacity(15);
        let count = range.addrs_view().fold(0usize, |count, view| {
            sink.clear();
            write!(&mut sink, "{view}").unwrap();
            black_box(&sink);
            count + 1
        });
        black_box(count);
    });
}
