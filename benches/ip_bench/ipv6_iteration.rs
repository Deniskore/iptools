// IPv6 iterator and formatting comparisons

// Iterator shortcut APIs

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_iter_count(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let local = black_box(range.clone());
        black_box(local.count());
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_iter_nth(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let mut local = black_box(range.clone());
        black_box(local.nth(black_box(3000)));
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_iter_last(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let local = black_box(range.clone());
        black_box(local.last());
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_addrs_count(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let iter = black_box(range.addrs());
        black_box(iter.count());
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_addrs_nth(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let mut iter = black_box(range.addrs());
        black_box(iter.nth(black_box(3000)));
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_addrs_last(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let iter = black_box(range.addrs());
        black_box(iter.last());
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_view_count(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let iter = black_box(range.addrs_view());
        black_box(iter.count());
    });
}
// Address iteration counterparts

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
fn iptools_iprange_ipv6_next_addr(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
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
fn iptools_iprange_ipv6_iter_view_addr(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
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
fn iptools_iprange_ipv6_for_each_ip_str(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
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
fn iptools_iprange_ipv6_iter_view_string(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let count = range.addrs_view().fold(0usize, |count, view| {
            black_box(view.to_ip_string());
            count + 1
        });
        black_box(count);
    });
}

#[divan::bench(sample_count = 10000)]
fn iptools_iprange_ipv6_iter_view_display(bencher: Bencher) {
    let range = IpRange::<IPv6Range>::new("2001:db8::", "2001:db8::fff").unwrap();
    bencher.bench_local(|| {
        let mut sink = String::with_capacity(39);
        let count = range.addrs_view().fold(0usize, |count, view| {
            sink.clear();
            write!(&mut sink, "{view}").unwrap();
            black_box(&sink);
            count + 1
        });
        black_box(count);
    });
}
