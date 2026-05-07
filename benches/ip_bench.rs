use divan::{Bencher, black_box};
use ipnet::{Ipv4Net as IpNetIpv4, Ipv6Net as IpNetIpv6};
use ipnetwork::{Ipv4Network as IpNetworkIpv4, Ipv6Network as IpNetworkIpv6};
use iptools::{
    iprange::{IPv4 as IPv4Range, IPv6 as IPv6Range, IpRange},
    ipv4, ipv6,
};
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

fn main() {
    divan::main();
}

include!("ip_bench/ipv4_core.rs");
include!("ip_bench/ipv6_core.rs");
include!("ip_bench/ipv4_range.rs");
include!("ip_bench/ipv6_range.rs");
include!("ip_bench/ipv4_iteration.rs");
include!("ip_bench/ipv6_iteration.rs");
