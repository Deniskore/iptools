use core::fmt;
use std::fmt::Display;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    V4CIDR(),
    V6CIDR(),
    V4Subnet(),
    V4IP(),
    V6IP(),
    V4IPConvert(),
    V6IPConvert(),
    Hex2IP(),
    UnknownVersion(),
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        use self::Error::*;

        match *self {
            V4CIDR() => "Couldn't validate CIDR",
            V6CIDR() => "Couldn't validate CIDR",
            V4Subnet() => "Couldn't validate subnet",
            V4IP() => "Couldn't validate IPV4 address",
            V6IP() => "Couldn't validate IPV6 address",
            V4IPConvert() => "Couldn't convert IPV4 address",
            V6IPConvert() => "Couldn't convert IPV6 address",
            Hex2IP() => "Couldn't convert HEX to IP address",
            UnknownVersion() => "Couldn't detect IP version",
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        use self::Error::*;

        match *self {
            V4CIDR() => write!(f, "Couldn't validate CIDR"),
            V6CIDR() => write!(f, "Couldn't validate CIDR"),
            V4Subnet() => write!(f, "Couldn't validate subnet"),
            V4IP() => write!(f, "Couldn't validate IPV4 address"),
            V6IP() => write!(f, "Couldn't validate IPV6 address"),
            V4IPConvert() => write!(f, "Couldn't convert IPV4 address"),
            V6IPConvert() => write!(f, "Couldn't convert IPV6 address"),
            Hex2IP() => write!(f, "Couldn't convert HEX to IP address"),
            UnknownVersion() => write!(f, "Couldn't detect IP version"),
        }
    }
}
