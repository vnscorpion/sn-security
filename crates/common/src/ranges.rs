//! Address ranges their owners publish, embedded so neither the agent nor the
//! hub needs a network lookup to use them, and refreshed with each release.
//!
//! * Cloudflare: a proxy, never a client. Banning one of its edges never stops
//!   an attacker behind it; it only cuts off every visitor routed through it.
//! * Googlebot, Google's special-case crawlers (AdsBot, Mediapartners...) and
//!   user-triggered fetchers, Bingbot, Applebot: what a crawler is, decided by
//!   the address it comes from. A User-Agent that claims to be one gains
//!   nothing by itself.
//! * Jetpack: Automattic's servers, which call `xmlrpc.php` on every Jetpack
//!   site of a VPS.
//! * QUIC.cloud: LiteSpeed's CDN nodes, for the `quic.cloud` alias of
//!   `trusted_proxies` (opt-in).
//!
//! Each list says where it came from and when it was taken. A list that could
//! not be fetched from its owner is left out rather than guessed.

use std::net::IpAddr;
use std::sync::LazyLock;

use crate::net::{self, Cidr};

/// Cloudflare's IPv4 ranges (https://www.cloudflare.com/ips-v4, checked
/// 2026-10-14).
pub const CLOUDFLARE_V4: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Cloudflare's IPv6 ranges (https://www.cloudflare.com/ips-v6, checked
/// 2026-10-14).
pub const CLOUDFLARE_V6: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Automattic's Jetpack servers (https://jetpack.com/ips-v4.txt, fetched
/// 2026-10-14).
pub const JETPACK: &[&str] = &[
    "122.248.245.244/32",
    "54.217.201.243/32",
    "54.232.116.4/32",
    "192.0.80.0/20",
    "192.0.96.0/20",
    "192.0.112.0/20",
    "195.234.108.0/22",
    "192.0.64.0/18",
];

/// Googlebot (https://developers.google.com/static/search/apis/ipranges/googlebot.json,
/// fetched 2026-10-14; the file's creationTime is 2026-10-13T14:46:11).
pub const GOOGLEBOT: &[&str] = &[
    "2001:4860:4801:10::/64",
    "2001:4860:4801:11::/64",
    "2001:4860:4801:12::/64",
    "2001:4860:4801:13::/64",
    "2001:4860:4801:14::/64",
    "2001:4860:4801:15::/64",
    "2001:4860:4801:16::/64",
    "2001:4860:4801:17::/64",
    "2001:4860:4801:18::/64",
    "2001:4860:4801:19::/64",
    "2001:4860:4801:1a::/64",
    "2001:4860:4801:1b::/64",
    "2001:4860:4801:1c::/64",
    "2001:4860:4801:1d::/64",
    "2001:4860:4801:1e::/64",
    "2001:4860:4801:1f::/64",
    "2001:4860:4801:20::/64",
    "2001:4860:4801:21::/64",
    "2001:4860:4801:22::/64",
    "2001:4860:4801:23::/64",
    "2001:4860:4801:24::/64",
    "2001:4860:4801:25::/64",
    "2001:4860:4801:26::/64",
    "2001:4860:4801:27::/64",
    "2001:4860:4801:28::/64",
    "2001:4860:4801:29::/64",
    "2001:4860:4801:2::/64",
    "2001:4860:4801:2a::/64",
    "2001:4860:4801:2b::/64",
    "2001:4860:4801:2c::/64",
    "2001:4860:4801:2d::/64",
    "2001:4860:4801:2e::/64",
    "2001:4860:4801:2f::/64",
    "2001:4860:4801:30::/64",
    "2001:4860:4801:31::/64",
    "2001:4860:4801:32::/64",
    "2001:4860:4801:33::/64",
    "2001:4860:4801:34::/64",
    "2001:4860:4801:35::/64",
    "2001:4860:4801:36::/64",
    "2001:4860:4801:37::/64",
    "2001:4860:4801:38::/64",
    "2001:4860:4801:39::/64",
    "2001:4860:4801:3a::/64",
    "2001:4860:4801:3b::/64",
    "2001:4860:4801:3c::/64",
    "2001:4860:4801:3d::/64",
    "2001:4860:4801:3e::/64",
    "2001:4860:4801:3f::/64",
    "2001:4860:4801:40::/64",
    "2001:4860:4801:41::/64",
    "2001:4860:4801:42::/64",
    "2001:4860:4801:43::/64",
    "2001:4860:4801:44::/64",
    "2001:4860:4801:45::/64",
    "2001:4860:4801:46::/64",
    "2001:4860:4801:47::/64",
    "2001:4860:4801:48::/64",
    "2001:4860:4801:49::/64",
    "2001:4860:4801:4a::/64",
    "2001:4860:4801:4b::/64",
    "2001:4860:4801:4c::/64",
    "2001:4860:4801:4d::/64",
    "2001:4860:4801:4e::/64",
    "2001:4860:4801:50::/64",
    "2001:4860:4801:51::/64",
    "2001:4860:4801:52::/64",
    "2001:4860:4801:53::/64",
    "2001:4860:4801:54::/64",
    "2001:4860:4801:55::/64",
    "2001:4860:4801:56::/64",
    "2001:4860:4801:57::/64",
    "2001:4860:4801:58::/64",
    "2001:4860:4801:59::/64",
    "2001:4860:4801:60::/64",
    "2001:4860:4801:61::/64",
    "2001:4860:4801:62::/64",
    "2001:4860:4801:63::/64",
    "2001:4860:4801:64::/64",
    "2001:4860:4801:65::/64",
    "2001:4860:4801:66::/64",
    "2001:4860:4801:67::/64",
    "2001:4860:4801:68::/64",
    "2001:4860:4801:69::/64",
    "2001:4860:4801:6a::/64",
    "2001:4860:4801:6b::/64",
    "2001:4860:4801:6c::/64",
    "2001:4860:4801:6d::/64",
    "2001:4860:4801:6e::/64",
    "2001:4860:4801:6f::/64",
    "2001:4860:4801:70::/64",
    "2001:4860:4801:71::/64",
    "2001:4860:4801:72::/64",
    "2001:4860:4801:73::/64",
    "2001:4860:4801:74::/64",
    "2001:4860:4801:75::/64",
    "2001:4860:4801:76::/64",
    "2001:4860:4801:77::/64",
    "2001:4860:4801:78::/64",
    "2001:4860:4801:79::/64",
    "2001:4860:4801:7a::/64",
    "2001:4860:4801:7b::/64",
    "2001:4860:4801:7c::/64",
    "2001:4860:4801:7d::/64",
    "2001:4860:4801:7e::/64",
    "2001:4860:4801:7f::/64",
    "2001:4860:4801:80::/64",
    "2001:4860:4801:81::/64",
    "2001:4860:4801:82::/64",
    "2001:4860:4801:83::/64",
    "2001:4860:4801:84::/64",
    "2001:4860:4801:85::/64",
    "2001:4860:4801:86::/64",
    "2001:4860:4801:87::/64",
    "2001:4860:4801:88::/64",
    "2001:4860:4801:90::/64",
    "2001:4860:4801:91::/64",
    "2001:4860:4801:92::/64",
    "2001:4860:4801:93::/64",
    "2001:4860:4801:94::/64",
    "2001:4860:4801:95::/64",
    "2001:4860:4801:96::/64",
    "2001:4860:4801:97::/64",
    "2001:4860:4801:a0::/64",
    "2001:4860:4801:a1::/64",
    "2001:4860:4801:a2::/64",
    "2001:4860:4801:a3::/64",
    "2001:4860:4801:a4::/64",
    "2001:4860:4801:a5::/64",
    "2001:4860:4801:a6::/64",
    "2001:4860:4801:a7::/64",
    "2001:4860:4801:a8::/64",
    "2001:4860:4801:a9::/64",
    "2001:4860:4801:aa::/64",
    "2001:4860:4801:ab::/64",
    "2001:4860:4801:ac::/64",
    "2001:4860:4801:ad::/64",
    "2001:4860:4801:ae::/64",
    "2001:4860:4801:b0::/64",
    "2001:4860:4801:b1::/64",
    "2001:4860:4801:b2::/64",
    "2001:4860:4801:b3::/64",
    "2001:4860:4801:b4::/64",
    "2001:4860:4801:b5::/64",
    "2001:4860:4801:b6::/64",
    "2001:4860:4801:c::/64",
    "2001:4860:4801:f::/64",
    "192.178.4.0/27",
    "192.178.4.128/27",
    "192.178.4.160/27",
    "192.178.4.192/27",
    "192.178.4.224/27",
    "192.178.4.32/27",
    "192.178.4.64/27",
    "192.178.4.96/27",
    "192.178.5.0/27",
    "192.178.6.0/27",
    "192.178.6.128/27",
    "192.178.6.160/27",
    "192.178.6.192/27",
    "192.178.6.224/27",
    "192.178.6.32/27",
    "192.178.6.64/27",
    "192.178.6.96/27",
    "192.178.7.0/27",
    "192.178.7.128/27",
    "192.178.7.160/27",
    "192.178.7.192/27",
    "192.178.7.224/27",
    "192.178.7.32/27",
    "192.178.7.64/27",
    "192.178.7.96/27",
    "34.100.182.96/28",
    "34.101.50.144/28",
    "34.118.254.0/28",
    "34.118.66.0/28",
    "34.126.178.96/28",
    "34.146.150.144/28",
    "34.147.110.144/28",
    "34.151.74.144/28",
    "34.152.50.64/28",
    "34.154.114.144/28",
    "34.155.98.32/28",
    "34.165.18.176/28",
    "34.175.160.64/28",
    "34.176.130.16/28",
    "34.22.85.0/27",
    "34.64.82.64/28",
    "34.65.242.112/28",
    "34.80.50.80/28",
    "34.88.194.0/28",
    "34.89.10.80/28",
    "34.89.198.80/28",
    "34.96.162.48/28",
    "35.247.243.240/28",
    "66.249.64.0/27",
    "66.249.64.128/27",
    "66.249.64.160/27",
    "66.249.64.192/27",
    "66.249.64.224/27",
    "66.249.64.32/27",
    "66.249.64.64/27",
    "66.249.64.96/27",
    "66.249.65.0/27",
    "66.249.65.128/27",
    "66.249.65.160/27",
    "66.249.65.192/27",
    "66.249.65.224/27",
    "66.249.65.32/27",
    "66.249.65.64/27",
    "66.249.65.96/27",
    "66.249.66.0/27",
    "66.249.66.128/27",
    "66.249.66.160/27",
    "66.249.66.192/27",
    "66.249.66.224/27",
    "66.249.66.32/27",
    "66.249.66.64/27",
    "66.249.66.96/27",
    "66.249.67.0/27",
    "66.249.67.32/27",
    "66.249.67.64/27",
    "66.249.68.0/27",
    "66.249.68.128/27",
    "66.249.68.160/27",
    "66.249.68.192/27",
    "66.249.68.224/27",
    "66.249.68.32/27",
    "66.249.68.64/27",
    "66.249.68.96/27",
    "66.249.69.0/27",
    "66.249.69.128/27",
    "66.249.69.160/27",
    "66.249.69.192/27",
    "66.249.69.224/27",
    "66.249.69.32/27",
    "66.249.69.64/27",
    "66.249.69.96/27",
    "66.249.70.0/27",
    "66.249.70.128/27",
    "66.249.70.160/27",
    "66.249.70.192/27",
    "66.249.70.224/27",
    "66.249.70.32/27",
    "66.249.70.64/27",
    "66.249.70.96/27",
    "66.249.71.0/27",
    "66.249.71.128/27",
    "66.249.71.160/27",
    "66.249.71.192/27",
    "66.249.71.224/27",
    "66.249.71.32/27",
    "66.249.71.64/27",
    "66.249.71.96/27",
    "66.249.72.0/27",
    "66.249.72.128/27",
    "66.249.72.160/27",
    "66.249.72.192/27",
    "66.249.72.224/27",
    "66.249.72.32/27",
    "66.249.72.64/27",
    "66.249.72.96/27",
    "66.249.73.0/27",
    "66.249.73.128/27",
    "66.249.73.160/27",
    "66.249.73.192/27",
    "66.249.73.224/27",
    "66.249.73.32/27",
    "66.249.73.64/27",
    "66.249.73.96/27",
    "66.249.74.0/27",
    "66.249.74.128/27",
    "66.249.74.160/27",
    "66.249.74.192/27",
    "66.249.74.224/27",
    "66.249.74.32/27",
    "66.249.74.64/27",
    "66.249.74.96/27",
    "66.249.75.0/27",
    "66.249.75.128/27",
    "66.249.75.160/27",
    "66.249.75.192/27",
    "66.249.75.224/27",
    "66.249.75.32/27",
    "66.249.75.64/27",
    "66.249.75.96/27",
    "66.249.76.0/27",
    "66.249.76.128/27",
    "66.249.76.160/27",
    "66.249.76.192/27",
    "66.249.76.224/27",
    "66.249.76.32/27",
    "66.249.76.64/27",
    "66.249.76.96/27",
    "66.249.77.0/27",
    "66.249.77.128/27",
    "66.249.77.160/27",
    "66.249.77.192/27",
    "66.249.77.224/27",
    "66.249.77.32/27",
    "66.249.77.64/27",
    "66.249.77.96/27",
    "66.249.78.0/27",
    "66.249.78.128/27",
    "66.249.78.160/27",
    "66.249.78.192/27",
    "66.249.78.224/27",
    "66.249.78.32/27",
    "66.249.78.64/27",
    "66.249.78.96/27",
    "66.249.79.0/27",
    "66.249.79.128/27",
    "66.249.79.160/27",
    "66.249.79.192/27",
    "66.249.79.224/27",
    "66.249.79.32/27",
    "66.249.79.64/27",
];

/// Bingbot (https://www.bing.com/toolbox/bingbot.json, fetched 2026-10-14; the
/// file's creationTime is 2024-01-03T10:00:00).
pub const BINGBOT: &[&str] = &[
    "157.55.39.0/24",
    "207.46.13.0/24",
    "40.77.167.0/24",
    "13.66.139.0/24",
    "13.66.144.0/24",
    "52.167.144.0/24",
    "13.67.10.16/28",
    "13.69.66.240/28",
    "13.71.172.224/28",
    "139.217.52.0/28",
    "191.233.204.224/28",
    "20.36.108.32/28",
    "20.43.120.16/28",
    "40.79.131.208/28",
    "40.79.186.176/28",
    "52.231.148.0/28",
    "20.79.107.240/28",
    "51.105.67.0/28",
    "20.125.163.80/28",
    "40.77.188.0/22",
    "65.55.210.0/24",
    "199.30.24.0/23",
    "40.77.202.0/24",
    "40.77.139.0/25",
    "20.74.197.0/28",
    "20.15.133.160/27",
    "40.77.177.0/24",
    "40.77.178.0/23",
];

/// Applebot (https://search.developer.apple.com/applebot.json, fetched 2026-10-14;
/// the file's creationTime is 2026-09-15T10:00:00).
pub const APPLEBOT: &[&str] = &[
    "17.241.208.160/27",
    "17.241.193.160/27",
    "17.241.200.160/27",
    "17.166.192.48/28",
    "17.166.240.48/28",
    "17.166.248.48/28",
    "17.166.20.0/24",
    "17.166.21.0/24",
    "17.166.22.0/24",
    "17.166.23.0/24",
    "17.166.24.0/24",
    "17.166.25.0/24",
    "17.166.232.0/24",
    "17.166.233.0/24",
    "17.166.234.0/24",
    "17.166.235.0/24",
    "17.166.236.0/24",
    "17.166.237.0/24",
    "17.166.150.0/24",
    "17.166.151.0/24",
    "17.166.152.0/24",
    "17.166.153.0/24",
    "17.166.154.0/24",
    "17.166.155.0/24",
];

/// QUIC.cloud nodes (https://quic.cloud/ips?ln, fetched 2026-10-14). Used only
/// when `trusted_proxies` lists `quic.cloud`.
pub const QUIC_CLOUD: &[&str] = &[
    "102.221.36.98",
    "103.106.229.82",
    "103.106.229.94",
    "103.146.63.42",
    "103.152.118.219",
    "103.152.118.72",
    "103.164.203.163",
    "103.167.151.84",
    "103.72.163.222",
    "103.75.117.169",
    "104.244.77.37",
    "108.61.158.223",
    "108.61.200.94",
    "109.248.43.195",
    "135.125.104.145",
    "136.243.106.228",
    "139.84.230.39",
    "141.164.38.65",
    "141.227.158.131",
    "144.202.90.7",
    "146.88.239.197",
    "147.78.0.165",
    "147.78.3.161",
    "149.104.83.47",
    "149.28.136.245",
    "149.28.47.113",
    "149.28.85.239",
    "15.204.231.24",
    "15.235.180.91",
    "15.235.181.227",
    "152.53.162.246",
    "152.53.167.143",
    "152.53.168.39",
    "152.53.169.106",
    "152.53.36.14",
    "152.53.38.14",
    "154.205.144.192",
    "155.138.221.81",
    "156.67.218.140",
    "158.51.123.249",
    "162.254.117.80",
    "162.254.118.29",
    "162.55.9.23",
    "163.182.174.161",
    "163.47.21.168",
    "164.52.202.100",
    "167.71.185.204",
    "167.88.61.211",
    "170.249.218.98",
    "173.234.26.74",
    "176.9.114.118",
    "178.17.171.177",
    "178.22.124.251",
    "178.255.220.12",
    "18.192.146.200",
    "185.116.60.231",
    "185.116.60.232",
    "185.126.237.51",
    "185.212.169.91",
    "185.228.26.40",
    "185.231.233.130",
    "185.53.57.40",
    "185.53.57.89",
    "188.172.228.182",
    "188.172.229.113",
    "188.64.184.71",
    "190.92.176.5",
    "191.96.101.140",
    "192.248.156.201",
    "192.248.191.135",
    "192.99.38.117",
    "193.203.191.189",
    "195.137.220.243",
    "195.231.17.141",
    "199.247.28.91",
    "199.59.247.242",
    "201.182.97.70",
    "209.124.84.191",
    "209.208.26.218",
    "211.23.143.87",
    "213.159.1.75",
    "213.183.48.170",
    "213.184.85.245",
    "216.106.177.77",
    "216.128.179.195",
    "216.238.104.48",
    "216.238.71.13",
    "23.160.56.125",
    "23.95.72.16",
    "31.131.4.244",
    "31.22.115.186",
    "31.40.212.152",
    "37.120.163.165",
    "38.114.121.40",
    "38.54.79.187",
    "38.60.253.237",
    "40.160.225.31",
    "40.160.241.195",
    "41.185.29.210",
    "41.223.52.170",
    "45.124.65.86",
    "45.248.77.61",
    "45.32.123.201",
    "45.32.183.112",
    "45.32.203.144",
    "45.32.67.144",
    "45.32.77.223",
    "45.63.67.181",
    "45.76.252.131",
    "45.77.148.74",
    "45.77.165.216",
    "45.77.51.171",
    "46.250.220.133",
    "49.12.102.29",
    "5.134.119.103",
    "51.158.202.109",
    "51.161.196.212",
    "51.68.143.214",
    "51.89.11.45",
    "54.36.103.97",
    "57.129.146.219",
    "57.131.30.109",
    "61.219.247.87",
    "61.219.247.90",
    "64.176.165.8",
    "64.176.4.251",
    "64.227.16.93",
    "65.108.104.232",
    "65.109.39.175",
    "65.20.76.133",
    "65.21.81.51",
    "66.163.114.36",
    "66.42.124.101",
    "66.42.75.121",
    "67.219.99.102",
    "70.34.206.56",
    "74.91.25.147",
    "79.172.239.249",
    "81.31.156.245",
    "81.31.156.246",
    "83.138.12.246",
    "86.105.14.231",
    "86.105.14.232",
    "91.148.135.53",
    "91.201.67.121",
    "91.228.7.67",
    "92.118.205.75",
    "93.95.231.22",
    "94.75.232.90",
    "95.179.145.87",
    "95.179.245.162",
    "95.216.116.209",
];

/// Google's special-case crawlers (AdsBot-Google, Mediapartners-Google,
/// APIs-Google...): see the header of the file for its source and date.
const GOOGLE_SPECIAL: &str = include_str!("ranges/google-special-crawlers.txt");
/// Google's user-triggered fetchers (Site Verifier, Feedfetcher, Read Aloud...),
/// both lists Google publishes for them: see each file's header.
const GOOGLE_FETCHERS: &str = include_str!("ranges/google-user-triggered-fetchers.txt");
const GOOGLE_FETCHERS_GOOGLE: &str =
    include_str!("ranges/google-user-triggered-fetchers-google.txt");

/// The prefixes in one of the embedded list files (`#` starts a comment).
fn file_entries(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
}

/// A crawler that publishes the addresses it crawls from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crawler {
    Googlebot,
    /// Google's special-case crawlers (AdsBot, Mediapartners...).
    GoogleSpecial,
    /// Fetches Google makes because a user asked for them.
    GoogleFetcher,
    Bingbot,
    Applebot,
}

impl Crawler {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Crawler::Googlebot => "googlebot",
            Crawler::GoogleSpecial => "google-special",
            Crawler::GoogleFetcher => "google-fetcher",
            Crawler::Bingbot => "bingbot",
            Crawler::Applebot => "applebot",
        }
    }
}

fn parse_all(list: &[&str]) -> Vec<Cidr> {
    list.iter().filter_map(|c| Cidr::parse(c)).collect()
}

static CLOUDFLARE: LazyLock<Vec<Cidr>> = LazyLock::new(|| {
    let mut v = parse_all(CLOUDFLARE_V4);
    v.extend(parse_all(CLOUDFLARE_V6));
    v
});

/// Every crawler range, grouped by family and prefix length, each group a map
/// from the masked network to its crawler: a lookup costs one probe per
/// distinct length (a handful), not one per range (a few thousand).
struct CrawlerIndex {
    groups: Vec<(bool, u8, std::collections::HashMap<u128, Crawler>)>,
}

/// An address as a number of its family's width, and whether it is IPv6.
fn bits(ip: IpAddr) -> (bool, u128) {
    match net::normalize(ip) {
        IpAddr::V4(v4) => (false, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (true, u128::from(v6)),
    }
}

/// `x` (an address of `width` bits) with only its first `len` bits kept.
fn masked(x: u128, width: u8, len: u8) -> u128 {
    if len == 0 {
        return 0;
    }
    let keep = u128::MAX << (128 - u32::from(len));
    (x << (128 - u32::from(width))) & keep
}

impl CrawlerIndex {
    fn build(lists: &[(Crawler, Vec<Cidr>)]) -> CrawlerIndex {
        let mut groups: Vec<(bool, u8, std::collections::HashMap<u128, Crawler>)> = Vec::new();
        for (who, cidrs) in lists {
            for c in cidrs {
                let (v6, x) = bits(c.addr);
                let width = if v6 { 128 } else { 32 };
                let key = masked(x, width, c.prefix);
                match groups.iter_mut().find(|g| g.0 == v6 && g.1 == c.prefix) {
                    Some(g) => {
                        g.2.entry(key).or_insert(*who);
                    }
                    None => groups.push((v6, c.prefix, [(key, *who)].into_iter().collect())),
                }
            }
        }
        // Longest prefixes first: the most specific list names the crawler.
        groups.sort_by_key(|g| std::cmp::Reverse(g.1));
        CrawlerIndex { groups }
    }

    fn find(&self, ip: IpAddr) -> Option<Crawler> {
        let (v6, x) = bits(ip);
        let width = if v6 { 128 } else { 32 };
        self.groups
            .iter()
            .filter(|g| g.0 == v6)
            .find_map(|g| g.2.get(&masked(x, width, g.1)).copied())
    }
}

static CRAWLERS: LazyLock<CrawlerIndex> = LazyLock::new(|| {
    let google = |text: &str| -> Vec<Cidr> { file_entries(text).filter_map(Cidr::parse).collect() };
    let mut fetchers = google(GOOGLE_FETCHERS);
    fetchers.extend(google(GOOGLE_FETCHERS_GOOGLE));
    CrawlerIndex::build(&[
        (Crawler::Googlebot, parse_all(GOOGLEBOT)),
        (Crawler::GoogleSpecial, google(GOOGLE_SPECIAL)),
        (Crawler::GoogleFetcher, fetchers),
        (Crawler::Bingbot, parse_all(BINGBOT)),
        (Crawler::Applebot, parse_all(APPLEBOT)),
    ])
});

static JETPACK_NETS: LazyLock<Vec<Cidr>> = LazyLock::new(|| parse_all(JETPACK));

/// Cloudflare's ranges, parsed.
#[must_use]
pub fn cloudflare() -> &'static [Cidr] {
    &CLOUDFLARE
}

/// QUIC.cloud's nodes, parsed.
#[must_use]
pub fn quic_cloud() -> Vec<Cidr> {
    parse_all(QUIC_CLOUD)
}

/// Is `ip` one of Cloudflare's?
#[must_use]
pub fn is_cloudflare(ip: IpAddr) -> bool {
    net::in_any(&CLOUDFLARE, ip)
}

/// Is `ip` one of Automattic's Jetpack servers?
#[must_use]
pub fn is_jetpack(ip: IpAddr) -> bool {
    net::in_any(&JETPACK_NETS, ip)
}

/// The crawler whose published ranges hold `ip`, if any. Only the address
/// counts here: the User-Agent of a request is whatever its sender chose.
#[must_use]
pub fn verified_crawler(ip: IpAddr) -> Option<Crawler> {
    CRAWLERS.find(ip)
}

/// Why an address (or the /64 it starts) must never be banned on an order from
/// the hub, or `None` for an ordinary public address: a Cloudflare edge (every
/// visitor routed through it would be cut off), or address space that is not a
/// client on the Internet (private, carrier-grade NAT, unique-local,
/// link-local).
#[must_use]
pub fn never_ban_reason(ip: IpAddr) -> Option<&'static str> {
    let ip = net::normalize(ip);
    if is_cloudflare(ip) {
        return Some("cloudflare");
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_private() {
                Some("private")
            } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
                Some("cgnat")
            } else if v4.is_link_local() {
                Some("link-local")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if (s[0] & 0xfe00) == 0xfc00 {
                Some("ula")
            } else if (s[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn every_embedded_entry_parses() {
        for list in [
            CLOUDFLARE_V4,
            CLOUDFLARE_V6,
            JETPACK,
            GOOGLEBOT,
            BINGBOT,
            APPLEBOT,
            QUIC_CLOUD,
        ] {
            assert!(!list.is_empty());
            for c in list {
                assert!(Cidr::parse(c).is_some(), "{c}");
            }
        }
        for (text, at_least) in [
            (GOOGLE_SPECIAL, 200),
            (GOOGLE_FETCHERS, 1000),
            (GOOGLE_FETCHERS_GOOGLE, 400),
        ] {
            let entries: Vec<&str> = file_entries(text).collect();
            assert!(entries.len() >= at_least, "{}", entries.len());
            for c in entries {
                assert!(Cidr::parse(c).is_some(), "{c}");
            }
            // Each file says where it came from and when.
            assert!(text.starts_with("# Google ") && text.contains("fetched 2026-10-14"));
        }
    }

    #[test]
    fn googles_other_crawlers_and_fetchers_are_known_too() {
        assert_eq!(
            verified_crawler(ip("108.177.2.5")),
            Some(Crawler::GoogleSpecial)
        );
        assert_eq!(
            verified_crawler(ip("2001:4860:4801:2008::7")),
            Some(Crawler::GoogleSpecial)
        );
        assert_eq!(
            verified_crawler(ip("107.178.192.9")),
            Some(Crawler::GoogleFetcher)
        );
        assert_eq!(
            verified_crawler(ip("142.250.32.130")),
            Some(Crawler::GoogleFetcher)
        );
        assert_eq!(
            verified_crawler(ip("2404:f340:10:4000::1")),
            Some(Crawler::GoogleFetcher)
        );
        // The next /24 is not.
        assert_eq!(verified_crawler(ip("108.177.3.1")), None);
        assert_eq!(
            verified_crawler(ip("::ffff:66.249.66.1")),
            Some(Crawler::Googlebot)
        );
        // The index finds exactly what a scan of every range would.
        let all: Vec<(Crawler, Cidr)> = [
            (Crawler::Googlebot, parse_all(GOOGLEBOT)),
            (Crawler::Bingbot, parse_all(BINGBOT)),
            (Crawler::Applebot, parse_all(APPLEBOT)),
        ]
        .into_iter()
        .flat_map(|(w, v)| v.into_iter().map(move |c| (w, c)))
        .collect();
        for (who, c) in &all {
            assert_eq!(verified_crawler(c.addr), Some(*who), "{c:?}");
        }
    }

    #[test]
    fn crawlers_are_known_by_their_address_only() {
        // Googlebot's published IPv4 and IPv6 ranges.
        assert_eq!(
            verified_crawler(ip("66.249.66.1")),
            Some(Crawler::Googlebot)
        );
        assert_eq!(
            verified_crawler(ip("2001:4860:4801:10::1")),
            Some(Crawler::Googlebot)
        );
        assert_eq!(verified_crawler(ip("157.55.39.10")), Some(Crawler::Bingbot));
        assert_eq!(
            verified_crawler(ip("17.241.208.170")),
            Some(Crawler::Applebot)
        );
        // Anyone else, whatever User-Agent they send.
        assert_eq!(verified_crawler(ip("203.0.113.7")), None);
        assert_eq!(verified_crawler(ip("66.249.128.1")), None);
    }

    #[test]
    fn what_the_hub_may_never_ban() {
        for (s, why) in [
            ("104.16.1.1", "cloudflare"),
            ("2606:4700::1", "cloudflare"),
            ("10.1.2.3", "private"),
            ("172.16.0.1", "private"),
            ("192.168.1.1", "private"),
            ("100.64.0.1", "cgnat"),
            ("100.127.255.254", "cgnat"),
            ("169.254.1.1", "link-local"),
            ("fd00::1", "ula"),
            ("fc00::1", "ula"),
            ("fe80::1", "link-local"),
            ("::ffff:10.0.0.1", "private"),
        ] {
            assert_eq!(never_ban_reason(ip(s)), Some(why), "{s}");
        }
        for s in [
            "203.0.113.7",
            "100.128.0.1",
            "100.63.255.255",
            "2001:db8::1",
            "66.249.66.1",
        ] {
            assert_eq!(never_ban_reason(ip(s)), None, "{s}");
        }
    }

    #[test]
    fn jetpack_is_automattic_only() {
        assert!(is_jetpack(ip("192.0.100.5")));
        assert!(is_jetpack(ip("122.248.245.244")));
        assert!(!is_jetpack(ip("192.0.2.1")));
    }
}
