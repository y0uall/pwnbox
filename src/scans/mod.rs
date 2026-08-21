use std::sync::LazyLock;

use regex::Regex;

/// A line that starts with a port number, e.g. "22/tcp" or "161/udp", as emitted
/// by nmap. Shared by the TCP and UDP scanners to pick port lines out of raw tool
/// output — each previously kept its own byte-identical private copy.
pub(crate) static RE_PORT_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\d+/").unwrap());

pub mod connectivity;
pub mod dns;
pub mod ftp;
pub mod kerberos;
pub mod ldap;
pub mod mssql;
pub mod mysql;
pub mod nfs;
pub mod postgres;
pub mod redis;
pub mod rpc;
pub mod smb;
pub mod smtp;
pub mod snmp;
pub mod ssh;
pub mod tcp;
pub mod udp;
pub mod web;
pub mod winrm;
