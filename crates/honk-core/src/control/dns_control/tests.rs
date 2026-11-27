use super::*;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::routing::Router;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Notify;

mod fixtures;
mod packet;
mod singleflight;
mod snapshots;
mod tcp;
mod udp;

use fixtures::*;
