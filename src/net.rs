//! Dual-stack (IPv4 + IPv6) socket helpers.
//!
//! Listeners are bound to `[::]` with `IPV6_V6ONLY` turned off, so a single
//! socket accepts both IPv4 and IPv6 clients on every platform (Windows
//! defaults to v6-only, some Linux setups set `bindv6only=1`).
//! If IPv6 is unavailable (disabled in the kernel / container), we fall back
//! to a plain IPv4 `0.0.0.0` socket so behaviour is never worse than before.

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{TcpListener, UdpSocket};
use tracing::warn;

fn v6_any(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
}

fn v4_any(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
}

fn make_socket(addr: SocketAddr, ty: Type, proto: Protocol) -> io::Result<Socket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, ty, Some(proto))?;
    if addr.is_ipv6() {
        // Accept IPv4 clients too (as ::ffff:a.b.c.d).
        sock.set_only_v6(false)?;
    }
    // Match tokio's behaviour on Unix (fast restart); on Windows
    // SO_REUSEADDR would allow port hijacking, so it is not set there.
    #[cfg(unix)]
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock)
}

fn tcp_std(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let sock = make_socket(addr, Type::STREAM, Protocol::TCP)?;
    sock.listen(1024)?;
    Ok(sock.into())
}

fn udp_std(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    Ok(make_socket(addr, Type::DGRAM, Protocol::UDP)?.into())
}

/// Bind a std TCP listener on `[::]:port` (dual-stack), falling back to `0.0.0.0:port`.
fn bind_tcp_std(port: u16) -> io::Result<std::net::TcpListener> {
    match tcp_std(v6_any(port)) {
        Ok(l) => Ok(l),
        Err(e6) => {
            let l = tcp_std(v4_any(port))?;
            warn!(
                "[net] dual-stack TCP bind on port {} failed ({}), listening on IPv4 only",
                port, e6
            );
            Ok(l)
        }
    }
}

/// Dual-stack async TCP listener.
pub async fn bind_tcp(port: u16) -> io::Result<TcpListener> {
    TcpListener::from_std(bind_tcp_std(port)?)
}

/// Dual-stack async UDP socket.
pub fn bind_udp(port: u16) -> io::Result<UdpSocket> {
    let std_sock = match udp_std(v6_any(port)) {
        Ok(s) => s,
        Err(e6) => {
            let s = udp_std(v4_any(port))?;
            warn!(
                "[net] dual-stack UDP bind on port {} failed ({}), listening on IPv4 only",
                port, e6
            );
            s
        }
    };
    UdpSocket::from_std(std_sock)
}

/// Ephemeral-port UDP socket whose address family matches `target`
/// (used for the outbound leg of UDP forwarding).
pub async fn bind_udp_for(target: &SocketAddr) -> io::Result<UdpSocket> {
    let local = if target.is_ipv6() {
        v6_any(0)
    } else {
        v4_any(0)
    };
    UdpSocket::bind(local).await
}

/// Is `port` free to listen on (either dual-stack or IPv4)?
pub fn port_available(port: u16) -> bool {
    bind_tcp_std(port).is_ok()
}

/// Map `::ffff:a.b.c.d` back to plain IPv4 so IP filters, logs and
/// X-Forwarded-For see the same address regardless of socket family.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Canonical textual form of a peer address' IP.
pub fn ip_string(ip: IpAddr) -> String {
    canonical_ip(ip).to_string()
}

/// `host:port`, adding brackets around bare IPv6 literals (`::1` → `[::1]:80`).
pub fn host_port(host: &str, port: u16) -> String {
    let h = host.trim();
    if h.parse::<Ipv6Addr>().is_ok() {
        format!("[{}]:{}", h, port)
    } else {
        format!("{}:{}", h, port)
    }
}
