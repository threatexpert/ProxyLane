//! Minimal Quinn UDP adapter for the existing Winsock sendto/recvfrom Hook path.
//! One datagram per call; deliberately no ECN, GSO, GRO or source-IP selection.
//! A production in-process adapter should replace this I/O with bounded PRC queues.
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, UdpPoller,
};
use std::{
    future::Future,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};

#[derive(Debug)]
pub struct RouteSocket(tokio::net::UdpSocket, SocketAddr);
impl RouteSocket {
    pub fn bind(remote: SocketAddr) -> io::Result<Arc<Self>> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        // One endpoint per upstream route. Hook redirects this connected socket
        // to its PRC peer. Replies must be labelled with the logical remote for
        // Quinn, not the PRC loopback address; the connected socket filters peers.
        socket.connect(remote)?;
        socket.set_nonblocking(true)?;
        Ok(Arc::new(Self(
            tokio::net::UdpSocket::from_std(socket)?,
            remote,
        )))
    }
}
type Writable = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;
struct Poller {
    socket: Arc<RouteSocket>,
    pending: Option<Writable>,
}
impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoutePoller")
    }
}
impl UdpPoller for Poller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending.is_none() {
            let socket = self.socket.clone();
            self.pending = Some(Box::pin(async move { socket.0.writable().await }));
        }
        let result = self.pending.as_mut().unwrap().as_mut().poll(cx);
        if result.is_ready() {
            self.pending = None;
        }
        result
    }
}
impl AsyncUdpSocket for RouteSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller {
            socket: self,
            pending: None,
        })
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "GSO is disabled for route probe",
            ));
        }
        if transmit.destination != self.1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wrong logical route",
            ));
        }
        let sent = self.0.try_send(transmit.contents)?;
        if sent != transmit.contents.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP send"));
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut buffer = tokio::io::ReadBuf::new(&mut bufs[0]);
        ready!(self.0.poll_recv(cx, &mut buffer))?;
        let len = buffer.filled().len();
        meta[0] = RecvMeta {
            addr: self.1,
            len,
            stride: len,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}
