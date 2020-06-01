use std::fs::File;
use std::future::Future;
use std::io::{self, BufReader, Cursor, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::Fuse;
use futures::{ready, FutureExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{NoClientAuth, ServerConfig, TLSError};

use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};

use crate::transport::Transport;

/// Represents errors that can occur building the TlsConfig
#[derive(Debug)]
pub enum TlsConfigError {
    Io(io::Error),
    /// An Error parsing the Certificate
    CertParseError,
    /// An Error parsing a Pkcs8 key
    Pkcs8ParseError,
    /// An Error parsing a Rsa key
    RsaParseError,
    /// An error from an empty key
    EmptyKey,
    /// An error from an invalid key
    InvalidKey(TLSError),
}

impl std::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsConfigError::Io(err) => err.fmt(f),
            TlsConfigError::CertParseError => write!(f, "certificate parse error"),
            TlsConfigError::Pkcs8ParseError => write!(f, "pkcs8 parse error"),
            TlsConfigError::RsaParseError => write!(f, "rsa parse error"),
            TlsConfigError::EmptyKey => write!(f, "key contains no private key"),
            TlsConfigError::InvalidKey(err) => write!(f, "key contains an invalid key, {}", err),
        }
    }
}

impl std::error::Error for TlsConfigError {}

/// Builder to set the configuration for the Tls server.
pub struct TlsConfigBuilder {
    cert: Box<dyn Read + Send + Sync>,
    key: Box<dyn Read + Send + Sync>,
}

impl std::fmt::Debug for TlsConfigBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        f.debug_struct("TlsConfigBuilder").finish()
    }
}

impl TlsConfigBuilder {
    /// Create a new TlsConfigBuilder
    pub fn new() -> TlsConfigBuilder {
        TlsConfigBuilder {
            key: Box::new(io::empty()),
            cert: Box::new(io::empty()),
        }
    }

    /// sets the Tls key via File Path, returns `TlsConfigError::IoError` if the file cannot be open
    pub fn key_path(mut self, path: impl AsRef<Path>) -> Self {
        self.key = Box::new(LazyFile {
            path: path.as_ref().into(),
            file: None,
        });
        self
    }

    /// sets the Tls key via bytes slice
    pub fn key(mut self, key: &[u8]) -> Self {
        self.key = Box::new(Cursor::new(Vec::from(key)));
        self
    }

    /// Specify the file path for the TLS certificate to use.
    pub fn cert_path(mut self, path: impl AsRef<Path>) -> Self {
        self.cert = Box::new(LazyFile {
            path: path.as_ref().into(),
            file: None,
        });
        self
    }

    /// sets the Tls certificate via bytes slice
    pub fn cert(mut self, cert: &[u8]) -> Self {
        self.cert = Box::new(Cursor::new(Vec::from(cert)));
        self
    }

    /// build ServerConfig
    pub fn build(mut self) -> Result<ServerConfig, TlsConfigError> {
        let mut cert_rdr = BufReader::new(self.cert);
        let cert = tokio_rustls::rustls::internal::pemfile::certs(&mut cert_rdr)
            .map_err(|()| TlsConfigError::CertParseError)?;

        let key = {
            // convert it to Vec<u8> to allow reading it again if key is RSA
            let mut key_vec = Vec::new();
            self.key
                .read_to_end(&mut key_vec)
                .map_err(TlsConfigError::Io)?;

            if key_vec.is_empty() {
                return Err(TlsConfigError::EmptyKey);
            }

            let mut pkcs8 = tokio_rustls::rustls::internal::pemfile::pkcs8_private_keys(
                &mut key_vec.as_slice(),
            )
            .map_err(|()| TlsConfigError::Pkcs8ParseError)?;

            if !pkcs8.is_empty() {
                pkcs8.remove(0)
            } else {
                let mut rsa = tokio_rustls::rustls::internal::pemfile::rsa_private_keys(
                    &mut key_vec.as_slice(),
                )
                .map_err(|()| TlsConfigError::RsaParseError)?;

                if !rsa.is_empty() {
                    rsa.remove(0)
                } else {
                    return Err(TlsConfigError::EmptyKey);
                }
            }
        };

        let mut config = ServerConfig::new(NoClientAuth::new());
        config
            .set_single_cert(cert, key)
            .map_err(|err| TlsConfigError::InvalidKey(err))?;
        config.set_protocols(&["h2".into(), "http/1.1".into()]);
        Ok(config)
    }
}

struct LazyFile {
    path: PathBuf,
    file: Option<File>,
}

impl LazyFile {
    fn lazy_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.file.is_none() {
            self.file = Some(File::open(&self.path)?);
        }

        self.file.as_mut().unwrap().read(buf)
    }
}

impl Read for LazyFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lazy_read(buf).map_err(|err| {
            let kind = err.kind();
            io::Error::new(
                kind,
                format!("error reading file ({:?}): {}", self.path.display(), err),
            )
        })
    }
}

impl<Fut, C> Transport for TlsStream<Fut, C>
where
    C: FnMut(Option<String>) -> Fut + Unpin + Send + Clone + 'static,
    Fut: Future<Output = Option<Arc<ServerConfig>>> + Unpin + 'static,
{
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Some(self.local_addr)
    }
}

enum SniError<'a> {
    TooLong,
    ParseError(nom::Err<(&'a [u8], nom::error::ErrorKind)>),
}

pub struct RetrieveSniHostname {
    stream: Option<AddrStream>,
    buf: Vec<u8>,
}

impl RetrieveSniHostname {
    fn new(stream: AddrStream) -> Self {
        RetrieveSniHostname {
            stream: Some(stream),
            buf: vec![0u8; 700],
        }
    }

    fn decode_hostname(bytes: &[u8]) -> Result<Option<Option<String>>, SniError> {
        match tls_parser::parse_tls_plaintext(bytes) {
            Ok((_rem, record)) => Ok(Some(
                record
                    .msg
                    .into_iter()
                    .filter_map(|msg| match msg {
                        tls_parser::tls::TlsMessage::Handshake(handshake) => match handshake {
                            tls_parser::tls::TlsMessageHandshake::ClientHello(hello) => {
                                if let Some(ext) = hello.ext {
                                    tls_parser::tls_extensions::parse_tls_extensions(ext)
                                        .ok()
                                        .and_then(|(_, ext)| {
                                            ext
                                                .into_iter()
                                                .filter_map(|ext| match ext {
                                                    tls_parser::tls_extensions::TlsExtension::SNI(snis) => snis
                                                        .into_iter()
                                                        .filter_map(|(sni_type, value)| {
                                                            if tls_parser::tls_extensions::SNIType::HostName
                                                                == sni_type
                                                            {
                                                                Some(value)
                                                            } else {
                                                                None
                                                            }
                                                        })
                                                        .next(),
                                                    _ => None,
                                                })
                                                .next()
                                        })
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        },
                        _ => None,
                    })
                    .next()
                    .and_then(|m| String::from_utf8(m.to_vec()).ok()),
            )),
            Err(nom::Err::Incomplete(_needed)) => {
                if bytes.len() < 16536 {
                    Ok(None)
                } else {
                    Err(SniError::TooLong)
                }
            }
            Err(e) => Err(SniError::ParseError(e)),
        }
    }
}

impl Future for RetrieveSniHostname {
    type Output = Result<(Option<String>, AddrStream), io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let pin = self.get_mut();

        let hostname = if let Some(stream) = &mut pin.stream {
            loop {
                let num_bytes_read = ready!(stream.poll_peek(cx, &mut pin.buf))?;
                match Self::decode_hostname(&pin.buf[..num_bytes_read]) {
                    Ok(Some(hostname)) => {
                        break hostname;
                    }
                    Ok(None) => {
                        pin.buf.resize(pin.buf.len() * 2, 0);
                    }
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "bad TLS ClientHello",
                        )));
                    }
                }
            }
        } else {
            return Poll::Pending;
        };

        return Poll::Ready(Ok((hostname, pin.stream.take().unwrap())));
    }
}

enum State<Fut, C>
where
    C: FnMut(Option<String>) -> Fut + Unpin + Send + Clone + 'static,
    Fut: Future<Output = Option<Arc<ServerConfig>>> + Unpin + 'static,
{
    WaitClientHello(RetrieveSniHostname, C),
    ResolveConfig(Fut, Option<AddrStream>),
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub(crate) struct TlsStream<Fut, C>
where
    C: FnMut(Option<String>) -> Fut + Unpin + Send + Clone + 'static,
    Fut: Future<Output = Option<Arc<ServerConfig>>> + Unpin + 'static,
{
    state: State<Fut, C>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl<Fut, C> TlsStream<Fut, C>
where
    C: FnMut(Option<String>) -> Fut + Unpin + Send + Clone + 'static,
    Fut: Future<Output = Option<Arc<ServerConfig>>> + Unpin + 'static,
{
    fn new(stream: AddrStream, config_fn: C) -> TlsStream<Fut, C> {
        let remote_addr = stream.remote_addr();
        let local_addr = stream.local_addr();
        TlsStream {
            state: State::WaitClientHello(RetrieveSniHostname::new(stream), config_fn),
            remote_addr,
            local_addr,
        }
    }
}

impl<Fut, C> AsyncRead for TlsStream<Fut, C>
where
    C: FnMut(Option<String>) -> Fut + Unpin + Send + Clone + 'static,
    Fut: Future<Output = Option<Arc<ServerConfig>>> + Unpin + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        loop {
            match pin.state {
                State::WaitClientHello(ref mut peek, ref mut config_fn) => {
                    match ready!(Pin::new(peek).poll(cx)) {
                        Ok((hostname, stream)) => {
                            pin.state = State::ResolveConfig((config_fn)(hostname), Some(stream));
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }
                State::ResolveConfig(ref mut resolve_config, ref mut stream) => {
                    match ready!(Pin::new(resolve_config).poll(cx)) {
                        Some(config) => {
                            let accept = tokio_rustls::TlsAcceptor::from(config)
                                .accept(stream.take().unwrap());
                            pin.state = State::Handshaking(accept);
                        }
                        None => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                "no certificate selected",
                            )));
                        }
                    }
                }
                State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                    Ok(mut stream) => {
                        let result = Pin::new(&mut stream).poll_read(cx, buf);
                        pin.state = State::Streaming(stream);
                        return result;
                    }
                    Err(err) => return Poll::Ready(Err(err)),
                },
                State::Streaming(ref mut stream) => {
                    return Pin::new(stream).poll_read(cx, buf);
                }
            }
        }
    }
}

impl<Fut, C> AsyncWrite for TlsStream<Fut, C>
where
    C: FnMut(Option<String>) -> Fut + Unpin + Send + Clone + 'static,
    Fut: Future<Output = Option<Arc<ServerConfig>>> + Unpin + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        loop {
            match pin.state {
                State::WaitClientHello(ref mut peek, ref mut config_fn) => {
                    match ready!(Pin::new(peek).poll(cx)) {
                        Ok((hostname, stream)) => {
                            pin.state = State::ResolveConfig((config_fn)(hostname), Some(stream));
                        }
                        Err(err) => return Poll::Ready(Err(err)),
                    }
                }
                State::ResolveConfig(ref mut resolve_config, ref mut stream) => {
                    match ready!(Pin::new(resolve_config).poll(cx)) {
                        Some(config) => {
                            let accept = tokio_rustls::TlsAcceptor::from(config)
                                .accept(stream.take().unwrap());
                            pin.state = State::Handshaking(accept);
                        }
                        None => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                "no certificate selected",
                            )));
                        }
                    }
                }
                State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                    Ok(mut stream) => {
                        let result = Pin::new(&mut stream).poll_write(cx, buf);
                        pin.state = State::Streaming(stream);
                        return result;
                    }
                    Err(err) => return Poll::Ready(Err(err)),
                },
                State::Streaming(ref mut stream) => return Pin::new(stream).poll_write(cx, buf),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::WaitClientHello(_, _) => Poll::Ready(Ok(())),
            State::ResolveConfig(_, _) => Poll::Ready(Ok(())),
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::WaitClientHello(_, _) => Poll::Ready(Ok(())),
            State::ResolveConfig(_, _) => Poll::Ready(Ok(())),
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) struct TlsAcceptor<Fut, C>
where
    C: FnMut(Option<String>) -> Fut + Unpin + Send + Clone + 'static,
    Fut: Future<Output = Option<Arc<ServerConfig>>> + Unpin + 'static,
{
    config_fn: C,
    incoming: AddrIncoming,
    sock: Option<AddrStream>,
}

impl<Fut, C> TlsAcceptor<Fut, C>
where
    C: FnMut(Option<String>) -> Fut + Unpin + Send + Clone + 'static,
    Fut: Future<Output = Option<Arc<ServerConfig>>> + Unpin + 'static,
{
    pub(crate) fn new(config_fn: C, incoming: AddrIncoming) -> TlsAcceptor<Fut, C> {
        TlsAcceptor {
            config_fn,
            incoming,
            sock: None,
        }
    }
}

impl<Fut, C> Accept for TlsAcceptor<Fut, C>
where
    C: FnMut(Option<String>) -> Fut + Unpin + Send + Clone + 'static,
    Fut: Future<Output = Option<Arc<ServerConfig>>> + Unpin + 'static,
{
    type Conn = TlsStream<Fut, C>;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config_fn.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_cert_key() {
        TlsConfigBuilder::new()
            .key_path("examples/tls/key.rsa")
            .cert_path("examples/tls/cert.pem")
            .build()
            .unwrap();
    }

    #[test]
    fn bytes_cert_key() {
        let key = include_str!("../examples/tls/key.rsa");
        let cert = include_str!("../examples/tls/cert.pem");

        TlsConfigBuilder::new()
            .key(key.as_bytes())
            .cert(cert.as_bytes())
            .build()
            .unwrap();
    }
}
