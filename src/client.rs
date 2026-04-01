use std::time::Duration;

use crate::chain::Chain;

/// Client is a proxy client with a connector and transporter.
#[derive(Clone, Debug)]
pub struct Client {
    pub connector: ConnectorType,
    pub transporter: TransporterType,
}

#[derive(Clone, Debug)]
pub enum ConnectorType {
    Http,
    Socks5,
    Forward,
    Auto,
}

#[derive(Clone, Debug)]
pub enum TransporterType {
    Tcp,
    Tls,
    Ws,
}

/// Connector trait for connecting to destination.
pub trait Connector: Send + Sync {
    fn connect_type(&self) -> &str;
}

/// Transporter trait for handshaking with proxy server.
pub trait Transporter: Send + Sync {
    fn transport_type(&self) -> &str;
    fn multiplex(&self) -> bool {
        false
    }
}

/// DialOptions for Transporter.
#[derive(Clone, Default)]
pub struct DialOptions {
    pub timeout: Duration,
    pub chain: Option<Chain>,
    pub host: String,
}

/// HandshakeOptions for Transporter handshake.
#[derive(Clone, Default)]
pub struct HandshakeOptions {
    pub addr: String,
    pub host: String,
    pub user: Option<(String, Option<String>)>,
    pub timeout: Duration,
}

/// ConnectOptions for Connector.Connect.
#[derive(Clone, Default)]
pub struct ConnectOptions {
    pub addr: String,
    pub timeout: Duration,
    pub user: Option<(String, Option<String>)>,
    pub user_agent: String,
    pub no_tls: bool,
    pub no_delay: bool,
}
