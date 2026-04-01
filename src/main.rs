use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};

use rustun::*;

#[derive(Parser, Debug)]
#[command(
    name = "rustun",
    version = VERSION,
    about = "A tunnel and proxy tool written in Rust",
    disable_version_flag = true
)]
struct Cli {
    /// Listen address, can listen on multiple ports (required)
    #[arg(short = 'L', action = clap::ArgAction::Append)]
    listen: Vec<String>,

    /// Forward address, can make a forward chain
    #[arg(short = 'F', action = clap::ArgAction::Append)]
    forward: Vec<String>,

    /// Specify out connection mark
    #[arg(short = 'M', default_value = "0")]
    mark: i32,

    /// Configure file
    #[arg(short = 'C')]
    config_file: Option<String>,

    /// Interface to bind
    #[arg(short = 'I')]
    interface: Option<String>,

    /// Enable debug log
    #[arg(short = 'D')]
    debug: bool,

    /// Print version
    #[arg(short = 'V')]
    print_version: bool,

    /// Profiling HTTP server address (requires PROFILING env var)
    #[arg(short = 'P', default_value = ":6060")]
    pprof_addr: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.print_version {
        println!(
            "rustun {} ({} {}/{})",
            VERSION,
            "rustc",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        std::process::exit(0);
    }

    let log_level = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    if let Some(config_file) = &cli.config_file {
        match config::load_config(config_file) {
            Ok(cfg) => {
                if let Err(e) = start_from_config(cfg).await {
                    error!("Failed to start from config: {}", e);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                error!("Failed to load config: {}", e);
                std::process::exit(1);
            }
        }
    } else if !cli.listen.is_empty() {
        if let Err(e) = start_from_cli(&cli).await {
            error!("Failed to start: {}", e);
            std::process::exit(1);
        }
    } else {
        use clap::CommandFactory;
        Cli::command().print_help().ok();
        println!();
        std::process::exit(0);
    }

    tokio::signal::ctrl_c().await.ok();
    info!("Shutting down...");
}

async fn start_from_cli(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let chain = if cli.forward.is_empty() {
        Chain::empty()
    } else {
        let mut nodes = Vec::new();
        for f in &cli.forward {
            let node = Node::parse(f)?;
            nodes.push(node);
        }
        let mut chain = Chain::new(nodes);
        chain.mark = cli.mark;
        if let Some(ref iface) = cli.interface {
            chain.interface = iface.clone();
        }
        chain
    };

    for listen_addr in &cli.listen {
        let node = Node::parse(listen_addr)?;
        let chain = chain.clone();

        tokio::spawn(async move {
            if let Err(e) = run_server(node, chain).await {
                error!("Server error: {}", e);
            }
        });
    }

    Ok(())
}

async fn start_from_config(
    cfg: config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    for route in cfg.routes {
        let chain = if route.chain_nodes.is_empty() {
            Chain::empty()
        } else {
            let mut nodes = Vec::new();
            for ns in &route.chain_nodes {
                let node = Node::parse(ns)?;
                nodes.push(node);
            }
            let mut chain = Chain::new(nodes);
            chain.retries = route.retries;
            chain.mark = route.mark;
            chain.interface = route.interface.clone();
            chain
        };

        for ns in &route.serve_nodes {
            let node = Node::parse(ns)?;
            let chain = chain.clone();

            tokio::spawn(async move {
                if let Err(e) = run_server(node, chain).await {
                    error!("Server error: {}", e);
                }
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Build HandlerOptions by extracting all query parameters from the node
// ---------------------------------------------------------------------------

fn build_handler_options(node: &Node, chain: Chain) -> HandlerOptions {
    // --- Authentication ---
    let authenticator: Option<Arc<dyn Authenticator>> = {
        // 1. Try loading from secrets file
        if let Some(secrets_path) = node.get("secrets") {
            match load_secrets_file(secrets_path) {
                Ok(au) => Some(Arc::new(au)),
                Err(e) => {
                    warn!("failed to load secrets file {}: {}", secrets_path, e);
                    None
                }
            }
        }
        // 2. Fall back to inline credentials
        else if let Some((ref user, ref pass)) = node.user {
            let mut kvs = HashMap::new();
            kvs.insert(user.clone(), pass.clone().unwrap_or_default());
            Some(Arc::new(LocalAuthenticator::new(kvs)))
        } else {
            None
        }
    };

    // --- Bypass ---
    let bypass: Option<Arc<bypass::Bypass>> = node.get("bypass").map(|s| {
        let (reversed, patterns_str) = if let Some(stripped) = s.strip_prefix('~') {
            (true, stripped)
        } else {
            (false, s)
        };
        let patterns: Vec<&str> = patterns_str.split(',').filter(|p| !p.is_empty()).collect();
        Arc::new(bypass::Bypass::from_patterns(reversed, &patterns))
    });

    // --- Whitelist / Blacklist ---
    let whitelist = node
        .get("whitelist")
        .and_then(|s| Permissions::parse(s).ok());
    let blacklist = node
        .get("blacklist")
        .and_then(|s| Permissions::parse(s).ok());

    // --- Hosts ---
    let _hosts_opt = node.get("hosts").and_then(|path| {
        let f = std::fs::File::open(path).ok()?;
        let h = Hosts::new(vec![]);
        h.reload(f).ok()?;
        Some(h)
    });

    // --- Timeout / Retries ---
    let timeout = node.get_duration("timeout");
    let retries = node.get_int("retry") as usize;

    // --- Proxy Agent ---
    let proxy_agent = node
        .get("proxyAgent")
        .unwrap_or("")
        .to_string();

    // --- Host (for SNI proxy) ---
    let host = node
        .get("host")
        .unwrap_or("")
        .to_string();

    HandlerOptions {
        addr: node.addr.clone(),
        chain: Some(chain),
        users: node
            .user
            .as_ref()
            .map(|u| vec![u.clone()])
            .unwrap_or_default(),
        authenticator,
        whitelist,
        blacklist,
        bypass,
        retries,
        timeout,
        node: Some(node.clone()),
        host,
        proxy_agent,
    }
}

/// Load a secrets file into a LocalAuthenticator.
/// Format: one `username password` pair per line. Lines starting with # are comments.
fn load_secrets_file(path: &str) -> Result<LocalAuthenticator, std::io::Error> {
    let f = std::fs::File::open(path)?;
    let au = LocalAuthenticator::new(HashMap::new());
    au.reload(f)?;
    Ok(au)
}

// ---------------------------------------------------------------------------
// Server startup -- maps protocol schemes to handlers
// ---------------------------------------------------------------------------

async fn run_server(
    node: Node,
    chain: Chain,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let handler_opts = build_handler_options(&node, chain);

    let addr = node.addr.clone();
    let protocol = node.protocol.clone();
    let _transport = node.transport.clone();
    let remote = node.remote.clone();

    info!(
        "{}://{} on {}",
        if protocol.is_empty() { "auto" } else { &protocol },
        addr,
        addr
    );

    match protocol.as_str() {
        // --- Proxy protocols ---
        "http" => {
            let handler = HttpHandler::new(handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "socks5" | "socks" => {
            let handler = Socks5Handler::new(handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "socks4" | "socks4a" => {
            let handler = Socks4Handler::new(handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "ss" => {
            let method = node.get("method").unwrap_or("plain");
            let password = node
                .user
                .as_ref()
                .and_then(|(_, p)| p.clone())
                .unwrap_or_default();
            let handler = ShadowHandler::new(method, &password, handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "ssu" => {
            let method = node.get("method").unwrap_or("plain");
            let password = node
                .user
                .as_ref()
                .and_then(|(_, p)| p.clone())
                .unwrap_or_default();
            let handler = ShadowHandler::new(method, &password, handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "http2" => {
            let handler = Http2Handler::new(handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "relay" => {
            let handler = RelayHandler::new(&remote, handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "sni" => {
            let handler = SniHandler::new(handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }

        // --- Forwarding ---
        "tcp" => {
            let handler = TcpDirectForwardHandler::new(&remote, handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "udp" => {
            let handler = UdpDirectForwardHandler::new(&remote, handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "rtcp" => {
            let handler = TcpRemoteForwardHandler::new(&remote, handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "rudp" => {
            // Remote UDP forwarding -- handler accepts TCP, forwards to remote UDP
            let handler = UdpDirectForwardHandler::new(&remote, handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }

        // --- DNS ---
        "dns" | "dot" | "doh" => {
            let handler = DnsHandler::new(&remote, handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }

        // --- Transparent proxy ---
        "red" | "redirect" => {
            let handler = TcpRedirectHandler::new(handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }
        "redu" | "redirectu" => {
            let handler = redirect::UdpRedirectHandler::new(handler_opts);
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }

        // --- SSH ---
        "forward" => {
            let handler = SshForwardHandler::new(handler_opts, SshConfig::default());
            let server = Server::new(&addr, handler).await?;
            server.serve().await
        }

        // --- Default: auto-detect or TCP forward ---
        _ => {
            if !remote.is_empty() {
                let handler = TcpDirectForwardHandler::new(&remote, handler_opts);
                let server = Server::new(&addr, handler).await?;
                server.serve().await
            } else {
                let handler = handler::AutoHandler::new(handler_opts);
                let server = Server::new(&addr, handler).await?;
                server.serve().await
            }
        }
    }
}
