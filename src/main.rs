use std::{env, error::Error, net::SocketAddr, path::PathBuf, process};
use timecurrency_node::{app::App, store::Store};

const USAGE: &str = "time-node --devnet --db PATH [--listen 127.0.0.1:26658]\n\nDevelopment network only. Public monetary launch is disabled.\nCometBFT v0.38.26 must run separately and connect to this loopback ABCI endpoint.";

#[derive(Debug, PartialEq)]
struct Options {
    db: PathBuf,
    listen: SocketAddr,
}

fn options(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut args = args.into_iter();
    let mut devnet = false;
    let mut db = None;
    let mut listen = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--devnet" if !devnet => devnet = true,
            "--db" if db.is_none() => {
                db = Some(PathBuf::from(args.next().ok_or("--db needs a path")?))
            }
            "--listen" if listen.is_none() => {
                listen = Some(args.next().ok_or("--listen needs an address")?)
            }
            _ => return Err(format!("unsupported or duplicate argument: {arg}")),
        }
    }
    if !devnet {
        return Err("--devnet is required; live monetary operation is disabled".into());
    }
    let db =
        db.ok_or("--db is required; storage is never silently placed in a temporary directory")?;
    if db.as_os_str().is_empty() {
        return Err("empty database path".into());
    }
    let listen: SocketAddr = listen
        .unwrap_or_else(|| "127.0.0.1:26658".into())
        .parse()
        .map_err(|_| "--listen must be a literal loopback IP and port")?;
    if !listen.ip().is_loopback() || listen.port() == 0 {
        return Err("ABCI must listen on a nonzero loopback port".into());
    }
    Ok(Options { db, listen })
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("{USAGE}");
        return Ok(());
    }
    if args == ["--version"] {
        println!(
            "time-node {} devnet-only publicLaunchAllowed=false",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    let options = options(args).map_err(std::io::Error::other)?;
    let app = App::new(Store::open(&options.db)?)?;
    // A failed ABCI invariant/storage operation cannot leave sibling request
    // threads alive to acknowledge a later request. Restart from durable state.
    std::panic::set_hook(Box::new(|_| {
        eprintln!(
            "Fatal application invariant or persistence failure; stopping all ABCI connections."
        );
        process::exit(1);
    }));
    eprintln!(
        "DEVNET ONLY: local accounts, synthetic auction, staking and recovery laboratory. Fixed validators; no real Bitcoin verification or public monetary launch."
    );
    eprintln!("ABCI listening on {}", options.listen);
    timecurrency_node::transport::serve(options.listen, app)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}\n\n{USAGE}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, String> {
        options(args.iter().map(|s| (*s).into()))
    }

    #[test]
    fn refuses_live_mode_and_public_abci() {
        assert!(parse(&["--db", "state.redb"]).is_err());
        assert!(
            parse(&[
                "--devnet",
                "--db",
                "state.redb",
                "--listen",
                "0.0.0.0:26658"
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "--devnet",
                "--db",
                "state.redb",
                "--listen",
                "example.com:26658"
            ])
            .is_err()
        );
        assert!(parse(&["--devnet", "--db", "state.redb", "--mainnet"]).is_err());
        assert!(
            parse(&[
                "--devnet",
                "--db",
                "state.redb",
                "--listen",
                "127.0.0.1:1",
                "--listen",
                "127.0.0.1:2"
            ])
            .is_err()
        );
    }

    #[test]
    fn requires_explicit_state_and_accepts_loopback() {
        assert!(parse(&["--devnet"]).is_err());
        assert_eq!(
            parse(&["--devnet", "--db", "state.redb"])
                .unwrap()
                .listen
                .to_string(),
            "127.0.0.1:26658"
        );
    }
}
