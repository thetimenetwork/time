use std::{env, error::Error, net::SocketAddr, path::PathBuf, process};
use timecurrency_v4::app::App;

const USAGE: &str = "time-node-v4 --devnet --db PATH [--listen 127.0.0.1:26658]\n\nProtocol-4 development candidate. Public monetary launch is disabled.\nCometBFT v0.38.26 runs separately and connects to this loopback ABCI endpoint.";

#[derive(Debug, PartialEq)]
struct Options {
    db: PathBuf,
    listen: SocketAddr,
    audit: bool,
}

fn options(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut args = args.into_iter();
    let mut devnet = false;
    let mut db = None;
    let mut listen = None;
    let mut audit = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--audit" if !audit => audit = true,
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
    Ok(Options { db, listen, audit })
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("{USAGE}");
        return Ok(());
    }
    if args == ["--version"] {
        println!(
            "time-node-v4 {} devnet-only publicLaunchAllowed=false",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    let options = options(args).map_err(std::io::Error::other)?;
    if options.audit {
        let engine = timecurrency_v4::engine::Engine::open_with_history(
            timecurrency_v4::store::Store::open(&options.db)?,
            options.db.with_extension("history"),
        )?;
        let meta = engine.meta().ok_or("database is uninitialized")?;
        let audit = engine.audit_with_progress(|p| {
            eprintln!("audit phase={} processed={}", p.phase, p.processed)
        })?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"status":"PASS_OFFLINE_AUTHENTICATED_RECOUNT","protocol":"4","network_id":meta.network_id,"height":meta.height.to_string(),"root":hex::encode(engine.head()?.ok_or("missing head")?.root),"elapsed_micros":meta.elapsed_micros()?.to_string(),"bank":meta.bank.to_string(),"liquid":audit.liquid.to_string(),"pos_escrow":meta.pos_assets_total.to_string(),"auction_reserve":meta.auction_reserve_total.to_string(),"accounts":audit.account_count.to_string(),"authenticated_leaves":audit.authenticated_leaves.to_string(),"authenticated_nodes":audit.authenticated_tree_nodes.to_string(),"history_archive_verified":audit.history_archive_verified,"history_pruned_through":meta.history_pruned_through.to_string(),"public_launch_allowed":false})
            )?
        );
        return Ok(());
    }
    let app = App::open(&options.db)?;
    // A failed ABCI invariant/storage operation cannot leave sibling request
    // threads alive to acknowledge a later request. Restart from durable state.
    std::panic::set_hook(Box::new(|_| {
        eprintln!(
            "Fatal application invariant or persistence failure; stopping all ABCI connections."
        );
        process::exit(1);
    }));
    let maintenance = app.clone();
    std::thread::Builder::new()
        .name("time-state-gc".into())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(25));
                if let Err(error) = maintenance.maintain_idle() {
                    eprintln!("Durable state maintenance failed; stopping: {error}");
                    process::exit(1);
                }
            }
        })?;
    eprintln!(
        "DEVNET ONLY: protocol 4 authenticated Bitcoin receipts and dynamic PoS. Public monetary launch disabled."
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
