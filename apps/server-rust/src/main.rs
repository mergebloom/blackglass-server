mod auth;
mod config;
mod db;
mod model;
mod server;

use anyhow::{Result, bail};
use std::{
    io::{self, Read},
    path::PathBuf,
};
use tracing_subscriber::EnvFilter;

const NAME: &str = "blackglass-server";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => {
            let config = config::Config::from_env()?;
            init_tracing(config.json_logs);
            server::run(config).await
        }
        [command] if command == "serve" => {
            let config = config::Config::from_env()?;
            init_tracing(config.json_logs);
            server::run(config).await
        }
        [command] if command == "--help" || command == "-h" || command == "help" => {
            print_help();
            Ok(())
        }
        [command] if command == "--version" || command == "-V" || command == "version" => {
            println!("{NAME} {VERSION}");
            Ok(())
        }
        [command] if command == "hash-password" => {
            let mut password = String::new();
            io::stdin().read_to_string(&mut password)?;
            let password = password.trim_end_matches(['\r', '\n']);
            if password.is_empty() {
                bail!("read a non-empty password from stdin")
            }
            println!("{}", auth::hash_password(password)?);
            Ok(())
        }
        [command, source, output] if command == "backup" => {
            let source = PathBuf::from(source);
            let output = PathBuf::from(output);
            db::backup_database(&source, &output)?;
            println!("backup verified: {}", output.display());
            Ok(())
        }
        [command, path] if command == "verify" => {
            let path = PathBuf::from(path);
            db::verify_database(&path)?;
            println!("database verified: {}", path.display());
            Ok(())
        }
        [command, source, destination] if command == "restore" => {
            let source = PathBuf::from(source);
            let destination = PathBuf::from(destination);
            db::restore_database(&source, &destination)?;
            println!("restore verified: {}", destination.display());
            Ok(())
        }
        [command, source, destination] if command == "migrate-legacy" => {
            let source = PathBuf::from(source);
            let destination = PathBuf::from(destination);
            db::migrate_legacy_database(&source, &destination)?;
            println!(
                "legacy migration verified: {} -> {}",
                source.display(),
                destination.display()
            );
            Ok(())
        }
        [command, path] if command == "revoke-all-sessions" => {
            let path = PathBuf::from(path);
            println!("revoked sessions: {}", db::revoke_all_sessions(&path)?);
            Ok(())
        }
        _ => bail!("invalid arguments; run `{NAME} --help` for usage"),
    }
}

fn print_help() {
    println!(
        "{NAME} {VERSION}\n\n\
Usage:\n  {NAME} serve\n  {NAME} hash-password\n  {NAME} backup <database> <output>\n  \
{NAME} verify <database>\n  {NAME} restore <backup> <new-database>\n  \
{NAME} migrate-legacy <legacy-database> <new-database>\n  \
{NAME} revoke-all-sessions <database>\n  {NAME} --version\n  {NAME} --help"
    );
}
fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=warn"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if json {
        builder.json().init()
    } else {
        builder.compact().init()
    }
}
