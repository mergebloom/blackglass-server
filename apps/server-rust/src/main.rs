mod admin;
mod auth;
mod config;
mod db;
mod model;
mod server;

use anyhow::{Context, Result, bail};
use std::{
    io::{self, Read},
    path::PathBuf,
};
use tracing_subscriber::EnvFilter;

const NAME: &str = "blackglass-server";
const VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const SOURCE_REVISION: &str = match option_env!("BLACKGLASS_SOURCE_REVISION") {
    Some(revision) => revision,
    None => "unknown",
};

#[tokio::main(worker_threads = 2)]
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
        [command] if command == "build-info" => {
            println!(
                "{}",
                serde_json::json!({
                    "name": NAME,
                    "version": VERSION,
                    "sourceRevision": SOURCE_REVISION,
                })
            );
            Ok(())
        }
        [command] if command == "hash-password" => {
            let password = read_password()?;
            println!("{}", auth::hash_password(&password)?);
            Ok(())
        }
        [scope, command, database] if scope == "user" && command == "list" => {
            let database = PathBuf::from(database);
            let _database_lock = server::acquire_database_lock(&database)?;
            let db = db::Db::open_offline_under_lock(&database)?;
            println!("{}", serde_json::to_string(&db.list_users()?)?);
            Ok(())
        }
        [scope, command, database, email, name] if scope == "user" && command == "create" => {
            let database = PathBuf::from(database);
            let _database_lock = server::acquire_database_lock(&database)?;
            let password = read_password()?;
            let password_hash = auth::hash_password(&password)?;
            let user_id = match std::fs::symlink_metadata(&database) {
                Ok(_) => {
                    let db = db::Db::open_offline_under_lock(&database)?;
                    db.create_user(email, name, &password_hash)?
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let initial_user = db::InitialUser::new(email, name, &password_hash)?;
                    let db = db::Db::initialize(&database, &initial_user)?;
                    db.list_users()?
                        .into_iter()
                        .next()
                        .context("initialized database has no user")?
                        .id
                }
                Err(error) => return Err(error.into()),
            };
            println!("created user: {user_id}");
            Ok(())
        }
        [scope, command, database, user_id] if scope == "user" && command == "set-password" => {
            let database = PathBuf::from(database);
            let user_id = parse_user_id(user_id)?;
            let _database_lock = server::acquire_database_lock(&database)?;
            let db = db::Db::open_offline_under_lock(&database)?;
            let password = read_password()?;
            let password_hash = auth::hash_password(&password)?;
            db.set_user_password(user_id, &password_hash)?;
            println!("updated user: {user_id}");
            Ok(())
        }
        [scope, command, database, user_id, email] if scope == "user" && command == "set-email" => {
            let database = PathBuf::from(database);
            let user_id = parse_user_id(user_id)?;
            let _database_lock = server::acquire_database_lock(&database)?;
            let db = db::Db::open_offline_under_lock(&database)?;
            db.set_user_email(user_id, email)?;
            println!("updated user: {user_id}");
            Ok(())
        }
        [scope, command, database, user_id, name] if scope == "user" && command == "set-name" => {
            let database = PathBuf::from(database);
            let user_id = parse_user_id(user_id)?;
            let _database_lock = server::acquire_database_lock(&database)?;
            let db = db::Db::open_offline_under_lock(&database)?;
            db.set_user_name(user_id, name)?;
            println!("updated user: {user_id}");
            Ok(())
        }
        [scope, command, database, user_id, status]
            if scope == "user" && command == "set-status" =>
        {
            let database = PathBuf::from(database);
            let user_id = parse_user_id(user_id)?;
            let _database_lock = server::acquire_database_lock(&database)?;
            let db = db::Db::open_offline_under_lock(&database)?;
            db.set_user_status(user_id, status)?;
            println!("updated user: {user_id}");
            Ok(())
        }
        [scope, command, database, user_id] if scope == "user" && command == "revoke-sessions" => {
            let database = PathBuf::from(database);
            let user_id = parse_user_id(user_id)?;
            let _database_lock = server::acquire_database_lock(&database)?;
            let db = db::Db::open_offline_under_lock(&database)?;
            println!("revoked sessions: {}", db.revoke_user_sessions(user_id)?);
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
        [command, source, destination] if command == "recover-stale-backup" => {
            let source = PathBuf::from(source);
            let destination = PathBuf::from(destination);
            db::recover_stale_backup(&source, &destination)?;
            println!("stale-backup recovery verified: {}", destination.display());
            Ok(())
        }
        [command, source, destination] if command == "migrate-legacy" => {
            let source = PathBuf::from(source);
            let destination = PathBuf::from(destination);
            let initial_user = configured_initial_user()?;
            db::migrate_legacy_database_with_initial_user(&source, &destination, &initial_user)?;
            println!(
                "legacy migration verified: {} -> {}",
                source.display(),
                destination.display()
            );
            Ok(())
        }
        [command, source, destination] if command == "migrate" => {
            let source = PathBuf::from(source);
            let destination = PathBuf::from(destination);
            let _database_lock = server::acquire_database_lock(&source)?;
            let initial_user = configured_initial_user()?;
            db::migrate_versioned_database_under_lock(&source, &destination, &initial_user)?;
            println!(
                "versioned migration verified: {} -> {}",
                source.display(),
                destination.display()
            );
            Ok(())
        }
        [command, database, data_host, backup] if command == "rebind-data-host" => {
            let database = PathBuf::from(database);
            let backup = PathBuf::from(backup);
            let changed = db::rebind_data_host(&database, data_host, &backup)?;
            println!(
                "rebound {changed} vault(s) to {data_host}; verified backup: {}",
                backup.display()
            );
            Ok(())
        }
        [command, database, vault, backup] if command == "purge-deleted" => {
            let database = PathBuf::from(database);
            let backup = PathBuf::from(backup);
            let changed = db::purge_deleted_history(&database, vault, &backup)?;
            println!(
                "purged {changed} historical revision(s) for vault {vault}; verified backup: {}",
                backup.display()
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

fn configured_initial_user() -> Result<db::InitialUser> {
    let email = std::env::var("SELFHOST_EMAIL")
        .map_err(|_| anyhow::anyhow!("SELFHOST_EMAIL is required for schema v5 migration"))?;
    let password_hash = std::env::var("SELFHOST_PASSWORD_HASH").map_err(|_| {
        anyhow::anyhow!("SELFHOST_PASSWORD_HASH is required for schema v5 migration")
    })?;
    let name = std::env::var("SELFHOST_NAME").unwrap_or_else(|_| "Blackglass user".into());
    db::InitialUser::new(&email, &name, &password_hash)
}

fn read_password() -> Result<String> {
    let mut password = String::new();
    io::stdin().read_to_string(&mut password)?;
    let password = password.trim_end_matches(['\r', '\n']);
    if password.is_empty() {
        bail!("read a non-empty password from stdin")
    }
    Ok(password.to_owned())
}

fn parse_user_id(value: &str) -> Result<i64> {
    let user_id = value
        .parse::<i64>()
        .map_err(|_| anyhow::anyhow!("user ID must be a positive safe integer"))?;
    if !(1..=db::MAX_JS_SAFE_INTEGER).contains(&user_id) {
        bail!("user ID must be a positive safe integer")
    }
    Ok(user_id)
}

fn print_help() {
    println!(
        "{NAME} {VERSION}\n\n\
Usage:\n  {NAME} serve\n  {NAME} hash-password\n  {NAME} backup <database> <output>\n  \
{NAME} user list <database>\n  {NAME} user create <database> <email> <name>\n  \
{NAME} user set-password <database> <user-id>\n  \
{NAME} user set-email <database> <user-id> <email>\n  \
{NAME} user set-name <database> <user-id> <name>\n  \
{NAME} user set-status <database> <user-id> <active|disabled>\n  \
{NAME} user revoke-sessions <database> <user-id>\n  \
{NAME} verify <database>\n  {NAME} restore <backup> <new-database>\n  {NAME} recover-stale-backup <backup> <new-database>\n  \
{NAME} migrate <versioned-database> <new-database>\n  \
{NAME} migrate-legacy <legacy-database> <new-database>\n  \
{NAME} rebind-data-host <database> <new-host> <backup>\n  \
{NAME} purge-deleted <database> <vault-id> <backup>\n  \
{NAME} revoke-all-sessions <database>\n  {NAME} build-info\n  {NAME} --version\n  {NAME} --help"
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
