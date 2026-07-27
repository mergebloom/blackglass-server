use anyhow::{Context, Result, bail};
#[cfg(test)]
use std::net::Ipv4Addr;
use std::{env, net::IpAddr, path::PathBuf, time::Duration};

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_host: IpAddr,
    pub control_port: u16,
    pub data_port: u16,
    pub public_data_host: String,
    pub database_path: PathBuf,
    pub staging_dir: PathBuf,
    pub email: String,
    pub password_hash: String,
    pub display_name: String,
    pub per_file_max: u64,
    pub session_ttl: Duration,
    pub allowed_origin: String,
    pub max_concurrent_uploads: usize,
    pub json_logs: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_host = value("SELFHOST_BIND_HOST")
            .unwrap_or_else(|| "127.0.0.1".into())
            .parse::<IpAddr>()
            .context("SELFHOST_BIND_HOST must be an IP address")?;
        if !bind_host.is_loopback() {
            bail!(
                "SELFHOST_BIND_HOST must be loopback; put a TLS reverse proxy in front of the service"
            );
        }
        let control_port = number("SELFHOST_CONTROL_PORT", 3000u16)?;
        let data_port = number("SELFHOST_DATA_PORT", 3003u16)?;
        let database_path = PathBuf::from(
            value("SELFHOST_DATABASE").unwrap_or_else(|| "selfhost-sync.sqlite".into()),
        );
        let staging_dir = value("SELFHOST_STAGING_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let mut path = database_path.clone();
                path.set_extension("uploads");
                path
            });
        let password_hash = match value("SELFHOST_PASSWORD_HASH") {
            Some(hash) => hash,
            None if value("SELFHOST_ALLOW_PLAINTEXT_PASSWORD").as_deref() == Some("1") => {
                let password = required("SELFHOST_PASSWORD")?;
                crate::auth::hash_password(&password)?
            }
            None => bail!(
                "SELFHOST_PASSWORD_HASH is required (use `hash-password`; plaintext is allowed only with SELFHOST_ALLOW_PLAINTEXT_PASSWORD=1)"
            ),
        };
        if !crate::auth::password_hash_is_production_grade(&password_hash) {
            bail!(
                "SELFHOST_PASSWORD_HASH must be an Argon2id PHC string with at least m=19456,t=2,p=1"
            );
        }
        if control_port == 0 || data_port == 0 || control_port == data_port {
            bail!("control and data ports must be distinct and non-zero");
        }
        let per_file_max = number("SELFHOST_PER_FILE_MAX", 200 * 1024 * 1024u64)?;
        if per_file_max == 0 || per_file_max > 1024 * 1024 * 1024 {
            bail!("SELFHOST_PER_FILE_MAX must be between 1 byte and 1 GiB");
        }
        let session_ttl_seconds = number("SELFHOST_SESSION_TTL_SECONDS", 30 * 24 * 60 * 60u64)?;
        if !(300..=365 * 24 * 60 * 60).contains(&session_ttl_seconds) {
            bail!("SELFHOST_SESSION_TTL_SECONDS must be between 300 seconds and 365 days");
        }
        let max_concurrent_uploads = number("SELFHOST_MAX_CONCURRENT_UPLOADS", 4usize)?;
        if !(1..=64).contains(&max_concurrent_uploads) {
            bail!("SELFHOST_MAX_CONCURRENT_UPLOADS must be between 1 and 64");
        }
        let allowed_origin =
            value("SELFHOST_ALLOWED_ORIGIN").unwrap_or_else(|| "app://obsidian.md".into());
        axum::http::HeaderValue::from_str(&allowed_origin)
            .context("SELFHOST_ALLOWED_ORIGIN is not a valid HTTP Origin value")?;
        let public_data_host =
            value("SELFHOST_DATA_HOST").unwrap_or_else(|| format!("127.0.0.1:{data_port}"));
        if public_data_host.len() > 255
            || public_data_host.contains("://")
            || public_data_host.contains('/')
            || public_data_host.chars().any(char::is_whitespace)
        {
            bail!("SELFHOST_DATA_HOST must be a hostname[:port] without a scheme or path");
        }
        Ok(Self {
            bind_host,
            control_port,
            data_port,
            public_data_host,
            database_path,
            staging_dir,
            email: required("SELFHOST_EMAIL")?,
            password_hash,
            display_name: value("SELFHOST_NAME").unwrap_or_else(|| "Blackglass user".into()),
            per_file_max,
            session_ttl: Duration::from_secs(session_ttl_seconds),
            allowed_origin,
            max_concurrent_uploads,
            json_logs: value("SELFHOST_LOG_FORMAT").as_deref() != Some("pretty"),
        })
    }

    #[cfg(test)]
    pub fn test(root: &std::path::Path, control_port: u16, data_port: u16) -> Result<Self> {
        Ok(Self {
            bind_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            control_port,
            data_port,
            public_data_host: format!("127.0.0.1:{data_port}"),
            database_path: root.join("server.sqlite"),
            staging_dir: root.join("uploads"),
            email: "owner@example.test".into(),
            password_hash: crate::auth::hash_password("test-password")?,
            display_name: "Test owner".into(),
            per_file_max: 8 * 1024 * 1024,
            session_ttl: Duration::from_secs(3600),
            allowed_origin: "app://obsidian.md".into(),
            max_concurrent_uploads: 2,
            json_logs: false,
        })
    }
}

fn value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}
fn required(name: &str) -> Result<String> {
    value(name).with_context(|| format!("{name} is required"))
}
fn number<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr + Copy,
    T::Err: std::fmt::Display,
{
    match value(name) {
        Some(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid {name}: {v}: {e}")),
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_configuration_is_loopback_and_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::test(dir.path(), 3100, 3103).unwrap();
        assert!(c.bind_host.is_loopback());
        assert_eq!(c.public_data_host, "127.0.0.1:3103");
        assert!(c.database_path.starts_with(dir.path()));
    }
}
