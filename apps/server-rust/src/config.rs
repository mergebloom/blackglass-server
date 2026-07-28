use anyhow::{Context, Result, bail};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    time::Duration,
};

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
    pub allowed_origins: Vec<String>,
    pub max_concurrent_uploads: usize,
    pub max_ws_connections: usize,
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
                "SELFHOST_PASSWORD_HASH must be an Argon2id v=19 PHC string with m=19456..65536,t=2..5,p=1..4"
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
        let max_ws_connections = number("SELFHOST_MAX_WS_CONNECTIONS", 256usize)?;
        if !(1..=4096).contains(&max_ws_connections) {
            bail!("SELFHOST_MAX_WS_CONNECTIONS must be between 1 and 4096");
        }
        let allowed_origins = match (
            value("SELFHOST_ALLOWED_ORIGINS"),
            value("SELFHOST_ALLOWED_ORIGIN"),
        ) {
            (Some(_), Some(_)) => {
                bail!("set SELFHOST_ALLOWED_ORIGINS or legacy SELFHOST_ALLOWED_ORIGIN, not both")
            }
            (Some(origins), None) => parse_allowed_origins(&origins)?,
            (None, Some(origin)) => parse_allowed_origins(&origin)?,
            (None, None) => vec!["app://obsidian.md".into()],
        };
        let public_data_host =
            value("SELFHOST_DATA_HOST").unwrap_or_else(|| format!("127.0.0.1:{data_port}"));
        if !is_canonical_data_host(&public_data_host) {
            bail!("SELFHOST_DATA_HOST must be a canonical hostname[:port]");
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
            allowed_origins,
            max_concurrent_uploads,
            max_ws_connections,
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
            allowed_origins: vec!["app://obsidian.md".into()],
            max_concurrent_uploads: 2,
            max_ws_connections: 16,
            json_logs: false,
        })
    }
}

fn value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

fn parse_allowed_origins(raw: &str) -> Result<Vec<String>> {
    let origins: Vec<String> = raw.split(',').map(str::trim).map(str::to_owned).collect();
    if origins.is_empty() || origins.len() > 8 || origins.iter().any(String::is_empty) {
        bail!("SELFHOST_ALLOWED_ORIGINS must contain between one and eight origins");
    }
    let mut seen = std::collections::HashSet::new();
    for origin in &origins {
        if origin.len() > 255 || origin == "*" || origin.eq_ignore_ascii_case("null") {
            bail!("SELFHOST_ALLOWED_ORIGINS must contain exact, bounded origins");
        }
        let Some((scheme, authority)) = origin.split_once("://") else {
            bail!("SELFHOST_ALLOWED_ORIGINS contains an invalid origin");
        };
        let valid_scheme = scheme.chars().enumerate().all(|(index, c)| {
            (index == 0 && c.is_ascii_alphabetic())
                || (index > 0 && (c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
        });
        if !valid_scheme
            || authority.is_empty()
            || authority
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '@'))
        {
            bail!("SELFHOST_ALLOWED_ORIGINS contains an invalid origin");
        }
        axum::http::HeaderValue::from_str(origin)
            .context("SELFHOST_ALLOWED_ORIGINS contains an invalid HTTP Origin value")?;
        if !seen.insert(origin) {
            bail!("SELFHOST_ALLOWED_ORIGINS must not contain duplicates");
        }
    }
    Ok(origins)
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

fn is_canonical_data_host(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 255
        || value.trim() != value
        || !value.is_ascii()
        || value.contains(['/', '\\', '?', '#', '@'])
    {
        return false;
    }

    if let Some(rest) = value.strip_prefix('[') {
        let Some((address, suffix)) = rest.split_once(']') else {
            return false;
        };
        let Ok(parsed) = address.parse::<Ipv6Addr>() else {
            return false;
        };
        if parsed.to_string() != address {
            return false;
        }
        return suffix.is_empty() || valid_port_suffix(suffix);
    }

    if value.contains('[') || value.contains(']') || value.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if port.is_some_and(|port| !valid_port(port)) || host.is_empty() {
        return false;
    }
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return address.to_string() == host;
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    if host.bytes().any(|byte| byte.is_ascii_uppercase()) || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn valid_port_suffix(value: &str) -> bool {
    value.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(value: &str) -> bool {
    value
        .parse::<u16>()
        .is_ok_and(|port| port != 0 && port.to_string() == value)
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

    #[test]
    fn parses_a_bounded_list_of_exact_origins() {
        assert_eq!(
            parse_allowed_origins("app://obsidian.md, http://localhost").unwrap(),
            vec!["app://obsidian.md", "http://localhost"]
        );
        for invalid in [
            "",
            "*",
            "null",
            "https://example.test/path",
            "https://example.test?query",
            "https://example.test#fragment",
            "https://example.test,https://example.test",
            "https://a.test,https://b.test,https://c.test,https://d.test,https://e.test,https://f.test,https://g.test,https://h.test,https://i.test",
        ] {
            assert!(
                parse_allowed_origins(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn public_data_hosts_must_be_canonical() {
        for accepted in [
            "blackglass.example",
            "blackglass.example:443",
            "127.0.0.1:3003",
            "[::1]:3003",
            "xn--bcher-kva.example",
        ] {
            assert!(
                is_canonical_data_host(accepted),
                "expected valid: {accepted}"
            );
        }
        for rejected in [
            " blackglass.example",
            "blackglass.example ",
            "BLACKGLASS.example",
            "blackglass.example/route",
            "blackglass.example?query",
            "blackglass.example#fragment",
            "user@blackglass.example",
            "blackglass.example\\path",
            "blackglass.example:0",
            "blackglass.example:0443",
            "blackglass.example:65536",
            "blackglass..example",
            "-blackglass.example",
            "127.000.000.001:3003",
            "::1",
            "[0:0:0:0:0:0:0:1]:3003",
        ] {
            assert!(
                !is_canonical_data_host(rejected),
                "expected invalid: {rejected}"
            );
        }
    }
}
