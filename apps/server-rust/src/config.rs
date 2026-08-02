use crate::db::MAX_JS_SAFE_INTEGER;
use anyhow::{Context, Result, bail};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    time::Duration,
};

pub(crate) const MAX_WS_CONNECTIONS_LIMIT: usize = 16;
pub(crate) const DEFAULT_MAX_WS_CONNECTIONS: usize = 16;
pub(crate) const MAX_CONCURRENT_UPLOADS_LIMIT: usize = 4;
pub(crate) const MAX_PER_FILE_BYTES: u64 = 900 * 1024 * 1024;
pub(crate) const AES_GCM_WIRE_OVERHEAD_BYTES: u64 = 12 + 16;
pub(crate) const DEFAULT_STORAGE_QUOTA_BYTES: i64 = 1024 * 1024 * 1024 * 1024;
const DEFAULT_UPLOAD_IDLE_TIMEOUT_SECONDS: u64 = 300;
const MIN_UPLOAD_IDLE_TIMEOUT_SECONDS: u64 = 5;
const MAX_UPLOAD_IDLE_TIMEOUT_SECONDS: u64 = 60 * 60;
// Bundled SQLite keeps the upstream 1,000,000,000-byte SQLITE_MAX_LENGTH.
// Leave substantial room for encryption and record/header overhead instead of
// advertising an upload which can be staged completely but never committed.
const _: () = assert!(MAX_PER_FILE_BYTES + 50 * 1024 * 1024 < 1_000_000_000);

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_host: IpAddr,
    pub control_port: u16,
    pub data_port: u16,
    pub public_data_host: String,
    pub database_path: PathBuf,
    pub staging_dir: PathBuf,
    pub per_file_max: u64,
    pub storage_quota_bytes: i64,
    pub storage_quota_bytes_per_owner: i64,
    pub session_ttl: Duration,
    pub upload_idle_timeout: Duration,
    pub allowed_origins: Vec<String>,
    pub max_concurrent_uploads: usize,
    pub max_concurrent_uploads_per_user: usize,
    pub max_ws_connections: usize,
    pub max_ws_connections_per_user: usize,
    pub trusted_proxy: Option<IpAddr>,
    pub admin: Option<crate::admin::AdminConfig>,
    pub json_logs: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_host = value("SELFHOST_BIND_HOST")
            .unwrap_or_else(|| "127.0.0.1".into())
            .parse::<IpAddr>()
            .context("SELFHOST_BIND_HOST must be an IP address")?;
        let external_bind_acknowledged = match value("SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND") {
            None => false,
            Some(value) if value == "1" => true,
            Some(_) => bail!("SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND must be exactly 1 when set"),
        };
        validate_bind_host(bind_host, external_bind_acknowledged)?;
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
        if control_port == 0 || data_port == 0 || control_port == data_port {
            bail!("control and data ports must be distinct and non-zero");
        }
        let per_file_max = number("SELFHOST_PER_FILE_MAX", 200 * 1024 * 1024u64)?;
        validate_per_file_max(per_file_max)?;
        let storage_quota_bytes =
            number("SELFHOST_STORAGE_QUOTA_BYTES", DEFAULT_STORAGE_QUOTA_BYTES)?;
        validate_storage_quota(storage_quota_bytes, per_file_max)?;
        let storage_quota_bytes_per_owner = number(
            "SELFHOST_STORAGE_QUOTA_BYTES_PER_OWNER",
            storage_quota_bytes,
        )?;
        validate_owner_storage_quota(
            storage_quota_bytes_per_owner,
            storage_quota_bytes,
            per_file_max,
        )?;
        let session_ttl_seconds = number("SELFHOST_SESSION_TTL_SECONDS", 30 * 24 * 60 * 60u64)?;
        if !(300..=365 * 24 * 60 * 60).contains(&session_ttl_seconds) {
            bail!("SELFHOST_SESSION_TTL_SECONDS must be between 300 seconds and 365 days");
        }
        let upload_idle_timeout_seconds = number(
            "SELFHOST_UPLOAD_IDLE_TIMEOUT_SECONDS",
            DEFAULT_UPLOAD_IDLE_TIMEOUT_SECONDS,
        )?;
        validate_upload_idle_timeout(upload_idle_timeout_seconds)?;
        let max_concurrent_uploads = number("SELFHOST_MAX_CONCURRENT_UPLOADS", 4usize)?;
        validate_concurrent_uploads(max_concurrent_uploads)?;
        let max_concurrent_uploads_per_user = number(
            "SELFHOST_MAX_CONCURRENT_UPLOADS_PER_USER",
            max_concurrent_uploads.min(2),
        )?;
        validate_per_user_limit(
            "SELFHOST_MAX_CONCURRENT_UPLOADS_PER_USER",
            max_concurrent_uploads_per_user,
            max_concurrent_uploads,
        )?;
        let max_ws_connections = number("SELFHOST_MAX_WS_CONNECTIONS", DEFAULT_MAX_WS_CONNECTIONS)?;
        if !(1..=MAX_WS_CONNECTIONS_LIMIT).contains(&max_ws_connections) {
            bail!("SELFHOST_MAX_WS_CONNECTIONS must be between 1 and {MAX_WS_CONNECTIONS_LIMIT}");
        }
        let max_ws_connections_per_user = number(
            "SELFHOST_MAX_WS_CONNECTIONS_PER_USER",
            max_ws_connections.min(4),
        )?;
        validate_per_user_limit(
            "SELFHOST_MAX_WS_CONNECTIONS_PER_USER",
            max_ws_connections_per_user,
            max_ws_connections,
        )?;
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
            resolve_public_data_host(bind_host, data_port, value("SELFHOST_DATA_HOST"))?;
        let trusted_proxy = value("SELFHOST_TRUSTED_PROXY")
            .map(|value| {
                let address = value
                    .parse::<IpAddr>()
                    .context("SELFHOST_TRUSTED_PROXY must be one exact IP address")?;
                if !private_or_loopback(address) {
                    bail!("SELFHOST_TRUSTED_PROXY must be a loopback or private IP address")
                }
                Ok(address)
            })
            .transpose()?;
        let admin = crate::admin::parse_admin_config(
            value("SELFHOST_ADMIN_BIND_HOST").as_deref(),
            value("SELFHOST_ADMIN_PORT").as_deref(),
            value("SELFHOST_ADMIN_TOKEN_HASH").as_deref(),
            control_port,
            data_port,
        )?;
        Ok(Self {
            bind_host,
            control_port,
            data_port,
            public_data_host,
            database_path,
            staging_dir,
            per_file_max,
            storage_quota_bytes,
            storage_quota_bytes_per_owner,
            session_ttl: Duration::from_secs(session_ttl_seconds),
            upload_idle_timeout: Duration::from_secs(upload_idle_timeout_seconds),
            allowed_origins,
            max_concurrent_uploads,
            max_concurrent_uploads_per_user,
            max_ws_connections,
            max_ws_connections_per_user,
            trusted_proxy,
            admin,
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
            per_file_max: 8 * 1024 * 1024,
            storage_quota_bytes: DEFAULT_STORAGE_QUOTA_BYTES,
            storage_quota_bytes_per_owner: DEFAULT_STORAGE_QUOTA_BYTES,
            session_ttl: Duration::from_secs(3600),
            upload_idle_timeout: Duration::from_secs(DEFAULT_UPLOAD_IDLE_TIMEOUT_SECONDS),
            allowed_origins: vec!["app://obsidian.md".into()],
            max_concurrent_uploads: 2,
            max_concurrent_uploads_per_user: 2,
            max_ws_connections: DEFAULT_MAX_WS_CONNECTIONS,
            max_ws_connections_per_user: 4,
            trusted_proxy: None,
            admin: None,
            json_logs: false,
        })
    }
}

fn private_or_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        IpAddr::V6(address) => address.is_loopback() || (address.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

fn validate_bind_host(bind_host: IpAddr, external_bind_acknowledged: bool) -> Result<()> {
    if bind_host.is_loopback() {
        return Ok(());
    }
    if !bind_host.is_unspecified() {
        bail!("SELFHOST_BIND_HOST must be loopback or an unspecified container bind address")
    }
    if !external_bind_acknowledged {
        bail!(
            "binding outside loopback requires SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND=1 and a private container network with a TLS ingress boundary"
        )
    }
    Ok(())
}

fn validate_concurrent_uploads(value: usize) -> Result<()> {
    if !(1..=MAX_CONCURRENT_UPLOADS_LIMIT).contains(&value) {
        bail!(
            "SELFHOST_MAX_CONCURRENT_UPLOADS must be between 1 and {MAX_CONCURRENT_UPLOADS_LIMIT}"
        )
    }
    Ok(())
}

fn validate_upload_idle_timeout(value: u64) -> Result<()> {
    if !(MIN_UPLOAD_IDLE_TIMEOUT_SECONDS..=MAX_UPLOAD_IDLE_TIMEOUT_SECONDS).contains(&value) {
        bail!(
            "SELFHOST_UPLOAD_IDLE_TIMEOUT_SECONDS must be between {MIN_UPLOAD_IDLE_TIMEOUT_SECONDS} and {MAX_UPLOAD_IDLE_TIMEOUT_SECONDS} seconds"
        )
    }
    Ok(())
}

fn validate_per_file_max(value: u64) -> Result<()> {
    if !(1..=MAX_PER_FILE_BYTES).contains(&value) {
        bail!(
            "SELFHOST_PER_FILE_MAX must be between 1 byte and {MAX_PER_FILE_BYTES} bytes (900 MiB SQLite-safe ceiling)"
        )
    }
    Ok(())
}

fn validate_storage_quota(value: i64, per_file_max: u64) -> Result<()> {
    let minimum = i64::try_from(per_file_max.saturating_add(AES_GCM_WIRE_OVERHEAD_BYTES))
        .context("SELFHOST_PER_FILE_MAX cannot be represented by SQLite")?;
    if !(minimum..=MAX_JS_SAFE_INTEGER).contains(&value) {
        bail!(
            "SELFHOST_STORAGE_QUOTA_BYTES must be between {minimum} bytes (one maximum-size encrypted file) and {MAX_JS_SAFE_INTEGER} bytes"
        )
    }
    Ok(())
}

fn validate_owner_storage_quota(value: i64, global: i64, per_file_max: u64) -> Result<()> {
    validate_storage_quota(value, per_file_max).map_err(|_| {
        anyhow::anyhow!(
            "SELFHOST_STORAGE_QUOTA_BYTES_PER_OWNER must hold one maximum-size encrypted file and remain JavaScript-safe"
        )
    })?;
    if value > global {
        bail!("SELFHOST_STORAGE_QUOTA_BYTES_PER_OWNER must not exceed SELFHOST_STORAGE_QUOTA_BYTES")
    }
    Ok(())
}

fn validate_per_user_limit(name: &str, value: usize, global: usize) -> Result<()> {
    if value == 0 || value > global {
        bail!("{name} must be between 1 and its corresponding global limit ({global})")
    }
    Ok(())
}

fn resolve_public_data_host(
    bind_host: IpAddr,
    data_port: u16,
    configured: Option<String>,
) -> Result<String> {
    let public_data_host = match configured {
        Some(host) => host,
        None if bind_host == IpAddr::V4(Ipv4Addr::LOCALHOST) => {
            format!("127.0.0.1:{data_port}")
        }
        None => {
            bail!("SELFHOST_DATA_HOST is required when SELFHOST_BIND_HOST is not 127.0.0.1")
        }
    };
    validate_public_data_host(&public_data_host)?;
    if bind_host != IpAddr::V4(Ipv4Addr::LOCALHOST) && direct_loopback_host(&public_data_host) {
        bail!("loopback SELFHOST_DATA_HOST requires SELFHOST_BIND_HOST=127.0.0.1")
    }
    validate_direct_loopback_port(&public_data_host, data_port)?;
    Ok(public_data_host)
}

fn direct_loopback_host(value: &str) -> bool {
    value
        .rsplit_once(':')
        .is_some_and(|(host, _)| matches!(host, "localhost" | "127.0.0.1"))
}

fn validate_direct_loopback_port(value: &str, data_port: u16) -> Result<()> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Ok(());
    };
    if matches!(host, "localhost" | "127.0.0.1") && port != data_port.to_string() {
        bail!("loopback SELFHOST_DATA_HOST port must match SELFHOST_DATA_PORT")
    }
    Ok(())
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
        if parsed.is_loopback()
            || parsed.is_unspecified()
            || parsed.is_multicast()
            || parsed.to_string() != address
        {
            return false;
        }
        return suffix.is_empty() || (suffix != ":443" && valid_port_suffix(suffix));
    }

    if value.contains('[') || value.contains(']') || value.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if port.is_some_and(|port| !valid_port(port) || port == "443") || host.is_empty() {
        return false;
    }
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
            return false;
        }
        return (!address.is_loopback() || (address == Ipv4Addr::LOCALHOST && port.is_some()))
            && address.to_string() == host;
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
    if (host.starts_with("localhost") && host != "localhost")
        || (host.starts_with("127.0.0.1") && host != "127.0.0.1")
        || (host == "localhost" && port.is_none())
    {
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

pub(crate) fn validate_public_data_host(value: &str) -> Result<()> {
    if !is_canonical_data_host(value) {
        bail!("SELFHOST_DATA_HOST must be a canonical hostname[:port]")
    }
    Ok(())
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
    fn trusted_proxy_addresses_are_private_or_loopback_only() {
        for accepted in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "::1",
            "fd00::1",
        ] {
            assert!(private_or_loopback(accepted.parse().unwrap()), "{accepted}");
        }
        for rejected in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            assert!(
                !private_or_loopback(rejected.parse().unwrap()),
                "{rejected}"
            );
        }
    }
    #[test]
    fn test_configuration_is_loopback_and_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::test(dir.path(), 3100, 3103).unwrap();
        assert!(c.bind_host.is_loopback());
        assert_eq!(c.public_data_host, "127.0.0.1:3103");
        assert!(c.database_path.starts_with(dir.path()));
    }

    #[test]
    fn external_bind_requires_an_explicit_container_acknowledgement() {
        assert!(validate_bind_host("127.0.0.1".parse().unwrap(), false).is_ok());
        assert!(validate_bind_host("::1".parse().unwrap(), false).is_ok());
        assert!(validate_bind_host("0.0.0.0".parse().unwrap(), false).is_err());
        assert!(validate_bind_host("::".parse().unwrap(), false).is_err());
        assert!(validate_bind_host("0.0.0.0".parse().unwrap(), true).is_ok());
        assert!(validate_bind_host("::".parse().unwrap(), true).is_ok());
        assert!(validate_bind_host("192.0.2.10".parse().unwrap(), true).is_err());
    }

    #[test]
    fn upload_concurrency_cannot_exceed_the_qualified_envelope() {
        for value in 1..=MAX_CONCURRENT_UPLOADS_LIMIT {
            validate_concurrent_uploads(value).unwrap();
        }
        for value in [0, MAX_CONCURRENT_UPLOADS_LIMIT + 1, 64] {
            assert!(
                validate_concurrent_uploads(value).is_err(),
                "passed: {value}"
            );
        }
    }

    #[test]
    fn upload_idle_timeout_has_safe_operational_bounds() {
        for value in [
            MIN_UPLOAD_IDLE_TIMEOUT_SECONDS,
            DEFAULT_UPLOAD_IDLE_TIMEOUT_SECONDS,
            MAX_UPLOAD_IDLE_TIMEOUT_SECONDS,
        ] {
            validate_upload_idle_timeout(value).unwrap();
        }
        for value in [
            0,
            MIN_UPLOAD_IDLE_TIMEOUT_SECONDS - 1,
            MAX_UPLOAD_IDLE_TIMEOUT_SECONDS + 1,
        ] {
            assert!(
                validate_upload_idle_timeout(value).is_err(),
                "unsafe upload idle timeout passed: {value}"
            );
        }
    }

    #[test]
    fn per_file_limit_stays_below_sqlite_default_maximum_length() {
        validate_per_file_max(MAX_PER_FILE_BYTES).unwrap();
        for value in [0, MAX_PER_FILE_BYTES + 1, 1024 * 1024 * 1024] {
            assert!(
                validate_per_file_max(value).is_err(),
                "unsafe per-file maximum passed: {value}"
            );
        }
    }

    #[test]
    fn storage_quota_is_wire_safe_and_can_hold_one_maximum_file() {
        let per_file_max = 200 * 1024 * 1024u64;
        let minimum = (per_file_max + AES_GCM_WIRE_OVERHEAD_BYTES) as i64;
        validate_storage_quota(minimum, per_file_max).unwrap();
        validate_storage_quota(DEFAULT_STORAGE_QUOTA_BYTES, per_file_max).unwrap();
        validate_storage_quota(MAX_JS_SAFE_INTEGER, per_file_max).unwrap();
        for value in [0, minimum - 1, MAX_JS_SAFE_INTEGER + 1] {
            assert!(
                validate_storage_quota(value, per_file_max).is_err(),
                "unsafe storage quota passed: {value}"
            );
        }
        assert_eq!(
            DEFAULT_STORAGE_QUOTA_BYTES, 1_099_511_627_776,
            "the compatibility default must preserve the previously advertised 1 TiB limit"
        );
    }

    #[test]
    fn per_user_resource_limits_never_exceed_global_limits() {
        validate_per_user_limit("connections", 1, 1).unwrap();
        validate_per_user_limit("connections", 4, 16).unwrap();
        assert!(validate_per_user_limit("connections", 0, 16).is_err());
        assert!(validate_per_user_limit("connections", 5, 4).is_err());

        let per_file_max = 200 * 1024 * 1024u64;
        let minimum = (per_file_max + AES_GCM_WIRE_OVERHEAD_BYTES) as i64;
        validate_owner_storage_quota(minimum, minimum, per_file_max).unwrap();
        assert!(validate_owner_storage_quota(minimum + 1, minimum, per_file_max).is_err());
    }

    #[test]
    fn advertised_data_host_defaults_only_for_direct_ipv4_loopback() {
        assert_eq!(
            resolve_public_data_host("127.0.0.1".parse().unwrap(), 3003, None).unwrap(),
            "127.0.0.1:3003"
        );
        for bind in ["::1", "0.0.0.0", "::"] {
            assert!(
                resolve_public_data_host(bind.parse().unwrap(), 3003, None).is_err(),
                "omitted data host passed for {bind}"
            );
        }
        assert_eq!(
            resolve_public_data_host(
                "0.0.0.0".parse().unwrap(),
                3003,
                Some("sync-data.example".into())
            )
            .unwrap(),
            "sync-data.example"
        );
        assert!(
            resolve_public_data_host(
                "0.0.0.0".parse().unwrap(),
                3003,
                Some("127.0.0.1:3003".into())
            )
            .is_err()
        );
    }

    #[test]
    fn direct_loopback_advertisements_require_the_listener_port() {
        for host in ["127.0.0.1", "localhost", "127.0.0.1:3004", "localhost:3004"] {
            assert!(
                resolve_public_data_host("127.0.0.1".parse().unwrap(), 3003, Some(host.into()))
                    .is_err(),
                "invalid direct loopback host passed: {host}"
            );
        }
        for host in ["127.0.0.1:3003", "localhost:3003"] {
            assert_eq!(
                resolve_public_data_host("127.0.0.1".parse().unwrap(), 3003, Some(host.into()))
                    .unwrap(),
                host
            );
        }
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
            "blackglass.example:8443",
            "127.0.0.1:3003",
            "[2001:db8::1]:8443",
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
            "blackglass.example:443",
            "[::1]:443",
            "blackglass.example:0443",
            "blackglass.example:65536",
            "blackglass..example",
            "-blackglass.example",
            "127.000.000.001:3003",
            "127.0.0.2:3003",
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "0.0.0.0:3003",
            "224.0.0.1:3003",
            "255.255.255.255:3003",
            "localhost.evil.example:8080",
            "127.0.0.1.evil.example:8080",
            "::1",
            "[::1]:3003",
            "[0:0:0:0:0:0:0:1]:3003",
            "[::]",
            "[ff02::1]:3003",
        ] {
            assert!(
                !is_canonical_data_host(rejected),
                "expected invalid: {rejected}"
            );
        }
    }
}
