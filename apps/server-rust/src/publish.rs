use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::Response,
    routing::get,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

const RECEIPT_FILE: &str = "blackglass-publish-runtime.json";
const MAX_RUNTIME_ASSETS: usize = 128;
const MAX_RUNTIME_BYTES: usize = 32 * 1024 * 1024;
const MAX_ASSET_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_RUNTIME_ENTRIES: usize = 512;
const MAX_RUNTIME_DEPTH: usize = 8;

#[derive(Clone, Debug)]
pub(crate) struct VerifiedPublishRuntime {
    runtime_sha256: String,
    source_runtime_sha256: String,
    assets: HashMap<String, Arc<[u8]>>,
    total_bytes: usize,
}

impl VerifiedPublishRuntime {
    pub(crate) fn load(
        root: &Path,
        expected_runtime_sha256: &str,
        expected_source_runtime_sha256: &str,
    ) -> Result<Self> {
        require_sha256(expected_runtime_sha256, "expected Publish runtime SHA-256")?;
        require_sha256(
            expected_source_runtime_sha256,
            "expected source Publish runtime SHA-256",
        )?;
        let root = canonical_directory(root, "Publish runtime root")?;
        let receipt_path = root.join(RECEIPT_FILE);
        let receipt = read_regular_file(
            &root,
            &receipt_path,
            "Publish runtime receipt",
            MAX_RECEIPT_BYTES,
        )?;
        let receipt: Value =
            serde_json::from_slice(&receipt).context("parse Publish runtime receipt")?;
        let receipt_object = receipt
            .as_object()
            .context("Publish runtime receipt must be an object")?;
        if receipt_object.get("schemaVersion").and_then(Value::as_u64) != Some(1)
            || receipt_object.get("generatedBy").and_then(Value::as_str)
                != Some("tools/adapt-publish-runtime.ts")
        {
            bail!("Publish runtime receipt has an unsupported schema or generator")
        }
        let source_runtime_sha256 = receipt_object
            .get("sourceRuntimeSha256")
            .and_then(Value::as_str)
            .context("Publish runtime receipt has no sourceRuntimeSha256")?;
        require_sha256(source_runtime_sha256, "source Publish runtime SHA-256")?;
        if source_runtime_sha256 != expected_source_runtime_sha256 {
            bail!("Publish runtime receipt does not match the configured reviewed source identity")
        }
        let output_runtime_sha256 = receipt_object
            .get("outputRuntimeSha256")
            .and_then(Value::as_str)
            .context("Publish runtime receipt has no outputRuntimeSha256")?;
        require_sha256(output_runtime_sha256, "output Publish runtime SHA-256")?;
        if output_runtime_sha256 != expected_runtime_sha256 {
            bail!("Publish runtime does not match the configured source-bound identity")
        }
        let manifest = receipt_object
            .get("outputManifest")
            .context("Publish runtime receipt has no outputManifest")?;
        let manifest_object = manifest
            .as_object()
            .context("Publish runtime outputManifest must be an object")?;
        if manifest_object.get("schemaVersion").and_then(Value::as_u64) != Some(1)
            || manifest_object.get("generatedBy").and_then(Value::as_str)
                != Some("tools/inspect-publish-runtime.ts")
            || manifest_object.get("runtimeSha256").and_then(Value::as_str)
                != Some(output_runtime_sha256)
        {
            bail!("Publish runtime outputManifest has inconsistent identity metadata")
        }
        let mut unsigned_manifest = manifest.clone();
        unsigned_manifest
            .as_object_mut()
            .context("Publish runtime outputManifest must be mutable")?
            .remove("runtimeSha256");
        let computed_manifest_sha256 = sha256(canonical_json(&unsigned_manifest).as_bytes());
        if computed_manifest_sha256 != output_runtime_sha256 {
            bail!("Publish runtime manifest canonical identity is invalid")
        }

        let asset_values = manifest_object
            .get("assets")
            .and_then(Value::as_array)
            .context("Publish runtime outputManifest has no asset inventory")?;
        if asset_values.is_empty() || asset_values.len() > MAX_RUNTIME_ASSETS {
            bail!("Publish runtime asset count is outside the supported bound")
        }
        let mut assets = HashMap::with_capacity(asset_values.len());
        let mut expected_files = HashSet::with_capacity(asset_values.len() + 1);
        let mut expected_directories = HashSet::new();
        expected_files.insert(RECEIPT_FILE.to_owned());
        let mut total_bytes = 0usize;
        for asset in asset_values {
            let asset = asset
                .as_object()
                .context("Publish runtime asset identity must be an object")?;
            let path = asset
                .get("path")
                .and_then(Value::as_str)
                .context("Publish runtime asset has no path")?;
            validate_relative_asset_path(path)?;
            if !expected_files.insert(path.to_owned()) {
                bail!("Publish runtime has a duplicate asset path: {path}")
            }
            let mut parent = PathBuf::new();
            for component in Path::new(path)
                .components()
                .collect::<Vec<_>>()
                .iter()
                .rev()
                .skip(1)
                .rev()
            {
                let Component::Normal(component) = component else {
                    unreachable!("validated Publish asset path component")
                };
                parent.push(component);
                expected_directories.insert(
                    parent
                        .to_string_lossy()
                        .replace(std::path::MAIN_SEPARATOR, "/"),
                );
            }
            let expected_bytes = asset
                .get("bytes")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .context("Publish runtime asset has an invalid byte length")?;
            if expected_bytes > MAX_ASSET_BYTES {
                bail!("Publish runtime asset exceeds the per-file bound: {path}")
            }
            let expected_sha256 = asset
                .get("sha256")
                .and_then(Value::as_str)
                .context("Publish runtime asset has no SHA-256")?;
            require_sha256(expected_sha256, "Publish runtime asset SHA-256")?;
            let bytes = read_regular_file(
                &root,
                &root.join(path),
                "Publish runtime asset",
                MAX_ASSET_BYTES,
            )?;
            if bytes.len() != expected_bytes || sha256(&bytes) != expected_sha256 {
                bail!("Publish runtime asset identity changed: {path}")
            }
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .context("Publish runtime total byte count overflow")?;
            if total_bytes > MAX_RUNTIME_BYTES {
                bail!("Publish runtime exceeds the total byte bound")
            }
            assets.insert(path.to_owned(), Arc::<[u8]>::from(bytes));
        }
        let (actual_files, actual_directories) = inventory_tree(&root)?;
        if actual_files != expected_files || actual_directories != expected_directories {
            bail!("Publish runtime directory contains unbound or missing files or directories")
        }
        Ok(Self {
            runtime_sha256: output_runtime_sha256.to_owned(),
            source_runtime_sha256: source_runtime_sha256.to_owned(),
            assets,
            total_bytes,
        })
    }

    pub(crate) fn report(&self) -> Value {
        json!({
            "sourceRuntimeSha256": self.source_runtime_sha256,
            "runtimeSha256": self.runtime_sha256,
            "assets": self.assets.len(),
            "bytes": self.total_bytes,
            "verified": true,
        })
    }

    fn asset(&self, path: &str) -> Option<Arc<[u8]>> {
        self.assets.get(path).cloned()
    }
}

#[derive(Clone)]
struct ReplayState {
    runtime: VerifiedPublishRuntime,
}

const REPLAY_SITE_UID: &str = "00000000000000000000000000000001";

pub(crate) async fn serve_replay(
    root: &Path,
    expected_runtime_sha256: &str,
    expected_source_runtime_sha256: &str,
    port: u16,
) -> Result<()> {
    let runtime = VerifiedPublishRuntime::load(
        root,
        expected_runtime_sha256,
        expected_source_runtime_sha256,
    )?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .context("bind Publish replay listener")?;
    println!(
        "{}",
        json!({
            "origin": format!("http://{}", listener.local_addr()?),
            "runtime": runtime.report(),
            "spike": true,
        })
    );
    axum::serve(listener, replay_router(runtime))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("serve Publish replay")
}

fn replay_router(runtime: VerifiedPublishRuntime) -> Router {
    Router::new()
        .route("/", get(replay_request))
        .route("/{*path}", get(replay_request))
        .with_state(ReplayState { runtime })
}

async fn replay_request(
    State(state): State<ReplayState>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let path = uri.path();
    match path {
        "/.well-known/blackglass-publish-runtime.json" => replay_response(
            StatusCode::OK,
            "application/json; charset=utf-8",
            serde_json::to_vec(&state.runtime.report())
                .expect("serialize replay runtime report")
                .into(),
            false,
            false,
        ),
        "/" => {
            let host = headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.contains(['<', '>', '"', '\'', '\\']))
                .unwrap_or("127.0.0.1");
            replay_response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                replay_shell(host).into_bytes().into(),
                false,
                false,
            )
        }
        path if path == format!("/options/{REPLAY_SITE_UID}") => replay_response(
            StatusCode::OK,
            "application/json; charset=utf-8",
            serde_json::to_vec(&json!({
                "indexFile": "Home",
                "siteName": "Blackglass Publish",
                "defaultTheme": "dark",
                "showOutline": true,
                "showBacklinks": true,
                "showSearch": true,
                "showThemeToggle": true,
                "showNavigation": true,
                "showGraph": true,
            }))
            .expect("serialize replay options")
            .into(),
            true,
            false,
        ),
        path if path == format!("/cache/{REPLAY_SITE_UID}") => replay_response(
            StatusCode::OK,
            "application/json; charset=utf-8",
            serde_json::to_vec(&json!({
                "Home.md": {
                    "links": [],
                    "headings": [{"heading":"Blackglass Publish","level":1,"pos":[0,0,0,0,20,20]}],
                    "frontmatter": {},
                    "frontmatterLinks": [],
                }
            }))
            .expect("serialize replay cache")
            .into(),
            true,
            false,
        ),
        path if path == format!("/access/{REPLAY_SITE_UID}/Home.md") => replay_response(
            StatusCode::OK,
            "text/markdown; charset=utf-8",
            Arc::<[u8]>::from(
                b"# Blackglass Publish\n\nA self-hosted Publish runtime, rendered entirely from Rust.\n"
                    .as_slice(),
            ),
            true,
            false,
        ),
        _ => {
            let asset_path = path.strip_prefix('/').unwrap_or(path);
            match state.runtime.asset(asset_path) {
                Some(asset) => replay_response(
                    StatusCode::OK,
                    content_type(asset_path),
                    asset,
                    false,
                    true,
                ),
                None => replay_response(
                    StatusCode::NOT_FOUND,
                    "text/plain; charset=utf-8",
                    Arc::<[u8]>::from(b"not found".as_slice()),
                    false,
                    false,
                ),
            }
        }
    }
}

fn replay_shell(host: &str) -> String {
    let site_info = json!({
        "uid": REPLAY_SITE_UID,
        "host": host,
        "status": "active",
        "slug": "spike",
        "redirect": 0,
        "customurl": Value::Null,
    });
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><script defer src=\"/app.js\"></script><link rel=\"stylesheet\" href=\"/app.css\"><title>Blackglass Publish</title><script>window.siteInfo={site_info};window.preloadOptions=fetch(\"/options/{REPLAY_SITE_UID}\",{{credentials:\"include\"}});window.preloadCache=fetch(\"/cache/{REPLAY_SITE_UID}\",{{credentials:\"include\"}});window.preloadPage=fetch(\"/access/{REPLAY_SITE_UID}/Home.md\",{{credentials:\"include\"}});</script></head><body class=\"theme-dark\"><div class=\"preload\">Loading…</div></body></html>"
    )
}

fn replay_response(
    status: StatusCode,
    content_type: &'static str,
    body: Arc<[u8]>,
    active: bool,
    immutable: bool,
) -> Response {
    let mut response = Response::new(Body::from(Bytes::from_owner(body)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        }),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if active {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        headers.insert("obs-status", HeaderValue::from_static("active"));
    }
    response
}

fn content_type(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|value| value.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label}: {}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("{label} must be a real directory: {}", path.display())
    }
    fs::canonicalize(path).with_context(|| format!("resolve {label}: {}", path.display()))
}

fn read_regular_file(
    root: &Path,
    path: &Path,
    label: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label}: {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("{label} must be a regular file: {}", path.display())
    }
    if metadata.len() > maximum_bytes as u64 {
        bail!("{label} exceeds its byte bound: {}", path.display())
    }
    let resolved =
        fs::canonicalize(path).with_context(|| format!("resolve {label}: {}", path.display()))?;
    if !resolved.starts_with(root) {
        bail!(
            "{label} escapes the Publish runtime root: {}",
            path.display()
        )
    }
    fs::read(resolved).with_context(|| format!("read {label}: {}", path.display()))
}

fn validate_relative_asset_path(path: &str) -> Result<()> {
    if path.is_empty() || path.contains('\\') || path.contains('\0') {
        bail!("Publish runtime asset path is unsafe: {path:?}")
    }
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("Publish runtime asset path is not canonical: {path:?}")
    }
    Ok(())
}

fn inventory_tree(root: &Path) -> Result<(HashSet<String>, HashSet<String>)> {
    fn walk(
        root: &Path,
        directory: &Path,
        files: &mut HashSet<String>,
        directories: &mut HashSet<String>,
        entries: &mut usize,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_RUNTIME_DEPTH {
            bail!("Publish runtime directory nesting exceeds its bound")
        }
        for entry in fs::read_dir(directory)
            .with_context(|| format!("read Publish runtime directory: {}", directory.display()))?
        {
            *entries += 1;
            if *entries > MAX_RUNTIME_ENTRIES {
                bail!("Publish runtime directory entry count exceeds its bound")
            }
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!(
                    "Publish runtime contains a symbolic link: {}",
                    path.display()
                )
            }
            if metadata.is_dir() {
                let relative = path
                    .strip_prefix(root)
                    .context("Publish runtime directory escaped its root")?
                    .to_str()
                    .context("Publish runtime directory path is not UTF-8")?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                directories.insert(relative);
                walk(root, &path, files, directories, entries, depth + 1)?;
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .context("Publish runtime inventory path escaped its root")?;
                let relative = relative
                    .to_str()
                    .context("Publish runtime asset path is not UTF-8")?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                files.insert(relative);
            } else {
                bail!(
                    "Publish runtime contains an unsupported entry: {}",
                    path.display()
                )
            }
        }
        Ok(())
    }
    let mut files = HashSet::new();
    let mut directories = HashSet::new();
    let mut entries = 0;
    walk(root, root, &mut files, &mut directories, &mut entries, 0)?;
    Ok((files, directories))
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{label} must be 64 lowercase hexadecimal characters")
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("serialize JSON string"),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("serialize JSON key"),
                        canonical_json(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::extract::Request;
    use tempfile::tempdir;
    use tower::ServiceExt;

    #[test]
    fn verifies_a_source_bound_runtime_and_rejects_tampering() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join("app.js"), b"runtime").unwrap();
        fs::write(root.join("app.css"), b"styles").unwrap();
        let assets = json!([
            {"path":"app.css","bytes":6,"sha256":sha256(b"styles")},
            {"path":"app.js","bytes":7,"sha256":sha256(b"runtime")}
        ]);
        let mut manifest = json!({
            "schemaVersion":1,
            "generatedBy":"tools/inspect-publish-runtime.ts",
            "assets":assets,
            "entrypoints":{"app.css":sha256(b"styles"),"app.js":sha256(b"runtime")},
            "routeAnchors":{"/access/":1,"/cache/":1,"/options/":1},
            "dataRoutes":["/access/","/cache/","/options/"],
            "externalOrigins":[]
        });
        let runtime_sha256 = sha256(canonical_json(&manifest).as_bytes());
        manifest.as_object_mut().unwrap().insert(
            "runtimeSha256".into(),
            Value::String(runtime_sha256.clone()),
        );
        let receipt = json!({
            "schemaVersion":1,
            "generatedBy":"tools/adapt-publish-runtime.ts",
            "sourceRuntimeSha256":"a".repeat(64),
            "outputRuntimeSha256":runtime_sha256,
            "incisions":[],
            "outputManifest":manifest
        });
        fs::write(
            root.join(RECEIPT_FILE),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        let verified = VerifiedPublishRuntime::load(
            root,
            receipt["outputRuntimeSha256"].as_str().unwrap(),
            &"a".repeat(64),
        )
        .unwrap();
        assert_eq!(verified.report()["assets"], 2);
        assert!(
            VerifiedPublishRuntime::load(
                root,
                receipt["outputRuntimeSha256"].as_str().unwrap(),
                &"b".repeat(64),
            )
            .unwrap_err()
            .to_string()
            .contains("reviewed source identity")
        );
        fs::create_dir(root.join("unbound")).unwrap();
        assert!(
            VerifiedPublishRuntime::load(
                root,
                receipt["outputRuntimeSha256"].as_str().unwrap(),
                &"a".repeat(64),
            )
            .unwrap_err()
            .to_string()
            .contains("files or directories")
        );
        fs::remove_dir(root.join("unbound")).unwrap();
        fs::write(root.join("app.js"), b"changed").unwrap();
        assert!(
            VerifiedPublishRuntime::load(
                root,
                receipt["outputRuntimeSha256"].as_str().unwrap(),
                &"a".repeat(64),
            )
            .unwrap_err()
            .to_string()
            .contains("identity changed")
        );
    }

    #[test]
    fn rejects_unbound_files_and_path_traversal() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join(RECEIPT_FILE), b"{}").unwrap();
        assert!(
            VerifiedPublishRuntime::load(directory.path(), &"a".repeat(64), &"b".repeat(64),)
                .is_err()
        );
        assert!(validate_relative_asset_path("../outside").is_err());
        assert!(validate_relative_asset_path("/absolute").is_err());
    }

    #[tokio::test]
    async fn replay_serves_bound_assets_and_required_public_headers() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join("app.js"), b"runtime").unwrap();
        fs::write(root.join("app.css"), b"styles").unwrap();
        let mut manifest = json!({
            "schemaVersion":1,
            "generatedBy":"tools/inspect-publish-runtime.ts",
            "assets":[
                {"path":"app.css","bytes":6,"sha256":sha256(b"styles")},
                {"path":"app.js","bytes":7,"sha256":sha256(b"runtime")}
            ],
            "entrypoints":{"app.css":sha256(b"styles"),"app.js":sha256(b"runtime")},
            "routeAnchors":{"/access/":1,"/cache/":1,"/options/":1},
            "dataRoutes":["/access/","/cache/","/options/"],
            "externalOrigins":[]
        });
        let runtime_sha256 = sha256(canonical_json(&manifest).as_bytes());
        manifest.as_object_mut().unwrap().insert(
            "runtimeSha256".into(),
            Value::String(runtime_sha256.clone()),
        );
        fs::write(
            root.join(RECEIPT_FILE),
            serde_json::to_vec(&json!({
                "schemaVersion":1,
                "generatedBy":"tools/adapt-publish-runtime.ts",
                "sourceRuntimeSha256":"a".repeat(64),
                "outputRuntimeSha256":runtime_sha256,
                "incisions":[],
                "outputManifest":manifest
            }))
            .unwrap(),
        )
        .unwrap();
        let runtime = VerifiedPublishRuntime::load(root, &runtime_sha256, &"a".repeat(64)).unwrap();
        let router = replay_router(runtime);

        let options = router
            .clone()
            .oneshot(
                Request::get(format!("/options/{REPLAY_SITE_UID}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(options.status(), StatusCode::OK);
        assert_eq!(options.headers()["obs-status"], "active");
        assert_eq!(options.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");

        let asset = router
            .clone()
            .oneshot(Request::get("/app.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            asset.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            to_bytes(asset.into_body(), 16).await.unwrap().as_ref(),
            b"runtime"
        );

        let identity = router
            .oneshot(
                Request::get("/.well-known/blackglass-publish-runtime.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let identity: Value =
            serde_json::from_slice(&to_bytes(identity.into_body(), 2048).await.unwrap()).unwrap();
        assert_eq!(identity["runtimeSha256"], runtime_sha256);
        assert_eq!(identity["verified"], true);
    }
}
