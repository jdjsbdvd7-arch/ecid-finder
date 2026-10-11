//! ecid-signer: logs in to Apple developer services with a *user-supplied* Apple ID
//! (session only, nothing persisted), registers the user's device by UDID, creates the
//! dev cert / App ID / provisioning profile on the user's own free Personal Team, and
//! signs the user's own IPA. Built on the open-source `isideload` crate.
//!
//! Protocol: JSON lines. stdin: one `start` message, then optional `2fa` replies.
//! stdout: events {"event": "..."}. Credentials live only in this process's memory.

mod bundle_id;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use isideload::anisette::remote_v3::RemoteV3AnisetteProvider;
use isideload::auth::apple_account::{AppleAccount, TwoFactorCallbackResponse};
use isideload::dev::developer_session::DeveloperSession;
use isideload::dev::devices::DevicesApi;
use isideload::sideload::builder::{MaxCertsBehavior, SideloaderBuilder, TeamSelection};
use isideload::util::callbacks::MaxCertsCallbackBox;
use isideload::util::fs_storage::FsStorage;
use isideload::util::storage::InMemoryStorage;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

#[derive(Deserialize)]
struct Start {
    email: String,
    password: String,
    udid: String,
    #[serde(default = "default_name", rename = "deviceName")]
    device_name: String,
    ipa: String,
    out: String,
    /// "error" (default) or "revoke"
    #[serde(default, rename = "maxCerts")]
    max_certs: String,
    #[serde(default, rename = "anisetteUrl")]
    anisette_url: Option<String>,
    /// directory for anisette device state ONLY (no credentials / tokens)
    #[serde(default, rename = "stateDir")]
    state_dir: Option<String>,
    /// optional user-chosen bundle id to sign the app under
    #[serde(default, rename = "bundleId")]
    bundle_id: Option<String>,
}

fn default_name() -> String {
    "ECID Finder device".to_string()
}

fn emit(v: Value) {
    println!("{}", v);
}

fn fail(code: &str, msg: impl std::fmt::Display) -> ! {
    emit(json!({"event":"error","code":code,"message":msg.to_string()}));
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    // reqwest is built with `rustls-no-provider`: install ring before any HTTP client exists.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let stdin = Arc::new(Mutex::new(BufReader::new(tokio::io::stdin())));

    let first = {
        let mut line = String::new();
        let n = stdin.lock().await.read_line(&mut line).await.unwrap_or(0);
        if n == 0 {
            fail("no_input", "expected a start message on stdin");
        }
        line
    };
    let start: Start = match serde_json::from_str(&first) {
        Ok(s) => s,
        Err(e) => fail("bad_start", e),
    };
    if !valid_udid(&start.udid) {
        fail("bad_udid", "UDID must look like 8hex-16hex or 40hex");
    }
    // ---- App ID hygiene (before any network) -------------------------------------------
    // Personal Teams cannot register com.apple.* identifiers (Apple error 9400). Rewrite the
    // IPA's own identifier (main app + extensions + Watch) to a unique one under our prefix.
    let source_ipa = PathBuf::from(&start.ipa);
    let original_id = match bundle_id::read_main_id(&source_ipa) {
        Ok(id) => id,
        Err(e) => fail("bad_ipa", e),
    };
    let work_ipa = PathBuf::from(format!("{}.rewritten.ipa", start.out));
    let mut current_ipa = source_ipa.clone();
    let mut current_id = original_id.clone();
    let wanted = match start.bundle_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(o) if bundle_id::valid_override(o) => Some((o.to_string(), "override")),
        Some(_) => fail("bad_bundle_id", "The custom bundle ID is invalid or reserved (com.apple.* is not allowed)."),
        None if bundle_id::is_reserved(&original_id) => Some((bundle_id::unique_id(&original_id, 0), "reserved")),
        None => None,
    };
    if let Some((new_id, reason)) = wanted {
        if new_id != original_id {
            match bundle_id::rewrite_ipa(&source_ipa, &work_ipa, &original_id, &new_id) {
                Ok(_) => {
                    emit(json!({"event":"bundle_rewrite","from":original_id,"to":new_id,"reason":reason}));
                    current_ipa = work_ipa.clone();
                    current_id = new_id;
                }
                Err(e) => fail("rewrite_failed", format!("Could not rewrite the bundle identifier: {e}")),
            }
        }
    }

    if let Err(e) = isideload::init() {
        eprintln!("init warning: {e:?}");
    }

    emit(json!({"event":"stage","stage":"anisette"}));
    let mut provider = match RemoteV3AnisetteProvider::default() {
        Ok(p) => p,
        Err(e) => fail("anisette_init", format!("{e:?}")),
    };
    if let Some(u) = &start.anisette_url {
        provider = provider.set_url(u);
    }
    if let Some(dir) = &start.state_dir {
        provider = provider.set_storage(Box::new(FsStorage::new(PathBuf::from(dir))));
    }

    emit(json!({"event":"stage","stage":"apple_login"}));
    let stdin2 = stdin.clone();
    let two_fa = move |params: isideload::auth::apple_account::TwoFactorCallbackParams| {
        let stdin = stdin2.clone();
        async move {
            emit(json!({"event":"need_2fa","params":params}));
            let mut line = String::new();
            let n = stdin.lock().await.read_line(&mut line).await.unwrap_or(0);
            if n == 0 {
                return Ok(TwoFactorCallbackResponse::Abort);
            }
            let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            let resp = match v.get("action").and_then(|a| a.as_str()) {
                Some("code") => TwoFactorCallbackResponse::SubmitCode(
                    v.get("code").and_then(|c| c.as_str()).unwrap_or("").trim().to_string(),
                ),
                Some("sms") => TwoFactorCallbackResponse::SendSms(
                    v.get("id").and_then(|c| c.as_u64()).unwrap_or(1) as u32,
                ),
                Some("devices") => TwoFactorCallbackResponse::SendToDevices,
                Some("resend") => TwoFactorCallbackResponse::ResendCode,
                _ => TwoFactorCallbackResponse::Abort,
            };
            Ok(resp)
        }
    };

    let mut account = match AppleAccount::builder(&start.email)
        .anisette_provider(provider)
        .login(&start.password, two_fa)
        .await
    {
        Ok(a) => a,
        Err(e) => fail("apple_login_failed", format!("{e:?}")),
    };
    // password no longer needed; `start` is dropped at end of scope, but shadow-clear anyway
    let email = start.email.clone();
    drop(start.password);
    emit(json!({"event":"stage","stage":"apple_logged_in"}));

    let session = match DeveloperSession::from_account(&mut account).await {
        Ok(s) => s,
        Err(e) => fail("dev_session_failed", format!("{e:?}")),
    };

    let behavior: MaxCertsBehavior<MaxCertsCallbackBox> = if start.max_certs == "revoke" {
        MaxCertsBehavior::Revoke
    } else {
        MaxCertsBehavior::Error
    };
    let mut sideloader = SideloaderBuilder::<MaxCertsCallbackBox>::new(session, email)
        .team_selection(TeamSelection::First)
        .max_certs_behavior(behavior)
        .machine_name("ECID Finder".to_string())
        // certificate private key is kept in memory only: nothing persisted
        .storage(Box::new(InMemoryStorage::new()))
        .delete_app_after_install(false)
        .build();

    emit(json!({"event":"stage","stage":"team"}));
    let team = match sideloader.get_team().await {
        Ok(t) => t,
        Err(e) => fail("team_failed", format!("{e:?}")),
    };
    emit(json!({"event":"team","teamId":team.team_id,"name":team.name}));

    emit(json!({"event":"stage","stage":"register_device"}));
    if let Err(e) = sideloader
        .get_dev_session()
        .ensure_device_registered(&team, &start.device_name, &start.udid, None)
        .await
    {
        fail("register_device_failed", format!("{e:?}"));
    }
    emit(json!({"event":"device_registered","udid":start.udid}));

    emit(json!({"event":"stage","stage":"sign"}));
    let mut salt: u32 = 0;
    let (signed_dir, _special) = loop {
        let progress = |p: f32| async move {
            emit(json!({"event":"progress","value":p}));
        };
        match sideloader
            .sign_app(
                current_ipa.clone(),
                Some(team.clone()),
                false,
                Some(progress),
                None,
                Some(&start.udid),
            )
            .await
        {
            Ok(r) => break r,
            Err(e) => {
                let msg = format!("{e:?}");
                let unavailable = msg.contains("9400") || msg.contains("is not available");
                if unavailable && salt < 3 {
                    // The (team-suffixed) App ID is taken / not ours: pick another unique id and retry.
                    salt += 1;
                    let new_id = bundle_id::unique_id(&original_id, salt);
                    match bundle_id::rewrite_ipa(&source_ipa, &work_ipa, &original_id, &new_id) {
                        Ok(_) => {
                            emit(json!({"event":"bundle_rewrite","from":original_id,"to":new_id,"reason":"unavailable"}));
                            current_ipa = work_ipa.clone();
                            current_id = new_id;
                            continue;
                        }
                        Err(re) => fail("rewrite_failed", format!("{re} / after: {msg}")),
                    }
                }
                fail("sign_failed", msg)
            }
        }
    };
    let _ = &current_id;

    emit(json!({"event":"stage","stage":"package"}));
    match zip_ipa(&signed_dir, Path::new(&start.out)) {
        Ok(()) => {}
        Err(e) => fail("package_failed", e),
    }
    let _ = std::fs::remove_file(&work_ipa);
    emit(json!({"event":"done","out":start.out,"teamId":team.team_id,"bundleId":current_id}));
}

fn valid_udid(u: &str) -> bool {
    let b = u.as_bytes();
    let hex = |s: &[u8]| s.iter().all(|c| c.is_ascii_hexdigit());
    (b.len() == 25 && b[8] == b'-' && hex(&b[..8]) && hex(&b[9..]))
        || (b.len() == 40 && hex(b))
}

/// `signed` is the .app dir (or a dir containing it). Zips as Payload/<name>.app/...
fn zip_ipa(signed: &Path, out: &Path) -> Result<(), String> {
    use std::io::{Read, Write};
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};
    let app_dir = if signed.extension().map(|e| e == "app").unwrap_or(false) {
        signed.to_path_buf()
    } else {
        walkdir::WalkDir::new(signed)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .find(|e| e.path().extension().map(|x| x == "app").unwrap_or(false) && e.path().is_dir())
            .map(|e| e.path().to_path_buf())
            .ok_or("no .app bundle found after signing")?
    };
    let name = app_dir.file_name().unwrap().to_string_lossy().to_string();
    let f = std::fs::File::create(out).map_err(|e| e.to_string())?;
    let mut zw = ZipWriter::new(f);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for entry in walkdir::WalkDir::new(&app_dir).into_iter().filter_map(|e| e.ok()) {
        let rel = entry.path().strip_prefix(&app_dir).unwrap();
        let zpath = format!("Payload/{}/{}", name, rel.to_string_lossy());
        if entry.file_type().is_dir() {
            if !rel.as_os_str().is_empty() {
                zw.add_directory(format!("{zpath}/"), opts).map_err(|e| e.to_string())?;
            }
        } else if entry.file_type().is_file() {
            #[cfg(unix)]
            let opts = {
                use std::os::unix::fs::PermissionsExt;
                let mode = entry.metadata().map(|m| m.permissions().mode()).unwrap_or(0o644);
                opts.unix_permissions(mode)
            };
            zw.start_file(zpath, opts).map_err(|e| e.to_string())?;
            let mut buf = Vec::new();
            std::fs::File::open(entry.path()).and_then(|mut f| f.read_to_end(&mut buf)).map_err(|e| e.to_string())?;
            zw.write_all(&buf).map_err(|e| e.to_string())?;
        }
    }
    zw.finish().map_err(|e| e.to_string())?;
    Ok(())
}
