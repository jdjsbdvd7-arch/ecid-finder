//! Bundle-identifier handling for free Personal Teams.
//!
//! isideload registers the App ID `<CFBundleIdentifier>.<TEAMID>`. Apple refuses that
//! (error 9400 "An App ID with Identifier ... is not available") when the identifier lives
//! in a namespace the user's team cannot own, e.g. `com.apple.*`. The fix is the same one
//! AltStore / SideStore use: give the app its own unique identifier before signing.
//! This has nothing to do with Apple root certificates or cdhash.

use std::io::{Read, Write};
use std::path::Path;

use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

/// Identifiers a Personal Team can never register.
pub fn is_reserved(id: &str) -> bool {
    let l = id.to_ascii_lowercase();
    l == "com.apple" || l.starts_with("com.apple.")
}

/// Valid user supplied override (reverse-DNS-ish, no Apple namespace).
pub fn valid_override(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 100
        && id.contains('.')
        && !id.starts_with('.')
        && !id.ends_with('.')
        && !id.contains("..")
        && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
        && !is_reserved(id)
}

fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Deterministic (same IPA + same salt => same id, so reinstalling updates instead of
/// burning another of the 10 App IDs/week), e.g. `com.ecidfinder.mobilehousearrest.a1b2c3`.
pub fn unique_id(original: &str, salt: u32) -> String {
    let last = original.rsplit('.').next().unwrap_or("app");
    let mut slug: String = last.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
    if slug.is_empty() {
        slug = "app".into();
    }
    slug.truncate(24);
    let h = fnv(&format!("{original}#{salt}"));
    format!("com.ecidfinder.{slug}.{:06x}", h & 0xff_ffff)
}

fn map_id(v: &str, old: &str, new: &str) -> Option<String> {
    if v == old {
        Some(new.to_string())
    } else if v.len() > old.len() && v.starts_with(old) && v.as_bytes()[old.len()] == b'.' {
        Some(format!("{new}{}", &v[old.len()..]))
    } else {
        None
    }
}

fn is_bundle_plist(name: &str) -> bool {
    // Payload/X.app/Info.plist, Payload/X.app/PlugIns/Y.appex/Info.plist, .../Watch/W.app/Info.plist ...
    let n = name.strip_prefix("Payload/").unwrap_or("");
    n.ends_with("/Info.plist") && n.split('/').next().map(|c| c.ends_with(".app")).unwrap_or(false)
        && !n.contains(".framework/")
}

/// Rewrite one Info.plist. Returns new bytes if anything changed.
fn rewrite_plist(raw: &[u8], old: &str, new: &str) -> Option<Vec<u8>> {
    let binary = raw.starts_with(b"bplist");
    let mut v: plist::Value = plist::from_bytes(raw).ok()?;
    let mut changed = false;
    if let Some(d) = v.as_dictionary_mut() {
        for key in ["CFBundleIdentifier", "WKCompanionAppBundleIdentifier"] {
            if let Some(s) = d.get(key).and_then(|x| x.as_string()).and_then(|s| map_id(s, old, new)) {
                d.insert(key.into(), plist::Value::String(s));
                changed = true;
            }
        }
        if let Some(attrs) = d
            .get_mut("NSExtension")
            .and_then(|e| e.as_dictionary_mut())
            .and_then(|e| e.get_mut("NSExtensionAttributes"))
            .and_then(|e| e.as_dictionary_mut())
        {
            if let Some(s) = attrs.get("WKAppBundleIdentifier").and_then(|x| x.as_string()).and_then(|s| map_id(s, old, new)) {
                attrs.insert("WKAppBundleIdentifier".into(), plist::Value::String(s));
                changed = true;
            }
        }
    }
    if !changed {
        return None;
    }
    let mut out = Vec::new();
    if binary {
        v.to_writer_binary(&mut out).ok()?;
    } else {
        v.to_writer_xml(&mut out).ok()?;
    }
    Some(out)
}

/// Main app bundle id of an IPA.
pub fn read_main_id(ipa: &Path) -> Result<String, String> {
    let f = std::fs::File::open(ipa).map_err(|e| e.to_string())?;
    let mut z = ZipArchive::new(f).map_err(|e| e.to_string())?;
    for i in 0..z.len() {
        let mut e = z.by_index(i).map_err(|e| e.to_string())?;
        let n = e.name().to_string();
        let parts: Vec<&str> = n.split('/').collect();
        if parts.len() == 3 && parts[0] == "Payload" && parts[1].ends_with(".app") && parts[2] == "Info.plist" {
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).map_err(|e| e.to_string())?;
            let v: plist::Value = plist::from_bytes(&buf).map_err(|e| e.to_string())?;
            return v
                .as_dictionary()
                .and_then(|d| d.get("CFBundleIdentifier"))
                .and_then(|x| x.as_string())
                .map(|s| s.to_string())
                .ok_or_else(|| "CFBundleIdentifier missing".to_string());
        }
    }
    Err("no Payload/<App>.app/Info.plist in IPA".into())
}

/// Copy `src` to `dst`, replacing `old` by `new` in the main app, its extensions and Watch app
/// (extensions MUST stay prefixed by the main id). Returns the number of Info.plist files changed.
pub fn rewrite_ipa(src: &Path, dst: &Path, old: &str, new: &str) -> Result<usize, String> {
    let f = std::fs::File::open(src).map_err(|e| e.to_string())?;
    let mut z = ZipArchive::new(f).map_err(|e| e.to_string())?;
    let out = std::fs::File::create(dst).map_err(|e| e.to_string())?;
    let mut w = ZipWriter::new(out);
    let mut changed = 0usize;
    for i in 0..z.len() {
        let name = z.by_index_raw(i).map_err(|e| e.to_string())?.name().to_string();
        if is_bundle_plist(&name) {
            let mut buf = Vec::new();
            {
                let mut e = z.by_index(i).map_err(|e| e.to_string())?;
                e.read_to_end(&mut buf).map_err(|e| e.to_string())?;
            }
            if let Some(nb) = rewrite_plist(&buf, old, new) {
                let mode = z.by_index_raw(i).map_err(|e| e.to_string())?.unix_mode().unwrap_or(0o644);
                let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated).unix_permissions(mode);
                w.start_file(name, opts).map_err(|e| e.to_string())?;
                w.write_all(&nb).map_err(|e| e.to_string())?;
                changed += 1;
                continue;
            }
        }
        let raw = z.by_index_raw(i).map_err(|e| e.to_string())?;
        w.raw_copy_file(raw).map_err(|e| e.to_string())?;
    }
    w.finish().map_err(|e| e.to_string())?;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved() {
        assert!(is_reserved("com.apple.mobile.MobileHouseArrest"));
        assert!(is_reserved("COM.APPLE.foo"));
        assert!(!is_reserved("com.applesauce.app"));
        assert!(!is_reserved("com.example.app"));
    }

    #[test]
    fn unique_is_stable_and_valid() {
        let a = unique_id("com.apple.mobile.MobileHouseArrest", 0);
        assert_eq!(a, unique_id("com.apple.mobile.MobileHouseArrest", 0));
        assert_ne!(a, unique_id("com.apple.mobile.MobileHouseArrest", 1));
        assert!(a.starts_with("com.ecidfinder.mobilehousearrest."));
        assert!(!is_reserved(&a) && valid_override(&a));
    }

    #[test]
    fn map() {
        assert_eq!(map_id("a.b", "a.b", "x.y").as_deref(), Some("x.y"));
        assert_eq!(map_id("a.b.widget", "a.b", "x.y").as_deref(), Some("x.y.widget"));
        assert_eq!(map_id("a.bc", "a.b", "x.y"), None);
    }

    #[test]
    fn override_validation() {
        assert!(valid_override("com.me.app"));
        assert!(!valid_override("com.apple.x"));
        assert!(!valid_override("noDots"));
        assert!(!valid_override("com..x"));
    }

    fn plist_bytes(pairs: &[(&str, &str)], binary: bool) -> Vec<u8> {
        let mut d = plist::Dictionary::new();
        for (k, v) in pairs {
            d.insert(k.to_string(), plist::Value::String(v.to_string()));
        }
        let mut out = Vec::new();
        if binary {
            plist::Value::Dictionary(d).to_writer_binary(&mut out).unwrap();
        } else {
            plist::Value::Dictionary(d).to_writer_xml(&mut out).unwrap();
        }
        out
    }

    #[test]
    fn rewrites_ipa_main_extension_and_keeps_others() {
        let dir = std::env::temp_dir().join(format!("ecid-bid-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("in.ipa");
        let dst = dir.join("out.ipa");
        let old = "com.apple.mobile.MobileHouseArrest.xxx";
        {
            let mut w = ZipWriter::new(std::fs::File::create(&src).unwrap());
            let o = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            for (name, data) in [
                ("Payload/A.app/Info.plist", plist_bytes(&[("CFBundleIdentifier", old)], false)),
                ("Payload/A.app/PlugIns/W.appex/Info.plist", plist_bytes(&[("CFBundleIdentifier", &format!("{old}.widget"))], true)),
                ("Payload/A.app/Frameworks/F.framework/Info.plist", plist_bytes(&[("CFBundleIdentifier", "org.other.f")], false)),
                ("Payload/A.app/A", b"\xcf\xfa\xed\xfe binary".to_vec()),
            ] {
                w.start_file(name, o).unwrap();
                w.write_all(&data).unwrap();
            }
            w.finish().unwrap();
        }
        assert_eq!(read_main_id(&src).unwrap(), old);
        let new = unique_id(old, 0);
        assert_eq!(rewrite_ipa(&src, &dst, old, &new).unwrap(), 2);
        assert_eq!(read_main_id(&dst).unwrap(), new);
        let mut z = ZipArchive::new(std::fs::File::open(&dst).unwrap()).unwrap();
        let mut buf = Vec::new();
        z.by_name("Payload/A.app/PlugIns/W.appex/Info.plist").unwrap().read_to_end(&mut buf).unwrap();
        assert!(buf.starts_with(b"bplist"));
        let v: plist::Value = plist::from_bytes(&buf).unwrap();
        assert_eq!(v.as_dictionary().unwrap()["CFBundleIdentifier"].as_string().unwrap(), format!("{new}.widget"));
        buf.clear();
        z.by_name("Payload/A.app/Frameworks/F.framework/Info.plist").unwrap().read_to_end(&mut buf).unwrap();
        let v: plist::Value = plist::from_bytes(&buf).unwrap();
        assert_eq!(v.as_dictionary().unwrap()["CFBundleIdentifier"].as_string().unwrap(), "org.other.f");
        buf.clear();
        z.by_name("Payload/A.app/A").unwrap().read_to_end(&mut buf).unwrap();
        assert!(buf.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]));
        std::fs::remove_dir_all(&dir).ok();
    }
}
