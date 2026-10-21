//! Explicit user-requested data attachment opening through the OS association.

use std::path::Path;

fn validate_name(path: &Path) -> Result<(), String> {
    let name = path.file_name().and_then(|name| name.to_str()).ok_or("Invalid attachment filename")?;
    if name.ends_with([' ', '.']) || name.contains(':') || name.chars().any(char::is_control) {
        return Err("Invalid attachment filename".into());
    }
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .filter(|extension| !extension.is_empty())
        .ok_or("Attachments without a file extension cannot be opened")?
        .to_ascii_lowercase();
    if matches!(
        extension.as_str(),
        "exe"
            | "com"
            | "bat"
            | "cmd"
            | "ps1"
            | "ps1xml"
            | "psm1"
            | "psd1"
            | "vbs"
            | "vbe"
            | "js"
            | "mjs"
            | "cjs"
            | "jse"
            | "wsf"
            | "wsh"
            | "hta"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "py"
            | "pyw"
            | "pl"
            | "rb"
            | "jar"
            | "msi"
            | "msc"
            | "chm"
            | "msp"
            | "mst"
            | "scr"
            | "pif"
            | "cpl"
            | "dll"
            | "sys"
            | "drv"
            | "ocx"
            | "lnk"
            | "url"
            | "scf"
            | "appref-ms"
            | "application"
            | "desktop"
            | "app"
            | "command"
            | "reg"
            | "inf"
            | "ins"
            | "isp"
            | "gadget"
            | "workflow"
            | "action"
    ) {
        return Err("Executable, script and shortcut attachments cannot be opened".into());
    }
    Ok(())
}

/// Shell associations need DOS/UNC paths rather than filesystem verbatim paths.
/// Build only the launch spelling; keep the canonical path for validation.
#[cfg(windows)]
fn launch_path(path: &Path) -> Result<std::path::PathBuf, String> {
    use std::ffi::OsString;
    use std::path::{Component, PathBuf, Prefix};

    let invalid = || "Unsupported attachment path prefix".to_string();
    if !path.is_absolute() {
        return Err(invalid());
    }
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else { return Err(invalid()) };
    let mut result = match prefix.kind() {
        Prefix::VerbatimDisk(drive) | Prefix::Disk(drive) => PathBuf::from(format!("{}:\\", char::from(drive))),
        Prefix::VerbatimUNC(server, share) | Prefix::UNC(server, share) => {
            let mut root = OsString::from("\\\\");
            root.push(server);
            root.push("\\");
            root.push(share);
            root.push("\\");
            PathBuf::from(root)
        }
        _ => return Err(invalid()),
    };
    for component in components {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => result.push(name),
            _ => return Err(invalid()),
        }
    }
    Ok(result)
}

/// Call only for an explicit open gesture after the host verifies managed access.
/// Success means the OS accepted dispatch, not that an external editor loaded it.
pub(crate) fn open(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("Attachment path must be absolute".into());
    }
    validate_name(path)?;
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| "Attachment is unavailable")?;
        if metadata.file_type().is_symlink() {
            return Err("Attachment links cannot be opened".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Attachment links cannot be opened".into());
            }
        }
    }
    if !std::fs::metadata(path).map_err(|_| "Attachment is unavailable")?.is_file() {
        return Err("Attachment is not a file".into());
    }
    let path = std::fs::canonicalize(path).map_err(|_| "Attachment is unavailable")?;
    validate_name(&path)?;
    #[cfg(windows)]
    let launch = launch_path(&path)?;
    #[cfg(not(windows))]
    let launch = path;
    // Pass a native Path, preserving spaces, Unicode and literal percent/hash
    // characters. The dependency supplies the safe platform association API.
    opener::open(launch.as_os_str()).map_err(|_| "The associated application could not be opened".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_attachment_allows_data_names_without_interpreting_shell_characters() {
        for name in ["notes.txt", "drawing.PDF", "component.ipt", "a & b # 10%.txt", "caffè.pdf"] {
            assert!(validate_name(std::path::Path::new(name)).is_ok(), "{name}");
        }
    }

    #[test]
    fn external_attachment_rejects_executables_scripts_shortcuts_and_ambiguous_names() {
        for name in [
            "run.EXE",
            "run.com",
            "run.bat",
            "run.cmd",
            "run.ps1",
            "run.vbs",
            "run.js",
            "run.mjs",
            "run.cjs",
            "run.ps1xml",
            "run.msc",
            "help.chm",
            "run.sh",
            "run.py",
            "run.jar",
            "link.lnk",
            "link.url",
            "link.scf",
            "installer.msi",
            "unknown",
            "unknown.",
            "run.exe ",
            "file.txt:run.exe",
            "bad\0.txt",
        ] {
            assert!(validate_name(std::path::Path::new(name)).is_err(), "{name:?}");
        }
    }

    #[test]
    fn external_attachment_rejects_relative_and_missing_files_without_launch() {
        assert!(open(std::path::Path::new("missing.txt")).is_err());
        assert!(open(&std::env::temp_dir().join("solidcraft-external-missing-file.invalid.txt")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn external_attachment_launch_path_converts_verbatim_dos_and_unc_without_encoding() {
        for (source, expected) in [
            (r"\\?\C:\Working\part.ipt", r"C:\Working\part.ipt"),
            (r"\\?\UNC\server\share\part.ipt", r"\\server\share\part.ipt"),
            (r"\\?\C:\Caffè & space\100% # pièce.pdf", r"C:\Caffè & space\100% # pièce.pdf"),
            (r"\\?\UNC\server\share\Caffè & space\100% # pièce.pdf", r"\\server\share\Caffè & space\100% # pièce.pdf"),
            (r"C:\Working\part.ipt", r"C:\Working\part.ipt"),
            (r"\\server\share\part.ipt", r"\\server\share\part.ipt"),
        ] {
            assert_eq!(launch_path(Path::new(source)).unwrap(), Path::new(expected));
        }
    }

    #[cfg(windows)]
    #[test]
    fn external_attachment_launch_path_rejects_device_prefixes() {
        for source in [r"\\.\C:\part.ipt", r"\\?\GLOBALROOT\Device\HarddiskVolume1\part.ipt", r"\??\C:\part.ipt", r"C:part.ipt", r"part.ipt"] {
            assert!(launch_path(Path::new(source)).is_err(), "{source}");
        }
    }
}
