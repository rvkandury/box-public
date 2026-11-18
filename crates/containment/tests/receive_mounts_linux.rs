//! Linux end-to-end proof that a mount arriving after the view is built reaches a receiving path.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]

use std::ffi::CString;
use std::io::BufRead as _;
use std::path::Path;
use std::process::{Command, Stdio};

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

/// The SnapStart sandbox agent binds each storage folder into the container as a receiver of a
/// shared mount, and mounts the storage there only when a session starts, after the box is running.
#[test]
fn a_mount_that_arrives_after_start_appears_at_a_receiving_path() {
    let Some(outcome) = run(true) else { return };
    assert!(
        outcome.contains("FILE_APPEARED from-the-late-mount"),
        "{outcome}"
    );
}

/// Without `receive_mounts`, the view stays private, and the late mount never appears.
#[test]
fn a_mount_that_arrives_after_start_stays_out_of_a_private_view() {
    let Some(outcome) = run(false) else { return };
    assert!(outcome.contains("FILE_NEVER_APPEARED"), "{outcome}");
}

fn run(receive: bool) -> Option<String> {
    // SAFETY: plain getter.
    if unsafe { libc::geteuid() } != 0 {
        println!("skipping: mounting the late file system needs root");
        return None;
    }
    let probe = Path::new(env!("CARGO_BIN_EXE_containment-test-probe"));
    let probe_dir = tempfile::tempdir().expect("probe directory");
    let staged_probe = probe_dir.path().join("containment-test-probe");
    std::fs::copy(probe, &staged_probe).expect("stage probe for the launch identity");
    let storage = tempfile::tempdir().expect("storage directory");
    let storage_path = storage.path().canonicalize().expect("canonical storage");
    mount(Some(&storage_path), &storage_path, None, libc::MS_BIND).expect("self-bind");
    mount(None, &storage_path, None, libc::MS_SHARED).expect("make the source shared");

    let mut config = ContainmentConfig::new()
        .allow(&staged_probe, Operation::Read, Scope::File)
        .expect("read probe")
        .allow(&staged_probe, Operation::Exec, Scope::File)
        .expect("execute probe")
        .allow(&storage_path, Operation::Read, Scope::Root)
        .expect("read storage")
        .allow(&storage_path, Operation::Write, Scope::Root)
        .expect("write storage");
    if receive {
        config = config
            .receive_mounts(&storage_path)
            .expect("receive mounts");
    }
    let config_json = config.to_json().expect("config json");
    let config_sha256 = Sha256::digest(config_json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let config_file = tempfile::NamedTempFile::new().expect("config file");
    std::fs::write(config_file.path(), config_json).expect("write config");

    let mut child = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .arg("--config")
        .arg(config_file.path())
        .arg("--config-sha256")
        .arg(config_sha256)
        .arg("--target-env-json")
        .arg("{}")
        .arg("--")
        .arg(&staged_probe)
        .arg("--wait-for-file")
        .arg(storage_path.join("late.txt"))
        .arg("10")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch the real containment trampoline");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout"));
    let mut first = String::new();
    stdout.read_line(&mut first).expect("the probe starts");
    assert_eq!(
        first.trim(),
        "WAITING",
        "the workload did not start: {first}"
    );

    mount(None, &storage_path, Some("tmpfs"), 0).expect("the late mount");
    std::fs::write(storage_path.join("late.txt"), "from-the-late-mount").expect("a file on it");

    let output = child.wait_with_output().expect("the probe ends");
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut rest).expect("stdout");
    unmount(&storage_path);
    unmount(&storage_path);
    Some(format!(
        "{rest}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn mount(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
) -> std::io::Result<()> {
    let source = CString::new(source.map_or("none".to_string(), |p| p.display().to_string()))?;
    let target = CString::new(target.display().to_string())?;
    let fstype = fstype.map(CString::new).transpose()?;
    // SAFETY: NUL-terminated strings that outlive the call.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ref().map_or(std::ptr::null(), |f| f.as_ptr()),
            flags,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn unmount(target: &Path) {
    let target = CString::new(target.display().to_string()).expect("path");
    // SAFETY: NUL-terminated string.
    unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
}
