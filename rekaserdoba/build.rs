use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=REKASERDOBA_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let sha = env::var("REKASERDOBA_BUILD_SHA")
        .or_else(|_| env::var("GITHUB_SHA"))
        .ok()
        .and_then(validate_sha)
        .or_else(git_sha)
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=REKASERDOBA_BUILD_SHA={sha}");
}

fn git_sha() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()?;
    let value = output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())?;
    validate_sha(value)
}

fn validate_sha(value: String) -> Option<String> {
    let value = value.trim();
    (value.len() >= 7 && value.len() <= 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}
