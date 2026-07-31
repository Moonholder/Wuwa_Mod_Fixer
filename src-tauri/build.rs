fn main() {
    tauri_build::build();

    println!("cargo:rerun-if-env-changed=BUILD_TEST_TAG");

    let tag = std::env::var("BUILD_TEST_TAG").unwrap_or_else(|_| {
        std::process::Command::new("git")
            .args(["rev-parse", "--short=7", "HEAD"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default()
            .trim()
            .to_string()
    });

    let tag = if tag.is_empty() { "DEV".to_string() } else { tag };
    println!("cargo:rustc-env=BUILD_GIT_HASH={tag}");
}
