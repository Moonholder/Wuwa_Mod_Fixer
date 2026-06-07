use std::process::Command;

fn main() {
    // Let Cargo know that if config.yml or compile_config.js changes, this build script must rerun
    println!("cargo:rerun-if-changed=../config.yml");
    println!("cargo:rerun-if-changed=../scripts/compile_config.js");
    println!("cargo:rerun-if-changed=src/resources/FixAeroRoverFemaleChargedEyesMap.dds");

    // Automatically invoke Node.js to compile config.yml into minified config.json
    let status = Command::new("node")
        .args(&["../scripts/compile_config.js"])
        .status();

    if let Ok(stat) = status {
        if stat.success() {
            println!("cargo:warning=Successfully auto-compiled config.yml into config.json!");
        } else {
            println!("cargo:warning=Failed to auto-compile config.yml: compile script exited with error.");
        }
    } else {
        println!("cargo:warning=Warning: Node.js was not found in your PATH. Auto-compile of config.yml was skipped.");
    }
}
