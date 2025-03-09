extern crate winres;

fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        
        res.set_icon("icon.ico");

        let version = env!("CARGO_PKG_VERSION");

        let mut parts: Vec<u16> = version
            .split('.')
            .map(|s| s.parse().unwrap_or(0))
            .collect();

        while parts.len() < 4 {
            parts.push(0);
        }

        let version_number = 
            ((parts[0] as u64) << 48) |
            ((parts[1] as u64) << 32) |
            ((parts[2] as u64) << 16) |
            (parts[3] as u64);

        res.set_version_info(
            winres::VersionInfo::PRODUCTVERSION,
            version_number
        );
        
        res.set("ProductName", "Fixer of Lacus Temporis")
            .set("FileDescription", "WWMI Mods Fix Tool")
            .set("LegalCopyright", "Copyright © 2025")
            .set("CompanyName", "t.me/WuwaMod");
        
        res.compile().expect("无法编译Windows资源");
    }
}