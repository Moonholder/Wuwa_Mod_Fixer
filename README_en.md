<h1 align="center">🌊 Wuwa Mod Fixer</h1>

<p align="center">
  <b>A tool for fixing mods broken by game updates.</b>
</p>

<p align="center">
  <a href="https://github.com/Moonholder/Wuwa_Mod_Fixer/releases/latest"><img src="https://img.shields.io/github/v/release/Moonholder/Wuwa_Mod_Fixer?color=blue&label=Latest" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL_3.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Rust-2024%20Edition-orange?logo=rust&logoColor=white" alt="Rust">
</p>

<p align="center">
  English Readme | <a href="README.md">中文说明</a>
</p>

<p align="center">
  <a href="https://ko-fi.com/moonholder"><img src="https://img.shields.io/badge/Ko--fi-Support-F16061?logo=ko-fi&logoColor=white" alt="Ko-fi"></a>
  <a href="https://support.jix.de5.net"><img src="https://img.shields.io/badge/WeChat-赞助支持-07C160?logo=wechat&logoColor=white" alt="WeChat Pay"></a>
</p>

---

## 📖 How to Use

Go to the [Releases page](https://github.com/Moonholder/Wuwa_Mod_Fixer/releases/latest) to download the suitable executable:
- **`Wuwa_Mod_Fixer`** (Recommended for most users): Graphical interface version. Double-click to open, select or drag in your Mod folder, and click "Start Fix". Also supports running via command-line arguments.
- **`wuwa-mod-cli`**: Lightweight headless standalone CLI version without GUI dependencies, suitable for terminal users or integration into automation scripts.

### ✨ Features
- **Automated Fixes**: Automatically detects and replaces asset hash changes.
- **Rollback Manager**: Backups are automatically created before fixing, with a built-in manager to restore original state at any time.
- **Cross-platform**: Supports Windows and Linux.
- **Dual Mode**: Supports intuitive graphical interface, interactive console wizard, and direct command-line execution.

### 🚀 Command Line Arguments
The application supports the following startup arguments (shared between desktop and standalone CLI versions):

| Argument | Description |
| :--- | :--- |
| `--path <DIR>` | **Specify Mod folder path**. Specifying this triggers direct fix or rollback. |
| `--cli` | Explicitly enter interactive console mode (for desktop binary). |
| `--rendering-33` | Enable "Rendering 3.3 pipeline fix". |
| `--stable-texture` | Enable "Apply Stable Texture" (mutually exclusive with `--derived-hashes`). |
| `--derived-hashes` | Enable "Add Derived Hashes" (mutually exclusive with `--stable-texture`). |
| `--aemeath-mech` | Enable "Fix Aemeath's mech form model error". |
| `--aero-fix <1\|2>` | Enable "Aero FemaleRover Eye Fix". `1` = TexCoord Override, `2` = Texture Mirror Flip. |
| `--rollback` | **Rollback the most recent fix** (only undoes the last operation; mutually exclusive with fix options). |
| `--config <FILE>` | **Specify a config file path**. Loads that `config.json` first and skips remote fetch. |
| `--online` | Fetch latest configuration online. |
| `--format <text\|json>` | Output format. Default is `text`, set to `json` to output line-delimited NDJSON event stream for third-party tools. |

**Example:**
```bash
# Run in interactive console mode
./wuwa-mod-cli
# Or desktop binary:
./Wuwa_Mod_Fixer --cli

# One-click fix for target Mod
./wuwa-mod-cli --path "D:\Mods\MyMod"

# One-click fix + Rendering 3.3 pipeline fix + apply stable texture
./wuwa-mod-cli --path "D:\Mods\MyMod" --rendering-33 --stable-texture

# One-click fix + derived hashes + fetch latest config online
./wuwa-mod-cli --path "D:\Mods\MyMod" --derived-hashes --online

# One-click fix + use a custom config file
./wuwa-mod-cli --path "D:\Mods\MyMod" --config "D:\Configs\config.json"

# Rollback the most recent fix
./wuwa-mod-cli --path "D:\Mods\MyMod" --rollback

# Stream JSON progress events (for third-party tools)
./wuwa-mod-cli --path "D:\Mods\MyMod" --format json
```

### 🛠️ Build & Packaging
Ensure you have [Rust](https://rustup.rs/) and [Node.js](https://nodejs.org/) (20.x+) installed.

#### Install Dependencies
```bash
npm install
npm install --prefix src-ui
```

#### Run Locally
```bash
npm run tauri dev
```

#### Build
```bash
# Build desktop GUI app (Windows / Linux)
npm run tauri build

# Build standalone headless CLI
cargo build --release -p wuwa-mod-cli
```
For Linux, you'll need to install Tauri system dependencies such as `libwebkit2gtk-4.1-dev`, `build-essential`, `curl`, `wget`, `file`, `libssl-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev` before building the desktop application.

---

## Sponsors

<table>
  <tr>
    <td align="center" width="64px">
      <a href="https://signpath.org">
        <img src="https://avatars.githubusercontent.com/u/34448643?s=48&v=4" width="24" alt="SignPath">
      </a>
    </td>
    <td>
      Free code signing on Windows provided by <a href="https://signpath.io">SignPath.io</a>, certificate by <a href="https://signpath.org">SignPath Foundation</a>
    </td>
  </tr>
</table>
