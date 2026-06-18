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

Go to the [Releases page](https://github.com/Moonholder/Wuwa_Mod_Fixer/releases/latest) to download the executable file. Double-click to open it, select or drag in your Mod folder, and click the "Start Fix" button.


### ✨ Features
- **Automated Fixes**: Automatically detects and replaces asset hash changes.
- **Rollback Manager**: Built-in manager to revert modifications to their original state.
- **Cross-platform GUI**: Built with Tauri V2 (Vue3 + Vite), supports Windows and Linux.
- **Dual Mode**: Supports both Graphical User Interface and classic Terminal mode.

### 🛠️ Build & Packaging
Ensure you have [Rust](https://rustup.rs/) and [Node.js](https://nodejs.org/) (v18+) installed.

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
npm run tauri build
```
For Linux, you'll need to install Tauri system dependencies such as `libwebkit2gtk-4.1-dev`, `build-essential`, `curl`, `wget`, `file`, `libssl-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev` before building.

### 🚀 Command Line Arguments
The application supports the following startup arguments:

| Argument | Description |
| :--- | :--- |
| `--cli` | **Enter Console Mode** (interactive menu). |
| `--path <DIR>` | **Specify Mod folder path** for non-interactive direct fix mode. Must be used with `--cli`. |
| `--config <FILE>` | **Specify a config file path**. The app will load that `config.json` first and skip remote config fetch. |
| `--derived-hashes` | Enable "Add Derived Hashes" (mutually exclusive with `--stable-texture`). |
| `--stable-texture` | Enable "Apply Stable Texture" (mutually exclusive with `--derived-hashes`). |
| `--aemeath-mech` | Enable "Fix Aemeath's mech form model error". |
| `--aero-fix <1\|2>` | Enable "Aero FemaleRover Eye Fix". `1` = TexCoord Override, `2` = Texture Mirror Flip. |
| `--rollback` | **Rollback the most recent fix** (only undoes the last operation; mutually exclusive with fix options). |
| `--online` | Fetch latest config from network (non-interactive mode uses local config by default). |
| `--dev` | **Developer Mode**. Forces loading local configuration and disables remote fetch. |

**Example:**
```bash
# Run in interactive console mode
./Mod_Fixer --cli

# One-click fix (basic hash replacement only)
./Mod_Fixer --cli --path "D:\Mods\MyMod"

# One-click fix + use a specific config file
./Mod_Fixer --cli --path "D:\Mods\MyMod" --config "D:\Configs\config.json"

# One-click fix + derived hashes + fetch latest config online
./Mod_Fixer --cli --path "D:\Mods\MyMod" --derived-hashes --online

# One-click fix + stable texture + Aemeath mech fix
./Mod_Fixer --cli --path "D:\Mods\MyMod" --stable-texture --aemeath-mech

# One-click fix + Aero eye fix (TexCoord mode)
./Mod_Fixer --cli --path "D:\Mods\MyMod" --aero-fix 1

# Rollback the most recent fix
./Mod_Fixer --cli --path "D:\Mods\MyMod" --rollback
```

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
