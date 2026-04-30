<h1 align="center">🌊 Wuwa Mod Fixer</h1>

<p align="center">
  <b>A tool designed for fixing textures, hashes, and vertex groups in modified assets caused by version updates.</b>
</p>

<p align="center">
  <a href="https://github.com/Moonholder/Wuwa_Mod_Fixer/releases/latest"><img src="https://img.shields.io/github/v/release/Moonholder/Wuwa_Mod_Fixer?color=blue&label=Latest" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL_3.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Rust-2024%20Edition-orange?logo=rust&logoColor=white" alt="Rust">
</p>

<p align="center">
  <a href="#chinese-version">中文说明</a> · <a href="#english-version">English</a>
</p>

<p align="center">
  <a href="https://ko-fi.com/moonholder"><img src="https://img.shields.io/badge/Ko--fi-Support-F16061?logo=ko-fi&logoColor=white" alt="Ko-fi"></a>
  <a href="https://support.jix.de5.net"><img src="https://img.shields.io/badge/WeChat-赞助支持-07C160?logo=wechat&logoColor=white" alt="WeChat Pay"></a>
</p>

---

<a name="chinese-version"></a>
## 中文说明

### ✨ 主要功能
- **自动化修复**：自动识别资源哈希变动并进行替换。
- **派生 Hash 支持**：通过纹理重定向修复高/中画质下的纹理错误。
- **回滚管理**：内置回滚管理器，可随时恢复到修改前的原始状态。
- **跨平台 GUI**：基于 Iced 0.14 构建，支持 Windows、Linux (Steam Deck)。
- **双模式运行**：支持图形界面与传统的控制台模式。

### 🛠️ 编译与打包
确保你已安装 [Rust](https://rustup.rs/) 环境。

#### 本地运行
```bash
cargo run --release
```

#### Windows 打包
```bash
cargo build --release --target x86_64-pc-windows-msvc
```

#### Linux 打包 (Ubuntu/Steam Deck)
需预装 `libx11-dev`, `libwayland-dev` 等依赖。
```bash
cargo build --release
```

### 🚀 命令行参数
程序支持以下启动参数：

| 参数 | 说明 |
| :--- | :--- |
| `--cli` | **进入控制台模式**（交互式菜单）。 |
| `--path <DIR>` | **指定 Mod 文件夹路径**，启用非交互直接修复模式。需搭配 `--cli` 使用。 |
| `--derived-hashes` | 启用「补全贴图状态」（与 `--stable-texture` 互斥）。 |
| `--stable-texture` | 启用「应用稳定纹理」（与 `--derived-hashes` 互斥）。 |
| `--aemeath-mech` | 启用「修复爱弥斯机兵形态」。 |
| `--texcoord-color` | 启用「修复 TexCoord COLOR1 数据」（修复3.3版本角色部分模组某些部位不显示的问题）。 |
| `--aero-fix <1\|2>` | 启用「女漂-风主形态眼部修复」。`1` = TexCoord 覆盖, `2` = 贴图镜像反转。 |
| `--rollback` | **回滚最近一次修复**（仅撤销上一次操作，与修复选项互斥）。 |
| `--online` | 联网获取最新配置（非交互模式默认使用本地配置）。 |
| `--dev` | **开发者模式**。强制加载本地配置文件，禁用远程获取逻辑。 |

**示例：**
```bash
# 以控制台交互模式运行
./Mod_Fixer --cli

# 一键修复（仅基础 hash 替换）
./Mod_Fixer --cli --path "D:\Mods\MyMod"

# 一键修复 + 补全贴图状态 + 联网获取最新配置
./Mod_Fixer --cli --path "D:\Mods\MyMod" --derived-hashes --online

# 一键修复 + 应用稳定纹理 + 爱弥斯机兵修复
./Mod_Fixer --cli --path "D:\Mods\MyMod" --stable-texture --aemeath-mech

# 一键修复 + 风主眼部修复 (TexCoord 模式)
./Mod_Fixer --cli --path "D:\Mods\MyMod" --aero-fix 1

# 回滚最近一次修复
./Mod_Fixer --cli --path "D:\Mods\MyMod" --rollback

# 以开发者模式运行
cargo run -- --dev
```

---

<a name="english-version"></a>
## English

### ✨ Features
- **Automated Fixes**: Automatically detects and replaces asset hash changes.
- **Derived Hash Support**: Fixes texture glitches via redirection for different quality settings.
- **Rollback Manager**: Built-in manager to revert modifications to their original state.
- **Cross-platform GUI**: Built with Iced 0.14, supports Windows and Linux (Steam Deck).
- **Dual Mode**: Supports both Graphical User Interface and classic Terminal mode.

### 🛠️ Build & Packaging
Ensure you have [Rust](https://rustup.rs/) installed.

#### Run Locally
```bash
cargo run --release
```

#### Build for Windows
```bash
cargo build --release --target x86_64-pc-windows-msvc
```

#### Build for Linux (Ubuntu/Steam Deck)
Requires dependencies like `libx11-dev`, `libwayland-dev`.
```bash
cargo build --release
```

### 🚀 Command Line Arguments
The application supports the following startup arguments:

| Argument | Description |
| :--- | :--- |
| `--cli` | **Enter Console Mode** (interactive menu). |
| `--path <DIR>` | **Specify Mod folder path** for non-interactive direct fix mode. Must be used with `--cli`. |
| `--derived-hashes` | Enable "Add Derived Hashes" (mutually exclusive with `--stable-texture`). |
| `--stable-texture` | Enable "Apply Stable Texture" (mutually exclusive with `--derived-hashes`). |
| `--aemeath-mech` | Enable "Fix Aemeath's mech form model error". |
| `--texcoord-color` | Enable "Fix TexCoord COLOR1 Data" (Fixes the issue where some parts of mods are not rendering for some characters in version 3.3). |
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

# One-click fix + derived hashes + fetch latest config online
./Mod_Fixer --cli --path "D:\Mods\MyMod" --derived-hashes --online

# One-click fix + stable texture + Aemeath mech fix
./Mod_Fixer --cli --path "D:\Mods\MyMod" --stable-texture --aemeath-mech

# One-click fix + Aero eye fix (TexCoord mode)
./Mod_Fixer --cli --path "D:\Mods\MyMod" --aero-fix 1

# Rollback the most recent fix
./Mod_Fixer --cli --path "D:\Mods\MyMod" --rollback

# Run in dev mode
cargo run -- --dev
```
