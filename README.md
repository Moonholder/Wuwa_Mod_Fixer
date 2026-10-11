<h1 align="center">🌊 Wuwa Mod Fixer</h1>

<p align="center">
  <b>一个用于修复由于游戏更新导致的模组失效等问题的工具。</b>
</p>

<p align="center">
  <a href="https://github.com/Moonholder/Wuwa_Mod_Fixer/releases/latest"><img src="https://img.shields.io/github/v/release/Moonholder/Wuwa_Mod_Fixer?color=blue&label=Latest" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL_3.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Rust-2024%20Edition-orange?logo=rust&logoColor=white" alt="Rust">
</p>

<p align="center">
  <a href="README_en.md">English Readme</a> | 中文说明
</p>

<p align="center">
  <a href="https://ko-fi.com/moonholder"><img src="https://img.shields.io/badge/Ko--fi-Support-F16061?logo=ko-fi&logoColor=white" alt="Ko-fi"></a>
  <a href="https://support.jix.de5.net"><img src="https://img.shields.io/badge/WeChat-赞助支持-07C160?logo=wechat&logoColor=white" alt="WeChat Pay"></a>
</p>

---

## 📖 使用方法

前往 [发布页](https://github.com/Moonholder/Wuwa_Mod_Fixer/releases/latest) 下载适合的可执行文件：
- **`Wuwa_Mod_Fixer`**（推荐大多数用户）：图形界面版本，双击打开，选择或拖入 Mod 文件夹，点击“开始修复”即可。同时也支持通过命令行参数直接调用。
- **`wuwa-mod-cli`**：轻量无界面的独立纯命令行版本，适合习惯终端操作或集成到第三方自动化工具的用户。

### ✨ 主要功能
- **自动化修复**：自动识别资源哈希变动并进行替换。
- **回滚管理**：修复前自动创建备份，内置回滚功能，可随时恢复到修改前的原始状态。
- **跨平台支持**：支持 Windows 与 Linux。
- **双模式运行**：支持直观的图形界面，也支持交互式控制台菜单与直接命令行调用。

### 🚀 命令行参数
程序支持以下启动参数（桌面版与纯命令行版通用）：

| 参数 | 说明 |
| :--- | :--- |
| `--path <DIR>` | **指定 Mod 文件夹路径**。传入此参数直接开始修复或回滚。 |
| `--cli` | 显式进入控制台交互模式（对于桌面版）。 |
| `--rendering-33` | 启用「Rendering 3.3 管线修复」。 |
| `--stable-texture` | 启用「应用稳定纹理」（与 `--derived-hashes` 互斥）。 |
| `--derived-hashes` | 启用「补全贴图状态」（与 `--stable-texture` 互斥）。 |
| `--aemeath-mech` | 启用「修复爱弥斯机兵形态」。 |
| `--aero-fix <1\|2>` | 启用「女漂-风主形态眼部修复」。`1` = TexCoord 覆盖, `2` = 贴图镜像反转。 |
| `--rollback` | **回滚最近一次修复**（仅撤销上一次操作，与修复选项互斥）。 |
| `--config <FILE>` | **指定配置文件路径**，优先读取该 `config.json`，并跳过远程配置获取。 |
| `--online` | 联网获取最新配置。 |
| `--format <text\|json>` | 输出格式。默认为 `text`，传 `json` 可输出逐行 NDJSON 事件流，方便第三方工具集成。 |

**示例：**
```bash
# 以控制台交互模式运行
./wuwa-mod-cli
# 或桌面版：
./Wuwa_Mod_Fixer --cli

# 一键修复指定 Mod
./wuwa-mod-cli --path "D:\Mods\MyMod"

# 一键修复 + 启用 Rendering 3.3 修复 + 应用稳定纹理
./wuwa-mod-cli --path "D:\Mods\MyMod" --rendering-33 --stable-texture

# 一键修复 + 补全贴图状态 + 联网获取最新配置
./wuwa-mod-cli --path "D:\Mods\MyMod" --derived-hashes --online

# 一键修复 + 使用指定配置文件
./wuwa-mod-cli --path "D:\Mods\MyMod" --config "D:\Configs\config.json"

# 回滚最近一次修复
./wuwa-mod-cli --path "D:\Mods\MyMod" --rollback

# 输出 JSON 格式流式进度（第三方工具集成）
./wuwa-mod-cli --path "D:\Mods\MyMod" --format json
```

### 🛠️ 开发与打包
确保你已安装 [Rust](https://rustup.rs/) 环境以及 [Node.js](https://nodejs.org/) (推荐 20.x 及以上版本)。

#### 安装依赖
```bash
npm install
npm install --prefix src-ui
```

#### 本地运行
```bash
npm run tauri dev
```

#### 编译打包
```bash
# 编译打包图形界面桌面端 (Windows / Linux)
npm run tauri build

# 编译独立纯命令行版本
cargo build --release -p wuwa-mod-cli
```
对于 Linux 系统，打包桌面版前需确保安装了 Tauri 相关的系统依赖，如 `libwebkit2gtk-4.1-dev`, `build-essential`, `curl`, `wget`, `file`, `libssl-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev` 等。

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
