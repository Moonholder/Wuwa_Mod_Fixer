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

前往 [发布页](https://github.com/Moonholder/Wuwa_Mod_Fixer/releases/latest) 下载可执行文件，双击打开，选择或拖入 Mod 文件夹，点击“开始修复”按钮即可。


### ✨ 主要功能
- **自动化修复**：自动识别资源哈希变动并进行替换。
- **回滚管理**：内置回滚管理器，可随时恢复到修改前的原始状态。
- **跨平台 GUI**：基于 Tauri V2 (Vue3 + Vite) 构建，支持 Windows、Linux。
- **双模式运行**：支持图形界面与传统的控制台模式。

### 🛠️ 开发与打包
确保你已安装 [Rust](https://rustup.rs/) 环境以及 [Node.js](https://nodejs.org/) (推荐 18.x 及以上版本)。

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
npm run tauri build
```
对于 Linux 系统，打包前需确保安装了 Tauri 相关的系统依赖，如 `libwebkit2gtk-4.1-dev`, `build-essential`, `curl`, `wget`, `file`, `libssl-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev` 等。

### 🚀 命令行参数
程序支持以下启动参数：

| 参数 | 说明 |
| :--- | :--- |
| `--cli` | **进入控制台模式**（交互式菜单）。 |
| `--path <DIR>` | **指定 Mod 文件夹路径**，启用非交互直接修复模式。需搭配 `--cli` 使用。 |
| `--config <FILE>` | **指定配置文件路径**，优先读取该 `config.json`，并跳过远程配置获取。 |
| `--derived-hashes` | 启用「补全贴图状态」（与 `--stable-texture` 互斥）。 |
| `--stable-texture` | 启用「应用稳定纹理」（与 `--derived-hashes` 互斥）。 |
| `--aemeath-mech` | 启用「修复爱弥斯机兵形态」。 |
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

# 一键修复 + 使用指定配置文件
./Mod_Fixer --cli --path "D:\Mods\MyMod" --config "D:\Configs\config.json"

# 一键修复 + 补全贴图状态 + 联网获取最新配置
./Mod_Fixer --cli --path "D:\Mods\MyMod" --derived-hashes --online

# 一键修复 + 应用稳定纹理 + 爱弥斯机兵修复
./Mod_Fixer --cli --path "D:\Mods\MyMod" --stable-texture --aemeath-mech

# 一键修复 + 风主眼部修复 (TexCoord 模式)
./Mod_Fixer --cli --path "D:\Mods\MyMod" --aero-fix 1

# 回滚最近一次修复
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
