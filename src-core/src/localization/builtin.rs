// src-core/src/localization/builtin.rs
// Built-in technical translations exclusively for core pipeline events and stages.
// UI buttons and CLI prompts are strictly isolated in their respective presentation layers.

use std::{collections::HashMap, sync::LazyLock};

static BUILTIN_TRANSLATIONS: LazyLock<HashMap<&'static str, HashMap<&'static str, &'static str>>> =
    LazyLock::new(|| {
        let mut m: HashMap<&'static str, HashMap<&'static str, &'static str>> = HashMap::new();

        macro_rules! insert_item {
            ($key:literal, $zh:literal, $en:literal) => {{
                let mut sub = HashMap::new();
                sub.insert("zh", $zh);
                sub.insert("en", $en);
                m.insert($key, sub);
            }};
            ($key:literal, $zh:literal, $en:literal, $zh_hant:literal, $ja:literal) => {{
                let mut sub = HashMap::new();
                sub.insert("zh", $zh);
                sub.insert("en", $en);
                sub.insert("zh-hant", $zh_hant);
                sub.insert("ja", $ja);
                m.insert($key, sub);
            }};
        }

        // Pipeline lifecycle & stage keys
        insert_item!(
            "pipeline.no_target_files",
            "未在当前目录下检测到任何符合规格的 Mod 资产，请检查路径是否正确",
            "No eligible Mod assets found in the current directory, please check if the path is correct",
            "未在當前目錄下檢測到任何符合規格的 Mod 資產，請檢查路徑是否正確",
            "現在のディレクトリに対象となるModアセットが見つかりません。パスを確認してください"
        );
        insert_item!(
            "pipeline.all_done",
            "所有文件处理完成...",
            "All files processed...",
            "所有檔案處理完成...",
            "すべてのファイル処理が完了しました..."
        );
        insert_item!(
            "pipeline.cancelled",
            "修复任务已被用户主动取消",
            "Fix task was cancelled by user",
            "修復任務已被使用者主動取消",
            "修復タスクはユーザーによってキャンセルされました"
        );
        insert_item!(
            "pipeline.error_prompt",
            "处理过程中发生未预期异常，建议前往 GitHub 提交 Issue 反馈。",
            "An unexpected error occurred during processing. Please report it on GitHub Issues.",
            "處理過程中發生未預期異常，建議前往 GitHub 提交 Issue 反饋。",
            "処理中に予期せぬエラーが発生しました。GitHub Issueにてご報告ください。"
        );
        insert_item!(
            "pipeline.stage_preprocess",
            "资产预检与索引准备",
            "Asset Pre-check & Indexing",
            "資產預檢與索引準備",
            "アセット事前検査とインデックス準備"
        );
        insert_item!(
            "pipeline.stage_parse",
            "解析 INI 配置语法树",
            "Parsing INI Configuration AST",
            "解析 INI 配置語法樹",
            "INI設定ASTの解析"
        );
        insert_item!(
            "pipeline.stage_remap",
            "应用网格与模型修复变换",
            "Applying Mesh & Model Fix Transformations",
            "應用網格與模型修復變換",
            "メッシュおよびモデル修復変換の適用"
        );
        insert_item!(
            "pipeline.stage_textures",
            "补全与生成贴图着色掩码",
            "Completing & Generating Texture Shading Masks",
            "補全與生成貼圖著色遮罩",
            "テクスチャシェーディングマスクの補完と生成"
        );
        insert_item!(
            "pipeline.stage_writeback",
            "安全写回修复文件",
            "Safely Writing Back Repaired Files",
            "安全寫回修復檔案",
            "修復されたファイルの安全な書き戻し"
        );
        insert_item!(
            "pipeline.character_matched",
            "匹配到目标角色特征",
            "Matched target character profile",
            "匹配到目標角色特徵",
            "対象キャラクターの特徴に一致しました"
        );
        insert_item!(
            "pipeline.file_skipped_no_match",
            "未匹配到任何已知角色特征，无需应用修复",
            "No known character features matched, skipped without modifications",
            "未匹配到任何已知角色特徵，無需應用修復",
            "既知のキャラクター特徴と一致しないため、スキップされました"
        );
        insert_item!(
            "pipeline.file_skipped_up_to_date",
            "文件已具备全部目标特征，无需重复修复",
            "File already up-to-date, skipped",
            "檔案已具備全部目標特徵，無需重複修復",
            "ファイルは既に最新状態のため、スキップされました"
        );
        insert_item!(
            "pipeline.process_file_error",
            "处理该文件时流水线异常",
            "Pipeline error occurred while processing this file",
            "處理該檔案時流水線異常",
            "このファイルの処理中にパイプラインエラーが発生しました"
        );
        insert_item!(
            "pipeline.file_parse_error",
            "INI 文件格式解析失败",
            "Failed to parse INI file syntax",
            "INI 檔案格式解析失敗",
            "INIファイルの構文解析に失敗しました"
        );
        insert_item!(
            "pipeline.rebuild_error",
            "重构修复段落时失败",
            "Failed to rebuild fixed section",
            "重構修復段落時失敗",
            "修復セクションの再構築に失敗しました"
        );

        m
    });

pub fn get_builtin_translation(key: &str, lang: &str) -> Option<&'static str> {
    let item = BUILTIN_TRANSLATIONS.get(key)?;
    let norm = lang.to_ascii_lowercase();
    let is_zh = norm.starts_with("zh");
    let lookup_lang = if norm.starts_with("zh-hant") || norm.starts_with("zh-tw") || norm.starts_with("zh-hk") {
        "zh-hant"
    } else if is_zh {
        "zh"
    } else if norm.starts_with("ja") {
        "ja"
    } else {
        "en"
    };

    item.get(lookup_lang)
        .or_else(|| if is_zh { item.get("zh") } else { None })
        .or_else(|| item.get("en"))
        .copied()
}
