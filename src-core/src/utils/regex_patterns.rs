// src-core/src/utils/regex_patterns.rs

use regex::Regex;
use std::sync::LazyLock;

// ---------------- rollback.rs ----------------
pub static BAK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(.*)_(\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2}(?:\.\d{3})?)\.BAK$").unwrap());

// ---------------- collector.rs ----------------
pub static FILENAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)filename\s*=\s*([^\s]+?\.buf)").unwrap());

pub static STRIDE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)stride\s*=\s*(\d+)").unwrap());

pub static COMPONENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^\[TextureOverrideComponent(\d+)[^\]\n]*\]?[^\S\n]*\n((?:[^\[\r\n][^\n]*\n|\r?\n)*(?:[^\[\r\n][^\n]*)?)",
    )
    .unwrap()
});

pub static DRAWINDEXED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"drawindexed\s*=\s*(\d+),\s*(\d+),").unwrap());

pub static RE_BLEND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\[ResourceBlendBuffer[^\]\n]*\]?[^\S\n]*\n((?:[^\[\r\n][^\n]*\n|\r?\n)*(?:[^\[\r\n][^\n]*)?)")
        .unwrap()
});

pub static RE_TEXCOORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\[ResourceTexCoordBuffer[^\]\n]*\]?[^\S\n]*\n((?:[^\[\r\n][^\n]*\n|\r?\n)*(?:[^\[\r\n][^\n]*)?)")
        .unwrap()
});

pub static RE_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\[ResourceIndexBuffer[^\]\n]*\]?[^\S\n]*\n((?:[^\[\r\n][^\n]*\n|\r?\n)*(?:[^\[\r\n][^\n]*)?)")
        .unwrap()
});

pub static RE_BREMAP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\[ResourceBlendRemapForwardBuffer[^\]\n]*\]?[^\S\n]*\n((?:[^\[\r\n][^\n]*\n|\r?\n)*(?:[^\[\r\n][^\n]*)?)").unwrap()
});

pub static RE_COLOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\[ResourceColorBuffer[^\]\n]*\]?[^\S\n]*\n((?:[^\[\r\n][^\n]*\n|\r?\n)*(?:[^\[\r\n][^\n]*)?)")
        .unwrap()
});

pub static RE_SHAPEKEY_OFFSET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)^\[ResourceShapeKeyOffsetBuffer[^\]\n]*\]?[^\S\n]*\n((?:[^\[\r\n][^\n]*\n|\r?\n)*(?:[^\[\r\n][^\n]*)?)",
    )
    .unwrap()
});

pub static RE_SHAPEKEY_VERTEX_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\[ResourceShapeKeyVertexIdBuffer[^\]\n]*\]?[^\S\n]*\n((?:[^\[\r\n][^\n]*\n|\r?\n)*(?:[^\[\r\n][^\n]*)?)").unwrap()
});

pub static RE_SHAPEKEY_VERTEX_OFFSET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\[ResourceShapeKeyVertexOffsetBuffer[^\]\n]*\]?[^\S\n]*\n((?:[^\[\r\n][^\n]*\n|\r?\n)*(?:[^\[\r\n][^\n]*)?)").unwrap()
});

// ---------------- mod_fixer.rs (RabbitFX) ----------------
pub static RE_RABBITFX_DIFFUSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Resource\\RabbitFX\\Diffuse\s*=").unwrap());

pub static RE_RABBITFX_NORMALMAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Resource\\RabbitFX\\Normalmap\s*=").unwrap());

pub static RE_RABBITFX_LIGHTMAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Resource\\RabbitFX\\Lightmap\s*=").unwrap());

pub static RE_RABBITFX_MATERIALMAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Resource\\RabbitFX\\Materialmap\s*=").unwrap());

pub static RE_RABBITFX_CUTOUTMAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Resource\\RabbitFX\\Cutoutmap\s*=").unwrap());

pub static RE_RABBITFX_SPECIALMAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Resource\\RabbitFX\\Specialmap\s*=").unwrap());

// ---------------- mod_fixer.rs (Various) ----------------
pub static RE_CHECKSUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(checksum\s*=\s*)\d+").unwrap());

pub static RE_HASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"hash\s*=\s*([0-9a-fA-F]{8,16})\b").unwrap());

pub static RE_STRIDE_8: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"stride\s*=\s*8").unwrap());

pub static RE_T17: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?im)^(\s*)ps-t17\s*=\s*(?:ref\s+)?(Resource\S*)"#).unwrap());

pub static RE_T18: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?im)^(\s*)ps-t18\s*=\s*(?:ref\s+)?(Resource\S*)"#).unwrap());

pub static RE_RUN_CMD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*run\s*=\s*Commandlist\\RabbitFX\\SetTextures").unwrap());

pub static RE_HANDLING_SKIP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^\s*handling\s*=\s*skip").unwrap());

// ---------------- mod_fixer.rs (ShapeKey) ----------------
pub static RE_ARRAY_VAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^(\s*array\s*=\s*)\d+").unwrap());

// ---------------- mod_fixer.rs (Hair Split) ----------------
pub static RE_MATCH_FIRST_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*match_first_index\s*=\s*(\d+)").unwrap());

pub static RE_MATCH_COUNT_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*match_index_count\s*=\s*(\d+)").unwrap());

pub static RE_VG_OFFSET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^\s*.*vg_offset\s*=\s*\d+").unwrap());

pub static RE_VG_COUNT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^\s*.*vg_count\s*=\s*\d+").unwrap());

pub static RE_RESOURCE_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bResourceTexture[a-zA-Z0-9_]+").unwrap());

pub static RE_RABBIT_FX_REF_DIFFUSE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*Resource\\RabbitFX\\Diffuse\s*=\s*(?:ref\s+)?(\w+)").unwrap());

pub static RE_COMP_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\[TextureOverrideComponent(\d+)\]").unwrap());
