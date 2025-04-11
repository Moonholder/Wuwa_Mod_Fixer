use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const INDEX_SIZE: usize = 4;
pub const BLEND_STRIDE: usize = 8;
pub const TEXCOORD_STRIDE: usize = 16;

pub enum BufferType {
    Blend,
    TexCoord,
    Index,
}

impl std::fmt::Display for BufferType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BufferType::Blend => write!(f, "Blend"),
            BufferType::TexCoord => write!(f, "TexCoord"),
            BufferType::Index => write!(f, "Index"),
        }
    }
}

pub fn parse_resouce_buffer_path(
    content: &str,
    buf_type: BufferType,
    ini_path: &Path,
) -> Vec<PathBuf> {
    let buffer_re_str = &format!(
        r"(?i)\[Resource{}Buffer(?:_\d+)?\][\s\S]*?filename\s*=\s*([^\s]+?\.buf)",
        buf_type
    );

    let buffer_re = Regex::new(buffer_re_str).unwrap();

    return buffer_re
        .find_iter(content)
        .filter_map(|m| {
            buffer_re
                .captures(m.as_str())
                .and_then(|c| c.get(1).map(|g| g.as_str()))
                .map(|buf_file| {
                    ini_path
                        .parent()
                        .map_or_else(|| PathBuf::from(buf_file), |parent| parent.join(buf_file))
                })
        })
        .collect();
}

pub fn parse_component_indices(content: &str) -> Result<HashMap<u8, (usize, usize)>, String> {
    // 1. 匹配 [TextureOverrideComponentX] 节
    let component_re = Regex::new(r"(?m)^\[TextureOverrideComponent(\d+)\]([^\[]*)")
        .map_err(|e| format!("Regex error: {}", e))?;

    // 2. 提取 drawindexed 的 indexCount 和 indexOffset
    let drawindexed_re = Regex::new(r"drawindexed\s*=\s*(\d+),\s*(\d+),")
        .map_err(|e| format!("Regex error: {}", e))?;

    let mut component_indices = HashMap::new();

    // 3. 遍历所有匹配的组件块
    for cap in component_re.captures_iter(content) {
        let component_index: u8 = cap[1]
            .parse()
            .map_err(|_| format!("invalid component id: {}", &cap[1]))?;

        let block_content = &cap[2];
        let mut index_offset = usize::MAX;
        let mut max_end_offset = 0;

        // 4. 提取每个 drawindexed 的 indexCount 和 indexOffset
        for draw_cap in drawindexed_re.captures_iter(block_content) {
            let count: usize = draw_cap[1]
                .parse()
                .map_err(|_| format!("invalid index count in component {}", component_index))?;
            let offset: usize = draw_cap[2]
                .parse()
                .map_err(|_| format!("invalid index offset in component {}", component_index))?;
            index_offset = index_offset.min(offset);
            max_end_offset = max_end_offset.max(offset + count);
        }

        let mut index_count = 0;

        if index_offset != usize::MAX {
            index_count = max_end_offset - index_offset;
        }

        if index_count > 0 {
            component_indices.insert(component_index, (index_count, index_offset));
        }
    }

    if component_indices.is_empty() {
        Err("No component found in content".into())
    } else {
        Ok(component_indices)
    }
}

pub fn parse_component_indices_with_multiple(
    content: &str,
    draw_block_index: &str,
) -> Result<HashMap<u8, (usize, usize)>, String> {
    // 1. 匹配 [TextureOverrideComponentX] 节
    let component_re = Regex::new(r"(?m)^\[TextureOverrideComponent(\d+)\]([^\[]*)")
        .map_err(|e| format!("Regex error: {}", e))?;

    // 2. 提取 drawindexed 的 indexCount 和 indexOffset
    let drawindexed_re = Regex::new(r"drawindexed\s*=\s*(\d+),\s*(\d+),")
        .map_err(|e| format!("Regex error: {}", e))?;

    let mut component_indices = HashMap::new();

    // 3. 遍历所有匹配的组件块
    for cap in component_re.captures_iter(content) {
        let component_index: u8 = cap[1]
            .parse()
            .map_err(|_| format!("invalid component id: {}", &cap[1]))?;

        let block_content = &cap[2];
        let mut index_count = 0;
        let mut index_offset = usize::MAX;

        // 根据 draw_block_index 分割获取对应的 drawindexed
        let pattern = format!(
            r"if \$swapvar == {}\s*([\s\S]*?)(?:else if \$swapvar|endif)",
            draw_block_index
        );
        let re = Regex::new(&pattern).map_err(|e| format!("Regex error: {}", e))?;

        if let Some(swapvar_cap) = re.captures(block_content) {
            let target_section = swapvar_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let mut max_end_offset = 0;
            // 4. 提取每个 drawindexed 的 indexCount 和 indexOffset
            for draw_cap in drawindexed_re.captures_iter(target_section) {
                let count: usize = draw_cap[1]
                    .parse()
                    .map_err(|_| format!("invalid index count in component {}", component_index))?;
                let offset: usize = draw_cap[2].parse().map_err(|_| {
                    format!("invalid index offset in component {}", component_index)
                })?;
                index_offset = index_offset.min(offset);
                max_end_offset = max_end_offset.max(offset + count);
            }
            if index_offset != usize::MAX {
                index_count = max_end_offset - index_offset;
            }
        }

        if index_count > 0 {
            component_indices.insert(component_index, (index_count, index_offset));
        }
    }

    if component_indices.is_empty() {
        Err("No component found in content".into())
    } else {
        Ok(component_indices)
    }
}

pub fn get_byte_range_in_buffer(
    index_count: usize,
    index_offset: usize,
    index_buffer: &[u8],
    stride: usize,
) -> Result<(usize, usize), String> {
    let start_index = index_offset;
    let end_index = index_offset + index_count;

    if end_index > index_buffer.len() / INDEX_SIZE {
        return Err("index out of range".to_string());
    }

    let mut vertex_indices = Vec::with_capacity(index_count);
    for i in start_index..end_index {
        let start = i * INDEX_SIZE;
        let end = start + INDEX_SIZE;
        let index = u32::from_le_bytes(index_buffer[start..end].try_into().unwrap()) as usize;
        vertex_indices.push(index);
    }

    let min_vertex_index = vertex_indices
        .iter()
        .min()
        .ok_or("not found min vertex index")?;
    let max_vertex_index = vertex_indices
        .iter()
        .max()
        .ok_or("not found max vertex index")?;
    let start_byte = *min_vertex_index * stride;
    let end_byte = (*max_vertex_index + 1) * stride;

    Ok((start_byte, end_byte))
}

pub fn get_buf_path_index(path: &Path) -> Option<&str> {
    path.file_stem()
        .unwrap()
        .to_str()
        .filter(|s| s.contains("_"))
        .map(|s| s.split("_").last().unwrap())
}

pub fn combile_buf_path(path: &Path, buf_type: &BufferType) -> PathBuf {
    get_buf_path_index(path).map_or_else(
        || path.with_file_name(format!("{}.buf", buf_type)),
        |index| path.with_file_name(format!("{}_{}.buf", buf_type, index)),
    )
}
