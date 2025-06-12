use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const INDEX_SIZE: usize = 4;
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

lazy_static::lazy_static! {
    static ref FILENAME_RE: Regex = Regex::new(r"(?i)filename\s*=\s*([^\s]+?\.buf)").unwrap();
    static ref STRIDE_RE: Regex = Regex::new(r"(?i)stride\s*=\s*(\d+)").unwrap();
    static ref COMPONENT_RE: Regex = Regex::new(r"(?m)^\[TextureOverrideComponent(\d+)\]([^\[]*)").unwrap();
    static ref DRAWINDEXED_RE: Regex = Regex::new(r"drawindexed\s*=\s*(\d+),\s*(\d+),").unwrap();
}

pub fn parse_resouce_buffer_path(
    content: &str,
    buf_type: BufferType,
    ini_path: &Path,
) -> Vec<(PathBuf, usize)> {
    let section_re = match Regex::new(&format!(
        r"(?i)\[Resource{}Buffer(?:_\d+)?\][\s\S]*?([^\[]*)",
        buf_type
    )) {
        Ok(re) => re,
        Err(e) => {
            error!("Failed to compile regex: {}", e);
            return Vec::new();
        }
    };

    let mut results = Vec::new();

    for section_cap in section_re.captures_iter(content) {
        let section_content = match section_cap.get(0) {
            Some(m) => m.as_str(),
            None => {
                warn!("Invalid section format");
                continue;
            }
        };

        let filename = match FILENAME_RE
            .captures(section_content)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().trim())
        {
            Some(name) => name,
            None => {
                warn!("Missing filename in section");
                continue;
            }
        };

        let stride = match STRIDE_RE
            .captures(section_content)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().trim())
            .and_then(|s| s.parse::<usize>().ok())
        {
            Some(s) => s,
            None => {
                warn!("Failed to parse stride");
                continue;
            }
        };

        let path = ini_path
            .parent()
            .map_or_else(|| PathBuf::from(filename), |p| p.join(filename));

        results.push((path, stride));
    }

    results
}

fn extract_component_indices<'a>(
    content: &'a str,
    extractor: impl Fn(&'a str) -> Option<&'a str> + 'a,
) -> HashMap<u8, (usize, usize)> {
    let mut component_indices = HashMap::new();

    for cap in COMPONENT_RE.captures_iter(content) {
        // 解析组件ID
        let component_id = match cap.get(1) {
            Some(m) => m.as_str(),
            None => {
                warn!("Invalid component format: missing ID");
                continue;
            }
        };

        let component_index = match component_id.parse::<u8>() {
            Ok(id) => id,
            Err(_) => {
                warn!("Invalid component ID: {}", component_id);
                continue;
            }
        };

        let block_content = match cap.get(2) {
            Some(m) => m.as_str(),
            None => {
                warn!("Component {} has no content", component_index);
                continue;
            }
        };

        let target_section = match extractor(block_content) {
            Some(section) => section,
            None => continue,
        };

        // 提取所有drawindexed信息
        let mut min_offset = usize::MAX;
        let mut max_end_offset = 0;

        for draw_cap in DRAWINDEXED_RE.captures_iter(target_section) {
            // 解析indexCount
            let count_str = match draw_cap.get(1) {
                Some(m) => m.as_str(),
                None => {
                    warn!(
                        "Invalid drawindexed format in component {}: missing count",
                        component_index
                    );
                    continue;
                }
            };

            let count = match count_str.parse::<usize>() {
                Ok(c) => c,
                Err(_) => {
                    warn!(
                        "Invalid index count in component {}: {}",
                        component_index, count_str
                    );
                    continue;
                }
            };

            // 解析indexOffset
            let offset_str = match draw_cap.get(2) {
                Some(m) => m.as_str(),
                None => {
                    warn!(
                        "Invalid drawindexed format in component {}: missing offset",
                        component_index
                    );
                    continue;
                }
            };

            let offset = match offset_str.parse::<usize>() {
                Ok(o) => o,
                Err(_) => {
                    warn!(
                        "Invalid index offset in component {}: {}",
                        component_index, offset_str
                    );
                    continue;
                }
            };

            min_offset = min_offset.min(offset);
            max_end_offset = max_end_offset.max(offset + count);
        }

        // 计算最终的index_count和index_offset
        if min_offset != usize::MAX {
            let index_count = max_end_offset - min_offset;
            component_indices.insert(component_index, (index_count, min_offset));
        }
    }

    component_indices
}

pub fn parse_component_indices(content: &str) -> HashMap<u8, (usize, usize)> {
    extract_component_indices(content, |block| Some(block))
}

pub fn parse_component_indices_with_multiple(
    content: &str,
    draw_block_index: &str,
) -> HashMap<u8, (usize, usize)> {
    let pattern = format!(
        r"if \$swapvar == {}\s*([\s\S]*?)(?:else if \$swapvar|endif)",
        regex::escape(draw_block_index)
    );

    let swapvar_re = match Regex::new(&pattern) {
        Ok(re) => re,
        Err(e) => {
            error!("Failed to compile regex: {}", e);
            return HashMap::new();
        }
    };

    extract_component_indices(content, move |block| {
        swapvar_re
            .captures(block)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str())
    })
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
