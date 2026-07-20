use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::collector;

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct VertexRemapConfig {
    pub trigger_hash: Vec<String>,
    #[serde(deserialize_with = "crate::config_loader::deserialize_option_map_or_string")]
    pub vertex_groups: Option<HashMap<u16, u16>>,
    pub component_remap: Option<Vec<ComponentRemapRegion>>,
    pub merged_components: Option<Vec<MergedComponentConfig>>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct ComponentRemapRegion {
    pub component_index: u8,
    #[serde(default, deserialize_with = "crate::config_loader::deserialize_map_or_string")]
    pub indices: HashMap<u16, u16>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct MergedComponentConfig {
    pub component_index: u8,
    pub match_first_index: String,
    pub match_index_count: String,
    pub vg_offset: u16,
    pub vg_count: u16,
}

pub trait RemapProvider {
    fn vertex_groups(&self) -> Option<&HashMap<u16, u16>>;
    fn component_remap(&self) -> Option<&Vec<ComponentRemapRegion>>;

    fn build_dynamic_vertex_groups<'a>(&'a self, content: &str) -> std::borrow::Cow<'a, HashMap<u16, u16>> {
        let mut composite_vg_map = HashMap::new();
        if let Some(regions) = self.component_remap() {
            let vg_offsets = collector::parse_vg_offsets(content);
            for region in regions {
                let ci = region.component_index;
                if let Some(&vg_offset) = vg_offsets.get(&ci) {
                    for (&old_local, &new_local) in &region.indices {
                        let old_global = old_local + vg_offset;
                        let new_global = new_local + vg_offset;
                        composite_vg_map.insert(old_global, new_global);
                    }
                }
            }
        }

        if composite_vg_map.is_empty() {
            if let Some(vg) = self.vertex_groups() {
                std::borrow::Cow::Borrowed(vg)
            } else {
                std::borrow::Cow::Owned(composite_vg_map)
            }
        } else {
            log::debug!("composite_vg_map: {:?}", composite_vg_map);
            std::borrow::Cow::Owned(composite_vg_map)
        }
    }

    fn apply_remap_merged(&self, blend_data: &mut [u8], content: &str, stride: usize) -> Result<bool, String> {
        if stride % 2 != 0 || stride < 8 {
            return Err(format!("Invalid stride {stride} - must be even and >=8"));
        }

        let vg = self.build_dynamic_vertex_groups(content);
        if !vg.is_empty() {
            log::info!("Applying merged remap with vertex groups");
            let changed = self.remapping_vertex_groups(blend_data, &vg, 0, blend_data.len(), stride);
            return Ok(changed);
        }
        Ok(false)
    }

    fn apply_remap_component(
        &self,
        blend_data: &mut [u8],
        blend_path: &PathBuf,
        content: &str,
        multiple: bool,
        stride: usize,
    ) -> Result<bool, String> {
        if stride % 2 != 0 || stride < 8 {
            return Err(format!("Invalid stride {stride} - must be even and >=8"));
        }
        if let Some(regions) = self.component_remap() {
            let mut applied = false;
            let index_path = collector::combile_buf_path(blend_path, &collector::BufferType::Index);
            let buf_index_opt = collector::get_buf_path_index(blend_path);
            let mut component_indices = if multiple || buf_index_opt.is_some() {
                collector::parse_component_indices_with_multiple(content, buf_index_opt.unwrap_or("0"))
            } else {
                collector::parse_component_indices(content)
            };
            if component_indices.is_empty() {
                component_indices = collector::parse_component_indices(content);
            }
            let index_data = std::fs::read(&index_path).map_err(|e| format!("Index read error: {}", e))?;

            for region in regions {
                let ci = region.component_index;
                if let Some(&(idx_count, idx_offset)) = component_indices.get(&ci) {
                    let (start, end) = collector::get_byte_range_in_buffer(idx_count, idx_offset, &index_data, stride)
                        .map_err(|e| format!("Failed to get byte range in buffer: {}", e))?;

                    if start < end && end <= blend_data.len() {
                        let changed = self.remapping_vertex_groups(blend_data, &region.indices, start, end, stride);
                        if changed {
                            applied = true;
                        }
                    }
                } else {
                    log::warn!("Component {} not found in parsed indices", ci);
                }
            }
            log::info!("Applied component remap");
            return Ok(applied);
        }
        Ok(false)
    }

    fn remapping_vertex_groups(
        &self,
        blend_data: &mut [u8],
        remap_indices: &HashMap<u16, u16>,
        start: usize,
        end: usize,
        stride: usize,
    ) -> bool {
        let mut changed = false;
        let indices_len = stride / 2;
        for chunk in blend_data[start..end].chunks_exact_mut(stride) {
            let indices = &mut chunk[0..indices_len];
            indices.iter_mut().for_each(|idx| {
                let old_val = *idx;
                let new_val = *remap_indices.get(&(*idx as u16)).unwrap_or(&(*idx as u16)) as u8;
                if old_val != new_val {
                    *idx = new_val;
                    changed = true;
                }
            });
        }
        changed
    }
}

impl RemapProvider for VertexRemapConfig {
    fn vertex_groups(&self) -> Option<&HashMap<u16, u16>> {
        self.vertex_groups.as_ref()
    }
    fn component_remap(&self) -> Option<&Vec<ComponentRemapRegion>> {
        self.component_remap.as_ref()
    }
}

impl VertexRemapConfig {
    pub fn remap_blend_remap_data(
        forward_data: &mut [u8],
        reverse_data: &mut [u8],
        vg_data: &mut [u8],
        vertex_groups: &HashMap<u16, u16>,
    ) {
        for i in 0..(vg_data.len() / 2) {
            let old_global = u16::from_le_bytes([vg_data[i * 2], vg_data[i * 2 + 1]]);
            let new_global = vertex_groups.get(&old_global).copied().unwrap_or(old_global);
            vg_data[i * 2..i * 2 + 2].copy_from_slice(&new_global.to_le_bytes());
        }
        const BLOCK_ENTRIES: usize = 512;
        let num_blocks = forward_data.len() / (BLOCK_ENTRIES * 2);
        for b in 0..num_blocks {
            let off = b * BLOCK_ENTRIES * 2;
            let mut new_reverse = vec![0u16; BLOCK_ENTRIES];
            for i in 0..BLOCK_ENTRIES {
                let old_global = u16::from_le_bytes([forward_data[off + i * 2], forward_data[off + i * 2 + 1]]);
                let new_global = vertex_groups.get(&old_global).copied().unwrap_or(old_global);
                forward_data[off + i * 2..off + i * 2 + 2].copy_from_slice(&new_global.to_le_bytes());
                if (new_global as usize) < BLOCK_ENTRIES {
                    new_reverse[new_global as usize] = i as u16;
                }
            }
            for i in 0..BLOCK_ENTRIES {
                reverse_data[off + i * 2..off + i * 2 + 2].copy_from_slice(&new_reverse[i].to_le_bytes());
            }
        }
    }

    pub fn remap_blend_remap_forward(forward_data: &mut [u8], vertex_groups: &HashMap<u16, u16>) {
        const BLOCK_ENTRIES: usize = 512;
        let num_blocks = forward_data.len() / (BLOCK_ENTRIES * 2);
        for b in 0..num_blocks {
            let off = b * BLOCK_ENTRIES * 2;
            let mut new_forward = vec![0u16; BLOCK_ENTRIES];
            for i in 0..BLOCK_ENTRIES {
                let base_global = u16::from_le_bytes([forward_data[off + i * 2], forward_data[off + i * 2 + 1]]);
                new_forward[i] = vertex_groups.get(&base_global).copied().unwrap_or(base_global);
            }
            for (i, &val) in new_forward.iter().enumerate() {
                forward_data[off + i * 2..off + i * 2 + 2].copy_from_slice(&val.to_le_bytes());
            }
        }
    }

    pub fn build_composite_remap<'a>(remaps: impl Iterator<Item = &'a VertexRemapConfig>) -> VertexRemapConfig {
        let mut composite_vg_map: HashMap<u16, u16> = HashMap::new();
        let mut composite_comp_map: HashMap<u8, HashMap<u16, u16>> = HashMap::new();
        let mut composite_merged_components = Vec::new();

        for config in remaps {
            if let Some(vg_map) = &config.vertex_groups {
                for (_, current_target) in composite_vg_map.iter_mut() {
                    if let Some(&new_target) = vg_map.get(current_target) {
                        *current_target = new_target;
                    }
                }
                for (&src, &tgt) in vg_map {
                    composite_vg_map.entry(src).or_insert(tgt);
                }
            }
            if let Some(comp_remap) = &config.component_remap {
                for region in comp_remap {
                    let map = composite_comp_map.entry(region.component_index).or_default();
                    for (_, ct) in map.iter_mut() {
                        if let Some(&nt) = region.indices.get(ct) {
                            *ct = nt;
                        }
                    }
                    for (&src, &tgt) in &region.indices {
                        map.entry(src).or_insert(tgt);
                    }
                }
            }
            if let Some(merged_comps) = &config.merged_components {
                for comp in merged_comps {
                    if !composite_merged_components
                        .iter()
                        .any(|c: &MergedComponentConfig| c.component_index == comp.component_index)
                    {
                        composite_merged_components.push(comp.clone());
                    }
                }
            }
        }

        let comp_regions: Vec<ComponentRemapRegion> = composite_comp_map
            .into_iter()
            .map(|(ci, indices)| ComponentRemapRegion {
                component_index: ci,
                indices,
            })
            .collect();

        VertexRemapConfig {
            trigger_hash: vec![],
            vertex_groups: if composite_vg_map.is_empty() {
                None
            } else {
                Some(composite_vg_map)
            },
            component_remap: if comp_regions.is_empty() {
                None
            } else {
                Some(comp_regions)
            },
            merged_components: if composite_merged_components.is_empty() {
                None
            } else {
                Some(composite_merged_components)
            },
        }
    }
}
