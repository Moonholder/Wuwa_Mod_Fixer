use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

use crate::collector;

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct VertexRemapConfig {
    pub trigger_hash: Vec<String>,
    #[serde(deserialize_with = "crate::config_loader::deserialize_option_map_or_string")]
    pub vertex_groups: Option<HashMap<u16, u16>>,
    pub component_remap: Option<Vec<ComponentRemapRegion>>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct ComponentRemapRegion {
    pub component_index: u8,
    #[serde(default, deserialize_with = "crate::config_loader::deserialize_map_or_string")]
    pub indices: HashMap<u16, u16>,
}

pub fn remap_vertex_groups(
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

impl VertexRemapConfig {
    pub fn effective_vertex_groups<'a>(&'a self, content: &str) -> Option<Cow<'a, HashMap<u16, u16>>> {
        if let Some(regions) = &self.component_remap {
            let vg_offsets = collector::parse_vg_offsets(content);
            let mut derived = HashMap::new();
            for region in regions {
                let ci = region.component_index;
                if let Some(&vg_offset) = vg_offsets.get(&ci) {
                    for (&old_local, &new_local) in &region.indices {
                        derived.insert(old_local + vg_offset, new_local + vg_offset);
                    }
                }
            }
            if !derived.is_empty() {
                log::debug!("derived global vg_map from component_remap: {:?}", derived);
                return Some(Cow::Owned(derived));
            }
        }

        if let Some(vg) = &self.vertex_groups {
            return Some(Cow::Borrowed(vg));
        }

        None
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

    pub fn build_composite_remap<'a>(
        remaps: impl Iterator<Item = &'a VertexRemapConfig>,
        content: &str,
    ) -> VertexRemapConfig {
        let mut composite_vg_map: HashMap<u16, u16> = HashMap::new();
        let mut composite_comp_map: HashMap<u8, HashMap<u16, u16>> = HashMap::new();

        for config in remaps {
            if let Some(step_vg) = config.effective_vertex_groups(content) {
                for (_, current_target) in composite_vg_map.iter_mut() {
                    if let Some(&new_target) = step_vg.get(current_target) {
                        *current_target = new_target;
                    }
                }
                for (&src, &tgt) in step_vg.as_ref() {
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
        }
    }
}
