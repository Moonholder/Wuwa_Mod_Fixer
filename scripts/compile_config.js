const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

// Compile the single master config.yml into a minified, production-ready config.json
const rawYml = fs.readFileSync(path.join(__dirname, '../config.yml'), 'utf8');

// 💡 Using FAILSAFE_SCHEMA to treat all scalars as raw strings!
// This solves the painful YAML auto-coercion issues where hex hashes resembling scientific notation 
// (e.g. 69e74056 -> Infinity), pure number strings (e.g. 129168 -> number), and single letters 
// (e.g. N -> false in YAML 1.1) would get completely ruined and crash the Rust type deserializer.
// The developer now does NOT need to remember to write single quotes around them in config.yml at all!
const data = yaml.load(rawYml, { schema: yaml.FAILSAFE_SCHEMA });

// Post-process settings: convert enable_aero_rover_fix back to a true Boolean
if (data && data.settings && data.settings.enable_aero_rover_fix !== undefined) {
    data.settings.enable_aero_rover_fix = (data.settings.enable_aero_rover_fix === 'true');
}

// Post-process characters to heal the data structure: convert fields that MUST be numbers back to Number type
if (data && data.characters) {
    for (const charName in data.characters) {
        if (!Object.prototype.hasOwnProperty.call(data.characters, charName)) continue;
        const charConfig = data.characters[charName];
        if (!charConfig) continue;

        // 1. Convert meta.id back to Number
        if (charConfig.textures) {
            for (const texHash in charConfig.textures) {
                if (!Object.prototype.hasOwnProperty.call(charConfig.textures, texHash)) continue;
                const texNode = charConfig.textures[texHash];
                if (texNode.meta) {
                    if (texNode.meta.id !== undefined) {
                        if (Array.isArray(texNode.meta.id)) {
                            texNode.meta.id = texNode.meta.id.map(Number);
                        } else {
                            texNode.meta.id = Number(texNode.meta.id);
                        }
                    }
                    if (Array.isArray(texNode.meta.slot)) {
                        texNode.meta.slot = texNode.meta.slot.map(Number);
                    }
                }
            }
        }

        // 2. Convert component_index back to Number
        if (Array.isArray(charConfig.vg_remaps)) {
            for (const vgRemap of charConfig.vg_remaps) {
                if (vgRemap && Array.isArray(vgRemap.component_remap)) {
                    for (const region of vgRemap.component_remap) {
                        if (region && region.component_index !== undefined) {
                            region.component_index = Number(region.component_index);
                        }
                    }
                }
            }
        }
        
        // 3. Convert shapekey_fix fields back to Number
        if (charConfig.shapekey_fix) {
            const sk = charConfig.shapekey_fix;
            if (sk.old_vertex_count !== undefined) sk.old_vertex_count = Number(sk.old_vertex_count);
            if (sk.new_vertex_count !== undefined) sk.new_vertex_count = Number(sk.new_vertex_count);
            if (sk.offset_stride !== undefined) sk.offset_stride = Number(sk.offset_stride);
            if (sk.custom_values_array !== undefined) sk.custom_values_array = Number(sk.custom_values_array);
        }

        // 4. Convert skip_components array elements back to Number
        if (Array.isArray(charConfig.skip_components)) {
            charConfig.skip_components = charConfig.skip_components.map(Number);
        }

        // 5. Convert materialmap_adapt fields back to Number
        if (Array.isArray(charConfig.materialmap_adapt)) {
            for (const rule of charConfig.materialmap_adapt) {
                if (rule && rule.component_id !== undefined) {
                    rule.component_id = Number(rule.component_id);
                }
                if (rule && rule.clothing_value !== undefined) {
                    rule.clothing_value = Number(rule.clothing_value);
                }
                if (rule && rule.skin_value !== undefined) {
                    rule.skin_value = Number(rule.skin_value);
                }
            }
        }

        // 6. Convert hair_fix / rover_hair_fix fields back to Number
        const hf = charConfig.hair_fix || charConfig.rover_hair_fix;
        if (hf) {
            if (hf.vg_offset !== undefined) hf.vg_offset = Number(hf.vg_offset);
            if (hf.vg_count !== undefined) hf.vg_count = Number(hf.vg_count);
        }
    }
}

// ZERO indentation whitespace for the absolute minimum production footprint
const outPath = path.join(__dirname, '../config.json');

// ─────────────────────────────────────────────────────────────────────────────
// slot_fix compilation: multi-epoch migration chain deriving closures
// and valid_epochs consumed by src-core.
// ─────────────────────────────────────────────────────────────────────────────
const SLOT_RE = /^(ps|vs|cs)-t([0-9]|[1-9][0-9]|1[0-2][0-7])$/;

function normalizeSlot(raw, ctxLabel) {
    const slot = String(raw === undefined || raw === null ? '' : raw).trim().toLowerCase();
    if (!SLOT_RE.test(slot)) {
        throw new Error(
            `[slot_fix] ${ctxLabel}: invalid resource slot '${raw}'. ` +
            `Expected lowercase 'ps-t<0..127>', 'vs-t<0..127>' or 'cs-t<0..127>'.`
        );
    }
    return slot;
}

function compileSlotFix(charName, charConfig) {
    const raw = charConfig.slot_fix;
    if (raw === undefined || raw === null) return null;
    if (typeof raw !== 'object') {
        throw new Error(`[slot_fix] ${charName}: 'slot_fix' must be a mapping.`);
    }

    const ruleId = String(raw.rule_id || `${charName.toLowerCase()}_slot_fix`).trim();
    if (!ruleId) throw new Error(`[slot_fix] ${charName}: 'rule_id' must not be empty.`);

    const stepsRaw = raw.steps;
    if (!Array.isArray(stepsRaw) || stepsRaw.length === 0) {
        throw new Error(`[slot_fix] ${charName}: 'steps' must be a non-empty array.`);
    }

    const totalSteps = stepsRaw.length;
    const normalizedSteps = [];

    for (let i = 0; i < totalSteps; i++) {
        const step = stepsRaw[i];
        if (!step || typeof step !== 'object') {
            throw new Error(`[slot_fix] ${charName}: step ${i} must be a mapping.`);
        }

        const stepRev = Number(String(step.rev === undefined ? '' : step.rev).trim());
        const expectedRev = i + 1;
        if (!Number.isInteger(stepRev) || stepRev !== expectedRev) {
            throw new Error(
                `[slot_fix] ${charName}: step ${i} 'rev' must be sequentially incrementing starting from 1 ` +
                `(expected ${expectedRev}, got '${step.rev}').`
            );
        }

        const rawMap = step.slot_map;
        if (!rawMap || typeof rawMap !== 'object' || Array.isArray(rawMap)) {
            throw new Error(`[slot_fix] ${charName}: step ${stepRev} 'slot_map' must be a non-empty mapping.`);
        }

        const slotMap = {};
        const seenSource = new Set();
        const seenTarget = new Map();

        for (const key of Object.keys(rawMap)) {
            const source = normalizeSlot(key, `${charName}.steps[${i}].slot_map key`);
            const target = normalizeSlot(rawMap[key], `${charName}.steps[${i}].slot_map['${key}']`);

            if (source === target) {
                throw new Error(
                    `[slot_fix] ${charName}: step ${stepRev} identity mapping '${source} -> ${target}' is not allowed.`
                );
            }
            if (seenSource.has(source)) {
                throw new Error(
                    `[slot_fix] ${charName}: step ${stepRev} duplicate source slot '${source}' in slot_map.`
                );
            }
            if (seenTarget.has(target)) {
                throw new Error(
                    `[slot_fix] ${charName}: step ${stepRev} slot_map is not injective — ` +
                    `'${seenTarget.get(target)}' and '${source}' both map to '${target}'.`
                );
            }

            seenSource.add(source);
            seenTarget.set(target, source);
            slotMap[source] = target;
        }

        if (Object.keys(slotMap).length === 0) {
            throw new Error(`[slot_fix] ${charName}: step ${stepRev} 'slot_map' must not be empty.`);
        }

        normalizedSteps.push({ rev: stepRev, slot_map: slotMap });
    }

    // Lineage tracing from epoch 0 to epoch K
    const lineages = [];
    for (let i = 0; i < totalSteps; i++) {
        const step = normalizedSteps[i];
        const map = step.slot_map;
        const currentEpoch = i + 1;
        const prevEpoch = i;

        const updatedLineages = new Set();
        for (const src of Object.keys(map)) {
            const dst = map[src];
            const existing = lineages.find((l) => l[prevEpoch] === src);
            if (existing) {
                existing.push(dst);
                updatedLineages.add(existing);
            } else {
                const newLineage = [];
                for (let e = 0; e <= prevEpoch; e++) {
                    newLineage.push(src);
                }
                newLineage.push(dst);
                lineages.push(newLineage);
                updatedLineages.add(newLineage);
            }
        }

        for (const l of lineages) {
            if (!updatedLineages.has(l)) {
                l.push(l[prevEpoch]);
            }
        }
    }

    // Validate injectivity across all epochs
    for (let e = 0; e <= totalSteps; e++) {
        const slotsAtE = lineages.map((l) => l[e]);
        const setAtE = new Set(slotsAtE);
        if (setAtE.size !== slotsAtE.length) {
            throw new Error(
                `[slot_fix] ${charName}: slot collision detected at epoch ${e}. Lineages collapsed onto same slot.`
            );
        }
    }

    // Compute closures for each epoch e in [0..K]: L(e) -> L(K) where L(e) != L(K)
    const closures = {};
    for (let e = 0; e <= totalSteps; e++) {
        closures[String(e)] = {};
        for (const l of lineages) {
            const slotAtE = l[e];
            const slotAtK = l[totalSteps];
            if (slotAtE !== slotAtK) {
                closures[String(e)][slotAtE] = slotAtK;
            }
        }
    }

    // Compute valid_epochs: inverted index of active slots L(e) -> [e1, e2, ...]
    const validEpochs = {};
    for (let e = 0; e <= totalSteps; e++) {
        for (const l of lineages) {
            const slot = l[e];
            if (!validEpochs[slot]) {
                validEpochs[slot] = [];
            }
            if (!validEpochs[slot].includes(e)) {
                validEpochs[slot].push(e);
            }
        }
    }
    for (const slot of Object.keys(validEpochs)) {
        validEpochs[slot].sort((a, b) => a - b);
    }

    // Anchors: explicit list wins, otherwise inherit main_hashes
    let anchors;
    if (raw.anchors !== undefined && raw.anchors !== null && String(raw.anchors).trim() !== '') {
        anchors = String(raw.anchors)
            .split(',')
            .map((s) => s.trim().toLowerCase())
            .filter((s) => s.length > 0);
    } else {
        anchors = [];
        const mainHashes = Array.isArray(charConfig.main_hashes) ? charConfig.main_hashes : [];
        for (const hr of mainHashes) {
            const olds = Array.isArray(hr.old) ? hr.old : (hr.old === undefined ? [] : [hr.old]);
            for (const h of olds) {
                const norm = String(h).trim().toLowerCase();
                if (norm && !anchors.includes(norm)) anchors.push(norm);
            }
            const nw = String(hr.new === undefined ? '' : hr.new).trim().toLowerCase();
            if (nw && !anchors.includes(nw)) anchors.push(nw);
        }
    }
    if (anchors.length === 0) {
        throw new Error(`[slot_fix] ${charName}: no anchors — set slot_fix.anchors or main_hashes.`);
    }

    const matchFirstIndex = [];
    if (raw.match_first_index !== undefined && raw.match_first_index !== null) {
        const rawMfi = String(raw.match_first_index)
            .split(',')
            .map((s) => s.trim())
            .filter((s) => s.length > 0);
        for (const v of rawMfi) matchFirstIndex.push(v);
    }

    return {
        rule_id: ruleId,
        character: charName,
        latest_rev: totalSteps,
        hashes: anchors,
        match_first_index: matchFirstIndex,
        closures: closures,
        valid_epochs: validEpochs,
    };
}

if (data && data.characters) {
    for (const charName in data.characters) {
        if (!Object.prototype.hasOwnProperty.call(data.characters, charName)) continue;
        const charConfig = data.characters[charName];
        if (!charConfig || typeof charConfig !== 'object') continue;
        const compiled = compileSlotFix(charName, charConfig);
        if (compiled) {
            charConfig.slot_fix = compiled;
        }
    }
}

fs.writeFileSync(outPath, JSON.stringify(data), 'utf8');
console.log('Successfully compiled config.yml into a minified, unified config.json!');


