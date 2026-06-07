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
                if (texNode && texNode.meta && texNode.meta.id !== undefined) {
                    texNode.meta.id = Number(texNode.meta.id);
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
    }
}

// ZERO indentation whitespace for the absolute minimum production footprint
const outPath = path.join(__dirname, '../config.json');
fs.writeFileSync(outPath, JSON.stringify(data), 'utf8');
console.log('Successfully compiled config.yml into a minified, unified config.json!');


