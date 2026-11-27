// src-core/src/slot_fix/mod.rs
//
// Strictly idempotent, statement-level resource slot shift engine.
//
// Design invariants
//   1. Never inspect `.dds` bytes or texture file names. Scope is derived from
//      the component `vb0` hash anchors only.
//   2. Never clone / rename / pollute a `[Resource*]` right-hand side. Only the
//      slot identifier on the left-hand side of a statement is rewritten, so a
//      many-to-one resource binding stays untouched.
//   3. Provenance is recorded as a STANDALONE COMMENT LINE, never trailing:
//
//          ; @wmf(rule=<rule_id>,rev=<rev>,orig=<initial_slot>,sig=<crc32_hex>)
//          ps-t7 = ResourceFx
//
//      3DMigoto (`IniHandler.cpp`) does NOT support inline/trailing comments:
//      everything right of `=` up to the newline is consumed verbatim as the
//      resource / value name, so `ps-t7 = ResourceFx ; @wmf(...)` would make the
//      engine look for a resource literally named `ResourceFx ; @wmf(...)` and
//      paint the screen red with "resource not found" warnings.
//      The anchor therefore lives on the line immediately ABOVE the statement
//      (`line[i - 1]`, whose first non-blank char is `;`) and copies the exact
//      indentation of the statement it describes.
//
//      `orig` always records the slot the statement had BEFORE this tool first
//      touched it. Re-runs are pure lookups M_rev(orig), therefore
//        F_rev2(F_rev1(x)) == F_rev2(x)
//      and upgrading a rule never requires a manual rollback first.
//   4. Ambiguity is isolated with the set-theoretic partitions produced at
//      compile time (Dom\Cod, Cod\Dom, Dom∩Cod). No heuristics, no guessing.
//   5. Phase 1 and phase 2 share one session timestamp so a single `--rollback`
//      reverts both atomically.
//
// Deliberately NOT handled
//   `checktextureoverride = ps-tN` and `[CommandListTriggerResourceOverrides]`
//   are texture-override trigger bookkeeping, not resource bindings: they name
//   a slot whose contents should be re-evaluated, they do not bind a resource.
//   They are maintained by `ResourceOverrideFixer`, so rewriting them here would
//   be redundant at best and destructive at worst. Both are excluded from scope
//   detection, from the affected-slot set and from rewriting, and a shared
//   command list is only cloned (shared sub-section protection) when it really
//   contains statements this engine would rewrite.

pub mod anchor;
pub mod engine;
pub mod lineage;
pub mod manifest;
pub mod pipeline;
pub mod resolve;
pub mod scope;
pub mod session;
pub mod statement;

pub use anchor::*;
pub use engine::*;
pub use lineage::*;
pub use manifest::*;
pub use pipeline::*;
pub use resolve::*;
pub use scope::*;
pub use session::*;
pub use statement::*;
