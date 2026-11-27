<script setup lang="ts">
// Confirmation drawer for ambiguous resource slot overlaps.
// Operates at the INI file level to mirror mod authoring reality: all components
// within a given configuration file share the same layout version context.
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { invoke } from '@tauri-apps/api/core'
import { useFixStore } from '../stores/fix'
import type { AmbiguousLinePreview, AmbiguousSlotItem, SlotDecision } from '../stores/fix'

const fix = useFixStore()
const { t } = useI18n()

interface IniFileEntry {
  relIniPath: string
  fileName: string
  absIniPath: string
  items: AmbiguousSlotItem[]
}

interface ModFolderEntry {
  folderName: string
  folderPath: string
  files: IniFileEntry[]
}

interface CodeTokenParts {
  prefix: string
  currentSlot: string
  suffix: string
}

function getDisplayFileName(relIniPath: string, folderName: string): string {
  const normRel = relIniPath.replace(/\\/g, '/')
  const normFolder = folderName.replace(/\\/g, '/')
  if (normRel.startsWith(normFolder + '/')) {
    return normRel.slice(normFolder.length + 1)
  }
  const parts = normRel.split('/')
  return parts[parts.length - 1] || normRel
}

function getModFolderPath(folderName: string, items: AmbiguousSlotItem[]): string {
  const first = items[0]
  if (!first || !first.abs_ini_path) return ''
  const abs = first.abs_ini_path
  const normAbs = abs.replace(/\\/g, '/')
  const normFolder = folderName.replace(/\\/g, '/')
  const idx = normAbs.lastIndexOf(normFolder)
  if (idx >= 0) {
    return abs.slice(0, idx + normFolder.length)
  }
  const lastSlash = Math.max(abs.lastIndexOf('/'), abs.lastIndexOf('\\'))
  return lastSlash > 0 ? abs.slice(0, lastSlash) : abs
}

async function openPath(path: string) {
  if (!path) return
  try {
    await invoke('open_path', { path })
  } catch (err) {
    console.warn('Failed to open path:', err)
  }
}

const modFolders = computed<ModFolderEntry[]>(() => {
  const modMap = new Map<string, Map<string, AmbiguousSlotItem[]>>()
  for (const item of fix.slotItems) {
    const folder = item.mod_folder_name || (item.rel_ini_path.split(/[/\\]/)[0] || item.rel_ini_path)
    let fileMap = modMap.get(folder)
    if (!fileMap) {
      fileMap = new Map<string, AmbiguousSlotItem[]>()
      modMap.set(folder, fileMap)
    }
    const fileKey = item.rel_ini_path
    const bucket = fileMap.get(fileKey)
    if (bucket) {
      bucket.push(item)
    } else {
      fileMap.set(fileKey, [item])
    }
  }

  return Array.from(modMap.entries()).map(([folderName, fileMap]) => {
    const allModItems: AmbiguousSlotItem[] = []
    const files = Array.from(fileMap.entries()).map(([relIniPath, items]) => {
      allModItems.push(...items)
      return {
        relIniPath,
        fileName: getDisplayFileName(relIniPath, folderName),
        absIniPath: items[0]?.abs_ini_path || '',
        items,
      }
    })

    return {
      folderName,
      folderPath: getModFolderPath(folderName, allModItems),
      files,
    }
  })
})

const allFiles = computed<IniFileEntry[]>(() => {
  const list: IniFileEntry[] = []
  for (const mod of modFolders.value) {
    list.push(...mod.files)
  }
  return list
})

function fileDecision(file: IniFileEntry): SlotDecision | undefined {
  if (file.items.length === 0) return undefined
  const first = fix.slotDecisions[file.items[0].item_id]
  if (!first) return undefined
  return file.items.every(i => fix.slotDecisions[i.item_id] === first) ? first : undefined
}

function chooseFile(file: IniFileEntry, decision: SlotDecision) {
  for (const item of file.items) {
    fix.setSlotDecision(item.item_id, decision)
  }
}

const decidedFileCount = computed(() => {
  return allFiles.value.filter(f => !!fileDecision(f)).length
})

const remainingFiles = computed(() => {
  return allFiles.value.length - decidedFileCount.value
})

function parseCodeParts(line: AmbiguousLinePreview): CodeTokenParts {
  const idx = line.raw_code.toLowerCase().indexOf(line.current_slot.toLowerCase())
  if (idx < 0) {
    return { prefix: '', currentSlot: line.current_slot, suffix: line.raw_code }
  }
  return {
    prefix: line.raw_code.slice(0, idx),
    currentSlot: line.raw_code.slice(idx, idx + line.current_slot.length),
    suffix: line.raw_code.slice(idx + line.current_slot.length),
  }
}
</script>

<template>
  <Transition name="fade">
    <div
      v-if="fix.slotDrawerOpen && fix.slotItems.length > 0"
      class="fixed inset-x-0 top-8 bottom-0 z-[85] bg-zinc-950/50 dark:bg-black/75 backdrop-blur-md flex items-center justify-center p-4 select-none"
    >
      <div
        class="w-full max-w-2xl max-h-[88vh] flex flex-col overflow-hidden rounded-2xl border border-zinc-200/90 dark:border-white/10 bg-white dark:bg-[#13161f] shadow-2xl shadow-zinc-950/40"
      >
        <!-- ── Header ───────────────────────────────────────────────────── -->
        <header class="px-5 py-4 shrink-0 border-b border-zinc-200/80 dark:border-white/5 bg-zinc-50/70 dark:bg-[#161a25]/60 flex items-start gap-3.5">
          <div
            class="w-9 h-9 rounded-xl bg-sky-500/10 border border-sky-500/20 dark:border-sky-500/25 flex items-center justify-center text-sky-600 dark:text-sky-400 shrink-0 mt-0.5 shadow-sm"
          >
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
            </svg>
          </div>

          <div class="flex-1 min-w-0">
            <h3 class="text-[15px] font-bold text-zinc-900 dark:text-white leading-5">
              {{ t('slot.title') }}
            </h3>
            <p class="mt-1 text-[11.5px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
              {{ t('slot.why_short') }}
            </p>
          </div>

          <button
            @click="fix.dismissSlotDrawer()"
            class="shrink-0 w-7 h-7 -mr-1 rounded-lg flex items-center justify-center text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-200/60 dark:hover:bg-white/5 transition-colors"
            :title="t('slot.close')"
          >
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </header>

        <!-- ── Quick actions toolbar ────────────────────────────────────── -->
        <div class="px-5 py-2.5 shrink-0 flex items-center justify-between border-b border-zinc-200/70 dark:border-white/5 bg-zinc-50/50 dark:bg-[#0f1118]">
          <div class="flex items-center gap-2">
            <button
              @click="fix.setAllSlotDecisions('keep')"
              class="px-2.5 py-1 rounded-md text-[11px] font-semibold text-zinc-700 dark:text-zinc-300 border border-zinc-300 dark:border-zinc-700/80 bg-zinc-100/90 dark:bg-zinc-800/80 hover:bg-zinc-200 dark:hover:bg-zinc-700/90 active:scale-[0.98] transition-all"
            >
              {{ t('slot.all_keep') }}
            </button>
            <button
              @click="fix.setAllSlotDecisions('update')"
              class="px-2.5 py-1 rounded-md text-[11px] font-semibold text-sky-700 dark:text-sky-300 border border-sky-300/80 dark:border-sky-500/35 bg-sky-50/90 dark:bg-sky-500/10 hover:bg-sky-100 dark:hover:bg-sky-500/20 active:scale-[0.98] transition-all"
            >
              {{ t('slot.all_update') }}
            </button>
          </div>
          <span class="text-[11.5px] font-mono text-zinc-500 dark:text-zinc-400 tabular-nums">
            {{ t('slot.decided_count', { decided: decidedFileCount, total: allFiles.length }) }}
          </span>
        </div>

        <!-- ── Main scrollable list ─────────────────────────────────────── -->
        <div class="flex-1 min-h-0 overflow-y-auto px-5 py-4 space-y-6">
          <div v-if="modFolders.length === 0" class="text-center text-[12px] text-zinc-500 py-10">
            {{ t('slot.empty') }}
          </div>

          <section v-for="mod in modFolders" :key="mod.folderName" class="space-y-3">
            <!-- Mod Folder Header (Level 1) with Quick Open -->
            <div class="flex items-center justify-between gap-2">
              <button
                type="button"
                @click="openPath(mod.folderPath)"
                class="group/mod inline-flex items-center gap-2 min-w-0 max-w-full text-xs text-zinc-800 dark:text-zinc-200 font-medium px-1.5 py-0.5 -ml-1.5 rounded-md hover:bg-zinc-200/60 dark:hover:bg-white/5 transition-colors text-left"
                :title="t('slot.open_folder_hint')"
              >
                <svg class="w-4 h-4 text-sky-600 dark:text-sky-500/80 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                </svg>
                <span class="truncate font-semibold tracking-wide group-hover/mod:text-sky-600 dark:group-hover/mod:text-sky-400 transition-colors">
                  {{ mod.folderName }}
                </span>
                <svg class="w-3.5 h-3.5 text-zinc-400 opacity-0 group-hover/mod:opacity-100 transition-opacity shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
              </button>
            </div>

            <!-- One card per INI file (Level 2) -->
            <div
              v-for="file in mod.files"
              :key="file.relIniPath"
              class="rounded-xl border bg-white dark:bg-[#171a24] p-4 space-y-3.5 transition-colors shadow-sm"
              :class="fileDecision(file)
                ? 'border-sky-500/50 dark:border-sky-500/30'
                : 'border-zinc-200/90 dark:border-zinc-800/90'"
            >
              <!-- File Header with Integrated Decision Switch & Quick Open -->
              <div class="flex items-center justify-between gap-3 pb-3 border-b border-zinc-100 dark:border-zinc-800/80">
                <button
                  type="button"
                  @click="openPath(file.absIniPath)"
                  class="group/file flex items-center gap-2 min-w-0 text-left px-1.5 py-0.5 -ml-1.5 rounded hover:bg-zinc-100 dark:hover:bg-white/5 transition-colors"
                  :title="t('slot.open_file_hint')"
                >
                  <svg class="w-4 h-4 text-zinc-400 group-hover/file:text-sky-500 transition-colors shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <span class="font-mono text-xs font-bold text-zinc-900 dark:text-white tracking-wide truncate group-hover/file:text-sky-600 dark:group-hover/file:text-sky-400 transition-colors">
                    {{ file.fileName }}
                  </span>
                  <svg class="w-3 h-3 text-zinc-400 opacity-0 group-hover/file:opacity-100 transition-opacity shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                </button>

                <!-- Native Segmented Switch (Keep vs Update) -->
                <div class="inline-flex rounded-lg bg-zinc-100 dark:bg-[#0e1017] p-0.5 border border-zinc-200 dark:border-zinc-800 text-xs shrink-0">
                  <button
                    @click="chooseFile(file, 'keep')"
                    class="px-3.5 py-1 rounded-md text-xs font-medium transition-all"
                    :class="fileDecision(file) === 'keep'
                      ? 'bg-white dark:bg-[#292f3f] text-zinc-900 dark:text-white shadow-sm font-semibold'
                      : 'text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white'"
                  >
                    {{ t('slot.keep') }}
                  </button>
                  <button
                    @click="chooseFile(file, 'update')"
                    class="px-3.5 py-1 rounded-md text-xs font-medium transition-all"
                    :class="fileDecision(file) === 'update'
                      ? 'bg-white dark:bg-[#292f3f] text-zinc-900 dark:text-white shadow-sm font-semibold'
                      : 'text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white'"
                  >
                    {{ t('slot.update') }}
                  </button>
                </div>
              </div>

              <!-- Component Sections inside this file (Level 3) -->
              <div
                v-for="(item, itemIdx) in file.items"
                :key="item.item_id"
                class="space-y-1.5"
                :class="{ 'pt-1.5 border-t border-zinc-100 dark:border-zinc-800/40': itemIdx > 0 }"
              >
                <!-- Section Name -->
                <div class="text-[11.5px] font-mono font-semibold text-zinc-700 dark:text-zinc-300">
                  [{{ item.section_name }}]
                </div>

                <!-- Code Block (Level 4) -->
                <div class="rounded-lg bg-zinc-50 dark:bg-[#0d0f15] border border-zinc-200/80 dark:border-zinc-800/80 px-3 py-2 font-mono text-xs space-y-1.5 select-text overflow-x-auto">
                  <div
                    v-for="line in item.affected_lines"
                    :key="line.line_number"
                    class="flex items-baseline gap-3"
                  >
                    <span class="w-8 shrink-0 text-right font-mono text-[11px] text-zinc-400 dark:text-zinc-600 select-none tabular-nums">
                      {{ line.line_number }}
                    </span>

                    <!-- Update preview: subtle inline token diff with arrow -->
                    <code
                      v-if="fileDecision(file) === 'update'"
                      class="min-w-0 leading-5 text-zinc-700 dark:text-zinc-300 break-all"
                    >
                      <span v-if="parseCodeParts(line).prefix">{{ parseCodeParts(line).prefix }}</span>
                      <span class="text-zinc-400 dark:text-zinc-500 line-through mr-1 select-none">{{ parseCodeParts(line).currentSlot }}</span>
                      <span class="text-zinc-400 dark:text-zinc-600 font-sans mr-1 select-none">→</span>
                      <span class="text-sky-600 dark:text-sky-400 font-semibold">{{ line.if_shifted_slot }}</span>
                      <span v-if="parseCodeParts(line).suffix">{{ parseCodeParts(line).suffix }}</span>
                    </code>

                    <!-- Kept / Default preview: exact statement -->
                    <code
                      v-else
                      class="min-w-0 leading-5 text-zinc-800 dark:text-zinc-200 break-all"
                    >
                      {{ line.raw_code }}
                    </code>
                  </div>
                </div>
              </div>
            </div>
          </section>
        </div>

        <!-- ── Footer ───────────────────────────────────────────────────── -->
        <footer class="px-5 py-3 shrink-0 border-t border-zinc-200/80 dark:border-white/5 bg-zinc-50/80 dark:bg-[#101219] flex items-center justify-between gap-3 text-xs">
          <span
            class="font-medium text-[11.5px]"
            :class="remainingFiles > 0 ? 'text-zinc-500 dark:text-zinc-400' : 'text-emerald-600 dark:text-emerald-400'"
          >
            {{ remainingFiles > 0 ? t('slot.remaining', { count: remainingFiles }) : t('slot.ready') }}
          </span>

          <div class="flex items-center gap-2.5">
            <button
              @click="fix.dismissSlotDrawer()"
              class="px-3.5 py-1.5 rounded-lg text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-200/60 dark:hover:bg-white/5 transition-colors font-medium"
            >
              {{ t('slot.skip_later') }}
            </button>
            <button
              @click="fix.applySlotDecisions()"
              :disabled="fix.isApplyingSlot || remainingFiles > 0"
              class="px-5 py-1.5 rounded-lg font-semibold bg-[#0066ff] dark:bg-[#0a84ff] text-white hover:bg-blue-600 disabled:opacity-40 disabled:cursor-not-allowed transition-all active:scale-[0.98] flex items-center gap-1.5 shadow-sm"
            >
              <svg v-if="fix.isApplyingSlot" class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              {{ fix.isApplyingSlot ? t('slot.applying') : t('slot.apply') }}
            </button>
          </div>
        </footer>
      </div>
    </div>
  </Transition>
</template>
