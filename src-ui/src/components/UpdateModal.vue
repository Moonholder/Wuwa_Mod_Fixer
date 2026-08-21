<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { useUpdateStore } from '../stores/update'
import { useSettingsStore } from '../stores/settings'
import { useI18n } from 'vue-i18n'
import { invoke } from '@tauri-apps/api/core'
import { marked } from 'marked'
import DOMPurify from 'dompurify'

marked.setOptions({
  breaks: false,
  gfm: true,
})

const update = useUpdateStore()
const settings = useSettingsStore()
const { locale } = useI18n()

const proxyNodes = [
  { id: 'direct', label: 'update.direct' },
  { id: 'ghfast', label: 'update.ghfast' },
  { id: 'ghproxy', label: 'update.ghproxy' },
  { id: 'dlproxy', label: 'update.dlproxy' },
  { id: 'kgithub', label: 'update.kgithub' }
]

function handleNodeChange(e: Event) {
  const node = (e.target as HTMLSelectElement).value
  settings.setProxy(node)
  update.proxyNode = node
}

function preprocessMarkdown(text: string): string {
  if (!text) return ''
  const lines = text.split(/\r?\n/)
  const result: string[] = []
  
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]
    const prev = result[result.length - 1]
    const isList = /^\s*([-*+]|\d+\.)\s+/.test(line)
    const isPrevList = prev !== undefined && /^\s*([-*+]|\d+\.)\s+/.test(prev)
    const isPrevEmpty = prev === undefined || prev.trim() === ''
    const isEmpty = line.trim() === ''

    if (!isEmpty && !isList && isPrevList) {
      result.push('')
    } else if (isList && !isPrevEmpty && !isPrevList) {
      result.push('')
    }

    const trimmed = line.trim()
    if (
      trimmed && 
      !isList && 
      !/^#{1,6}\s/.test(trimmed) && 
      !/^\*\*.*\*\*$/.test(trimmed) && 
      trimmed.length <= 20 && 
      !/[。！？.!?]$/.test(trimmed)
    ) {
      line = `**${trimmed}**`
    }

    result.push(line)
  }
  return result.join('\n')
}

const localizedNotes = computed(() => {
  if (!update.status?.manifest?.notes) return ''
  const notes = update.status.manifest.notes as any
  const rawText = typeof notes === 'string' 
    ? notes 
    : (notes[locale.value] || notes['en'] || Object.values(notes)[0] || '')
  
  const processedText = preprocessMarkdown(rawText)
  const rawHtml = marked.parse(processedText) as string
  return DOMPurify.sanitize(rawHtml, {
    ALLOWED_TAGS: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'b', 'i', 'strong', 'em', 'strike', 'code', 'hr', 'br', 'ul', 'ol', 'li', 'blockquote', 'pre', 'a', 'span'],
    ALLOWED_ATTR: ['href', 'target', 'rel', 'class'],
  })
})

function handleNotesClick(e: MouseEvent) {
  const target = e.target as HTMLElement
  const anchor = target.closest('a')
  if (anchor && anchor.getAttribute('href')) {
    e.preventDefault()
    const url = anchor.getAttribute('href')!
    if (/^https?:\/\//i.test(url)) {
      invoke('open_url', { url }).catch(err => {
        console.error('Failed to open link:', err)
      })
    }
  }
}

function handleKeyDown(e: KeyboardEvent) {
  if (e.key === 'Escape' && update.showModal && !update.status?.mandatory && !update.downloading) {
    update.ignoreCurrentVersion()
  }
}

onMounted(() => {
  window.addEventListener('keydown', handleKeyDown)
})

onUnmounted(() => {
  window.removeEventListener('keydown', handleKeyDown)
})
</script>

<template>
  <Transition name="fade">
    <!-- Overlay Mask (top-8 leaves window titlebar accessible) -->
    <div 
      v-if="update.status?.available && update.showModal" 
      class="fixed inset-x-0 top-8 bottom-0 z-[100] flex items-center justify-center p-4 sm:p-6 bg-black/65 backdrop-blur-sm transition-all select-none"
    >
      <div class="modal-card relative w-full max-w-[480px] bg-white dark:bg-[#12141a] rounded-2xl shadow-2xl overflow-hidden border border-zinc-200 dark:border-zinc-800/90 flex flex-col transform transition-all p-6">
        
        <!-- Header -->
        <div class="flex items-center justify-between pb-3">
          <h2 class="text-zinc-900 dark:text-white font-bold text-lg tracking-wide">
            {{ $t('update.title') || '应用更新' }}
          </h2>
          
          <!-- Close button (X) -->
          <button 
            v-if="!update.status?.mandatory && !update.downloading" 
            @click="update.ignoreCurrentVersion()" 
            class="w-8 h-8 rounded-lg bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-800/80 dark:hover:bg-zinc-700/80 text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-white flex items-center justify-center transition-colors active:scale-95"
            :title="$t('update.skip') || '关闭'"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <!-- New Version Prompt -->
        <div class="flex items-center justify-between text-[13px] font-medium text-zinc-700 dark:text-zinc-300 mb-3.5">
          <div>
            {{ $t('update.prompt_prefix') || '发现新版本:' }} 
            <span class="font-bold text-sky-600 dark:text-sky-400 font-mono">{{ update.status?.manifest?.version }}</span>。
            {{ $t('update.prompt_suffix') || '是否立即更新？' }}
          </div>
        </div>

        <!-- Mandatory Update Alert -->
        <div v-if="update.status?.mandatory" class="mb-3.5 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400 text-xs px-3 py-2 rounded-lg border border-rose-200 dark:border-rose-900/50 flex items-start gap-2 shadow-sm">
          <svg class="w-4 h-4 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          <div class="font-medium leading-relaxed">
            {{ $t('update.mandatory') || '需要更新程序。最低要求版本: ' }}{{ update.status?.manifest?.min_required_version }}
          </div>
        </div>

        <!-- Release Notes Card Panel -->
        <div class="bg-zinc-50 dark:bg-[#0d1117] rounded-xl border border-zinc-200/80 dark:border-[#30363d] overflow-hidden mb-4 shadow-inner">
          <div class="px-3.5 py-2 border-b border-zinc-200/60 dark:border-[#30363d] text-[11px] font-bold text-zinc-500 dark:text-[#8b949e] tracking-wide select-none">
            {{ $t('update.notes_title') || 'GitHub Release 更新说明' }}
          </div>
          <!-- Markdown Content with DOMPurify sanitization -->
          <div 
            class="p-4 max-h-[220px] overflow-y-auto release-notes-scroll text-[13px] text-zinc-700 dark:text-[#e6edf3] leading-relaxed select-text" 
            v-html="localizedNotes" 
            @click="handleNotesClick"
          ></div>
        </div>

        <!-- Download Progress Area -->
        <div v-if="update.downloading" class="flex flex-col gap-2.5 animate-in fade-in slide-in-from-bottom-2 duration-300">
          <div class="flex justify-between items-end text-xs">
            <div class="flex flex-col gap-1.5">
              <span class="font-bold text-sky-600 dark:text-sky-400">{{ $t('update.downloading') || '正在下载更新...' }}</span>
              <!-- Active Download Node -->
              <span class="text-[10px] bg-sky-50 dark:bg-sky-900/20 text-sky-600 dark:text-sky-400 px-2 py-0.5 rounded flex items-center gap-1.5 border border-sky-100 dark:border-sky-800/50 font-medium">
                <svg class="w-2.5 h-2.5 animate-spin" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" class="opacity-30"></circle><path fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" class="opacity-70"></path></svg>
                {{ $t(`update.${update.activeNodeId.replace('-', '_')}`) || update.activeNodeId }}
              </span>
            </div>
            <span class="font-mono text-lg font-black text-sky-600 dark:text-sky-400">{{ update.dlPct }}%</span>
          </div>
          
          <div class="h-2 w-full bg-zinc-200 dark:bg-zinc-800/80 rounded-full overflow-hidden shadow-inner relative">
            <div class="h-full bg-sky-500 transition-all duration-150 ease-out" :style="`width: ${update.dlPct}%`"></div>
          </div>
          <div class="text-right text-[10.5px] text-zinc-400 font-mono font-medium">{{ update.dlProgressMb }}</div>
        </div>

        <!-- Pre-download Controls & Buttons -->
        <div v-else class="flex items-center justify-between gap-3 pt-1">
          <!-- Proxy Node Selector (Compact) -->
          <div class="flex items-center gap-2">
            <span class="text-[11px] font-medium text-zinc-400 dark:text-zinc-500 shrink-0">{{ $t('update.proxy_node') || '节点:' }}</span>
            <div class="relative">
              <select 
                :value="settings.proxy_node" 
                @change="handleNodeChange" 
                class="bg-zinc-100 hover:bg-zinc-200/80 dark:bg-[#1a1c24] dark:hover:bg-[#252834] text-[11px] font-bold text-zinc-700 dark:text-zinc-200 py-1.5 pl-3 pr-7 rounded-lg outline-none appearance-none cursor-pointer border border-zinc-200/80 dark:border-zinc-700/80 shadow-sm focus:ring-1 focus:ring-sky-500/50 transition-all min-w-[125px]"
              >
                <option v-for="n in proxyNodes" :key="n.id" :value="n.id" class="bg-white dark:bg-[#181a20] text-zinc-800 dark:text-zinc-200">{{ $t(n.label) }}</option>
              </select>
              <div class="absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none">
                <svg class="w-3.5 h-3.5 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
              </div>
            </div>
          </div>
          
          <!-- Action Buttons (Right Aligned) -->
          <div class="flex items-center gap-2.5">
            <button 
              v-if="!update.status?.mandatory" 
              @click="update.ignoreCurrentVersion()" 
              class="px-4 py-2 rounded-lg bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-200 font-bold text-xs transition-colors active:scale-[0.98]"
            >
              {{ $t('update.skip') || '跳过' }}
            </button>
            <button 
              @click="update.downloadAndApply()" 
              class="px-4 py-2 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-white dark:bg-zinc-100 dark:hover:bg-white dark:text-zinc-900 font-bold text-xs shadow-sm active:scale-[0.98] transition-all"
            >
              {{ $t('update.download_update') || '立即更新' }}
            </button>
          </div>
        </div>

      </div>
    </div>
  </Transition>
</template>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease, backdrop-filter 0.2s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  backdrop-filter: blur(0px);
}

.fade-enter-active .modal-card {
  transition: transform 0.28s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.fade-leave-active .modal-card {
  transition: transform 0.15s cubic-bezier(0.25, 1, 0.5, 1);
}
.fade-enter-from .modal-card {
  transform: scale(0.95) translateY(8px);
}
.fade-leave-to .modal-card {
  transform: scale(0.97) translateY(4px);
}

/* Custom Scrollbar for Release Notes */
.release-notes-scroll {
  scrollbar-width: thin;
  scrollbar-color: rgba(120, 120, 120, 0.3) transparent;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  font-size: 13px;
  line-height: 1.65;
  color: #e6edf3;
}
.release-notes-scroll::-webkit-scrollbar {
  width: 5px;
}
.release-notes-scroll::-webkit-scrollbar-track {
  background: transparent;
}
.release-notes-scroll::-webkit-scrollbar-thumb {
  background: rgba(120, 120, 120, 0.3);
  border-radius: 4px;
}
.release-notes-scroll::-webkit-scrollbar-thumb:hover {
  background: rgba(120, 120, 120, 0.5);
}

/* Release Notes Typography - Pixel-perfect GitHub Primer Style */
.release-notes-scroll :deep(a) {
  color: #4493f8;
  text-decoration: underline;
  text-underline-offset: 3px;
  text-decoration-thickness: 1px;
  cursor: pointer;
  transition: color 0.15s ease;
}
.release-notes-scroll :deep(a:hover) {
  color: #79c0ff;
}

.release-notes-scroll :deep(h1),
.release-notes-scroll :deep(h2),
.release-notes-scroll :deep(h3),
.release-notes-scroll :deep(h4),
.release-notes-scroll :deep(h5),
.release-notes-scroll :deep(h6) {
  font-weight: 600;
  line-height: 1.35;
  margin-top: 16px;
  margin-bottom: 8px;
  color: #f0f6fc;
}
.release-notes-scroll :deep(h1:first-child),
.release-notes-scroll :deep(h2:first-child),
.release-notes-scroll :deep(h3:first-child),
.release-notes-scroll :deep(h4:first-child),
.release-notes-scroll :deep(p:first-child) {
  margin-top: 0;
}

.release-notes-scroll :deep(h1) {
  font-size: 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.12);
  padding-bottom: 4px;
}
.release-notes-scroll :deep(h2) {
  font-size: 15px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  padding-bottom: 3px;
}
.release-notes-scroll :deep(h3) {
  font-size: 14px;
}
.release-notes-scroll :deep(h4) {
  font-size: 13px;
}

.release-notes-scroll :deep(p) {
  margin-top: 10px;
  margin-bottom: 8px;
  line-height: 1.65;
}
.release-notes-scroll :deep(p:first-child) {
  margin-top: 0;
}
.release-notes-scroll :deep(p:last-child) {
  margin-bottom: 0;
}

.release-notes-scroll :deep(ul),
.release-notes-scroll :deep(ol) {
  padding-left: 20px;
  margin-top: 8px;
  margin-bottom: 10px;
}
.release-notes-scroll :deep(ul:first-child),
.release-notes-scroll :deep(ol:first-child) {
  margin-top: 0;
}
.release-notes-scroll :deep(ul:last-child),
.release-notes-scroll :deep(ol:last-child) {
  margin-bottom: 0;
}

.release-notes-scroll :deep(ul) {
  list-style-type: disc;
}
.release-notes-scroll :deep(ol) {
  list-style-type: decimal;
}

.release-notes-scroll :deep(li) {
  margin-top: 4px;
  margin-bottom: 4px;
  line-height: 1.65;
  padding-left: 2px;
}
.release-notes-scroll :deep(li + li) {
  margin-top: 4px;
}
.release-notes-scroll :deep(li > p) {
  margin-top: 3px;
  margin-bottom: 3px;
}
.release-notes-scroll :deep(li > ul),
.release-notes-scroll :deep(li > ol) {
  margin-top: 3px;
  margin-bottom: 3px;
  padding-left: 18px;
}

.release-notes-scroll :deep(strong),
.release-notes-scroll :deep(b) {
  font-weight: 700;
  color: #ffffff;
}
.release-notes-scroll :deep(p > strong:only-child),
.release-notes-scroll :deep(p > b:only-child) {
  font-size: 14.5px;
  font-weight: 700;
  display: inline-block;
  color: #ffffff;
  margin-top: 4px;
}
.release-notes-scroll :deep(em),
.release-notes-scroll :deep(i) {
  font-style: italic;
}

.release-notes-scroll :deep(code) {
  background: rgba(110, 118, 129, 0.25);
  padding: 0.18em 0.4em;
  margin: 0 0.15em;
  border-radius: 4px;
  font-size: 85%;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
}

.release-notes-scroll :deep(pre) {
  background: rgba(0, 0, 0, 0.25);
  border-radius: 6px;
  padding: 8px 12px;
  overflow-x: auto;
  font-size: 85%;
  line-height: 1.45;
  margin-top: 8px;
  margin-bottom: 10px;
}
.release-notes-scroll :deep(pre code) {
  background: transparent;
  padding: 0;
}

.release-notes-scroll :deep(blockquote) {
  border-left: 3px solid rgba(88, 166, 255, 0.5);
  padding-left: 0.8rem;
  margin: 8px 0;
  color: rgba(156, 163, 175, 1);
}

.release-notes-scroll :deep(hr) {
  border: none;
  border-top: 1px solid rgba(255, 255, 255, 0.12);
  margin: 12px 0;
}
</style>