<script setup lang="ts">
import { useFixStore } from '../stores/fix'
import { ref, watch, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { invoke } from '@tauri-apps/api/core'

const { t } = useI18n()
const fix = useFixStore()
const logContainer = ref<HTMLElement | null>(null)
const props = defineProps(['modPath', 'optionsInfo'])
const emit = defineEmits(['config-updated'])

const refreshing = ref(false)
const exported = ref(false)

// Reliable auto-scroll trigger
watch(() => fix.logs, async () => {
  if (fix.autoScroll && logContainer.value) {
    await nextTick()
    logContainer.value.scrollTop = logContainer.value.scrollHeight
  }
}, { flush: 'post' })

let isDraggingScrollbar = false;

function handleWheel(e: WheelEvent) {
  if (e.deltaY < 0) fix.autoScroll = false;
}

let touchStartY = 0;
function handleTouchStart(e: TouchEvent) {
  touchStartY = e.touches[0].clientY;
}
function handleTouchMove(e: TouchEvent) {
  if (e.touches[0].clientY > touchStartY + 5) fix.autoScroll = false;
}

function handleMouseDown(e: MouseEvent) {
  if (!logContainer.value) return;
  if (e.offsetX > logContainer.value.clientWidth - 20) {
    isDraggingScrollbar = true;
    const stopDrag = () => {
      isDraggingScrollbar = false;
      window.removeEventListener('mouseup', stopDrag);
    };
    window.addEventListener('mouseup', stopDrag);
  }
}

function handleKeyDown(e: KeyboardEvent) {
  if (['ArrowUp', 'PageUp', 'Home'].includes(e.key)) {
    fix.autoScroll = false;
  }
}

function handleScroll() {
  if (!logContainer.value) return;
  const { scrollTop, scrollHeight, clientHeight } = logContainer.value;
  const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
  
  if (isAtBottom) {
    fix.autoScroll = true;  // User reached the bottom
  } else if (isDraggingScrollbar) {
    fix.autoScroll = false; // User is dragging scrollbar up
  }
}

async function exportLogs() {
  if (fix.logs.length === 0) {
    fix.pushLog('WARN', t('console.no_logs_export'));
    return;
  }
  
  const decodeHtml = (html: string) => {
    const txt = document.createElement("textarea");
    txt.innerHTML = html;
    return txt.value;
  };
  const logBody = fix.logs.map(l => decodeHtml(l.messageHtml.replace(/<[^>]+>/g, ''))).join('\n');
  
  try {
    const savedPath = await invoke<string>('export_logs', { 
      logBody, 
      modPath: props.modPath || "N/A", 
      optionsInfo: props.optionsInfo || "Default"
    });
    fix.pushLog('INFO', `[OK] ${t('console.export_success')}: ${savedPath}`);
    (window as any).showToast?.(t('console.export_success') || 'Exported successfully!', 'success');
    
    // Visual feedback
    exported.value = true;
    setTimeout(() => { exported.value = false; }, 2000);
  } catch (e) {
    fix.pushLog('ERROR', `[ERROR] ${t('console.export_failed')}: ${e}`);
    (window as any).showToast?.(t('console.export_failed') || 'Export failed!', 'error');
  }
}

async function refreshConfig() {
  if (refreshing.value) return;
  refreshing.value = true;
  fix.pushLog('INFO', `[INFO] ${t('console.fetching_config')}...`);
  try {
    await invoke('refresh_config');
    fix.pushLog('INFO', `[OK] ${t('console.config_updated')}`);
    (window as any).showToast?.(t('console.config_updated') || 'Config updated!', 'success');
    emit('config-updated');
  } catch (e) {
    fix.pushLog('ERROR', `[ERROR] ${t('console.config_failed')}: ${e}`);
    (window as any).showToast?.(t('console.config_failed') || 'Config update failed!', 'error');
  } finally {
    refreshing.value = false;
  }
}
</script>

<template>
  <div class="h-full flex flex-col rounded-xl bg-white dark:bg-[#0c0d12] border border-zinc-200 dark:border-zinc-800/60 shadow-sm overflow-hidden relative font-mono group">
    
    <div class="px-4 py-2.5 bg-zinc-50 dark:bg-[#12131a] border-b border-zinc-200 dark:border-zinc-800/60 flex justify-between items-center z-10 select-none shrink-0">
      <div class="flex items-center gap-4">
        <div class="flex items-center gap-2">
          <!-- Clean, professional Terminal Icon representing log console -->
          <svg class="w-4 h-4 text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
          <span class="text-[11px] font-bold tracking-widest text-zinc-500 uppercase flex items-center gap-2">
            Console
          </span>
        </div>

        <div class="flex items-center gap-3 border-l border-zinc-200 dark:border-zinc-700/50 pl-4">
          <button @click="refreshConfig" class="text-[11px] text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-sky-400 transition-colors flex items-center gap-1" :title="t('console.refresh_desc')">
            <svg class="w-3.5 h-3.5" :class="{'animate-spin': refreshing}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
            {{ $t('console.refresh') }}
          </button>
          <button @click="exportLogs" class="text-[11px] text-zinc-500 hover:text-emerald-600 dark:text-zinc-400 dark:hover:text-emerald-400 transition-colors flex items-center gap-1">
            <svg v-if="!exported" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
            <svg v-else class="w-3.5 h-3.5 text-emerald-500 dark:text-emerald-400 animate-in zoom-in-50 duration-200" fill="none" stroke="currentColor" stroke-width="3" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            {{ exported ? $t('console.export_done') || 'Done!' : $t('console.export') }}
          </button>
        </div>
      </div>

      <label class="flex items-center gap-1.5 text-[11px] cursor-pointer transition-colors select-none" 
             :class="fix.autoScroll 
               ? 'text-sky-600 dark:text-sky-400 font-bold' 
               : 'text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-300'"
             :title="t('console.auto_scroll_desc')">
        <div 
          class="w-3.5 h-3.5 rounded border flex items-center justify-center transition-all duration-150 shrink-0"
          :class="fix.autoScroll 
            ? 'border-sky-500/50 bg-sky-50 dark:border-sky-400/50 dark:bg-sky-400/10 text-sky-600 dark:text-sky-400' 
            : 'border-zinc-300 dark:border-zinc-600 bg-white dark:bg-transparent'"
        >
          <svg v-if="fix.autoScroll" class="w-2.5 h-2.5" fill="none" stroke="currentColor" stroke-width="3" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <span>{{ $t('console.auto_scroll') }}</span>
        <input type="checkbox" v-model="fix.autoScroll" class="hidden" />
      </label>
    </div>
    
    <div @keydown="handleKeyDown" tabindex="0" @wheel.passive="handleWheel" @touchstart.passive="handleTouchStart" @touchmove.passive="handleTouchMove" @mousedown="handleMouseDown" @scroll.passive="handleScroll" class="flex-1 overflow-y-auto p-4 text-[12px] leading-relaxed hide-scrollbar scroll-smooth min-h-0 focus:outline-none" ref="logContainer">
      <div v-if="fix.logs.length === 0" class="h-full flex flex-col items-center justify-center text-zinc-400 dark:text-zinc-600 opacity-80">
        <svg class="w-8 h-8 mb-3 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"></path></svg>
        <span class="italic">{{ $t('console.waiting') }}</span>
      </div>
      
      <div v-for="log in fix.logs" :key="log.id" class="mb-1 flex hover:bg-zinc-100/50 dark:hover:bg-white/[0.04] px-2 -mx-2 rounded transition-colors break-words pl-2">
        <div class="flex-1 min-w-0">
          <span v-if="log.level === 'ERROR'" class="text-rose-600 dark:text-rose-400 font-bold drop-shadow-sm dark:drop-shadow-[0_0_8px_rgba(251,113,133,0.15)]" v-html="log.messageHtml"></span>
          <span v-else-if="log.level === 'WARN'" class="text-amber-600 dark:text-amber-400 font-medium" v-html="log.messageHtml"></span>
          <span v-else-if="log.messageHtml.includes('SUCCESS') || log.messageHtml.toLowerCase().includes('success') || log.messageHtml.includes('完成') || log.messageHtml.includes('成功')" class="text-emerald-600 dark:text-emerald-400 font-bold" v-html="log.messageHtml"></span>
          <span v-else-if="log.messageHtml.includes('---')" class="text-zinc-400 dark:text-zinc-600" v-html="log.messageHtml"></span>
          <span v-else class="text-zinc-700 dark:text-zinc-300" v-html="log.messageHtml"></span>
        </div>
      </div>
      <!-- Spacer to prevent bottom progress bar overlap -->
      <div class="h-2 w-full shrink-0"></div>
    </div>
    
    <div v-if="fix.running" class="absolute bottom-0 left-0 right-0 h-[3px] bg-zinc-100 dark:bg-zinc-900 shrink-0">
      <div 
        class="h-full animate-[bg-pan_2s_linear_infinite] transition-all duration-300 ease-out" 
        :class="fix.isCancelling ? 'bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.8)]' : 'bg-gradient-to-r from-sky-400 via-indigo-400 to-sky-400 shadow-[0_0_10px_rgba(56,189,248,0.8)]'"
        :style="{ width: `${fix.progressPct}%` }">
      </div>
    </div>
  </div>
</template>