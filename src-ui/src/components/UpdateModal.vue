<script setup lang="ts">
import { computed } from 'vue'
import { useUpdateStore } from '../stores/update'
import { useSettingsStore } from '../stores/settings'
import { useI18n } from 'vue-i18n'

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

const localizedNotes = computed(() => {
  if (!update.status?.manifest?.notes) return ''
  const notes = update.status.manifest.notes as any
  let text = typeof notes === 'string' ? notes : (notes[locale.value] || notes['en'] || '')
  return text.replace(/\n/g, '<br>').replace(/- (.*?)(<br>|$)/g, '<li class="ml-4 list-disc mb-1">$1</li>')
})
</script>

<template>
  <Transition name="fade">
    <!-- Overlay Mask -->
    <div v-if="update.status?.available && update.showModal" class="fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6 bg-black/60 backdrop-blur-md transition-all">
      <div class="relative w-full max-w-md bg-white dark:bg-zinc-900 rounded-2xl shadow-2xl overflow-hidden border border-zinc-200 dark:border-zinc-800 flex flex-col transform transition-all">
        
        <!-- Header Art -->
        <div class="h-[100px] bg-gradient-to-br from-sky-500 via-indigo-500 to-purple-600 relative overflow-hidden flex items-center justify-center shrink-0">
          <div class="absolute inset-0 bg-black/10"></div>
          <div class="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCI+PGNpcmNsZSBjeD0iMjAiIGN5PSIyMCIgcj0iMiIgZmlsbD0icmdiYSgyNTUsMjU1LDI1NSwwLjIpIi8+PC9zdmc+')] opacity-20 mix-blend-overlay"></div>
          
          <div class="relative z-10 flex flex-col items-center">
            <div class="w-12 h-12 bg-white/20 backdrop-blur-md rounded-2xl flex items-center justify-center shadow-lg border border-white/30 mb-2">
              <svg class="w-6 h-6 text-white drop-shadow-sm" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path>
              </svg>
            </div>
            <h2 class="text-white font-bold text-lg drop-shadow-sm tracking-wide">{{ $t('update.available') || 'Update Available' }}</h2>
          </div>
        </div>

        <div class="p-6 flex flex-col">
          <!-- Version Info -->
          <div class="flex items-center justify-between mb-4">
            <span class="px-2.5 py-0.5 bg-sky-100 dark:bg-sky-500/20 text-sky-700 dark:text-sky-400 font-mono font-bold text-[13px] rounded-md border border-sky-200 dark:border-sky-500/30">
              {{ update.status?.manifest?.version }}
            </span>
            <div class="text-xs text-zinc-400 font-mono font-medium tracking-wide">
              {{ new Date(update.status?.manifest?.pub_date || '').toLocaleDateString() }}
            </div>
          </div>

          <!-- Mandatory Update Alert -->
          <div v-if="update.status?.mandatory" class="mb-4 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400 text-xs px-3 py-2 rounded-lg border border-rose-200 dark:border-rose-900/50 flex items-start gap-2 shadow-sm">
            <svg class="w-4 h-4 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
            <div class="font-medium leading-relaxed">
              {{ $t('update.mandatory') || 'Mandatory Update (min v' }}{{ update.status?.manifest?.min_required_version }})
            </div>
          </div>

          <!-- Release Notes Panel -->
          <div class="bg-zinc-50 dark:bg-zinc-950/40 rounded-xl p-4 mb-5 border border-zinc-100 dark:border-zinc-800/80 shadow-inner max-h-[160px] overflow-y-auto hide-scrollbar">
            <div class="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-2 select-none">Release Notes</div>
            <!-- Enable HTML tags rendering -->
            <div class="text-[13px] text-zinc-700 dark:text-zinc-300 font-sans leading-relaxed" v-html="localizedNotes"></div>
          </div>

          <!-- Download Progress Area -->
          <div v-if="update.downloading" class="flex flex-col gap-2.5 animate-in fade-in slide-in-from-bottom-2 duration-300">
            <div class="flex justify-between items-end text-xs">
              <div class="flex flex-col gap-1.5">
                <span class="font-bold text-sky-600 dark:text-sky-400">{{ $t('update.downloading') || 'Downloading Update...' }}</span>
                <!-- Active Download Node -->
                <span class="text-[10px] bg-sky-50 dark:bg-sky-900/20 text-sky-600 dark:text-sky-400 px-2 py-1 rounded flex items-center gap-1.5 border border-sky-100 dark:border-sky-800/50 transition-all font-medium">
                  <svg class="w-3 h-3 animate-spin" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" class="opacity-30"></circle><path fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" class="opacity-70"></path></svg>
                  {{ $t(`update.${update.activeNodeId.replace('-', '_')}`) || update.activeNodeId }}
                </span>
              </div>
              <span class="font-mono text-xl font-black bg-gradient-to-r from-sky-400 to-indigo-400 bg-clip-text text-transparent">{{ update.dlPct }}%</span>
            </div>
            
            <div class="h-2 w-full bg-zinc-200 dark:bg-zinc-800/80 rounded-full overflow-hidden shadow-inner relative">
              <!-- Progress Bar Background -->
              <div class="h-full bg-sky-500 transition-all duration-150 ease-out relative" :style="`width: ${update.dlPct}%`">
                <div class="absolute inset-0 bg-white/20 -skew-x-12 animate-[slide_2s_linear_infinite]"></div>
              </div>
            </div>
            <div class="text-right text-[10.5px] text-zinc-400 font-mono font-medium">{{ update.dlProgressMb }}</div>
          </div>

          <!-- Pre-download Controls -->
          <div v-else class="flex flex-col gap-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
            <div class="flex items-center justify-between gap-3 bg-zinc-50 dark:bg-zinc-900/60 p-2.5 pl-4 rounded-xl border border-zinc-200 dark:border-zinc-800/80 transition-colors">
              <span class="text-xs font-bold text-zinc-500 dark:text-zinc-400 shrink-0">{{ $t('update.proxy_node') || 'Download Node' }}</span>
              <div class="relative w-40">
                <select :value="settings.proxy_node" @change="handleNodeChange" class="w-full bg-white dark:bg-zinc-800 text-xs font-bold text-zinc-800 dark:text-zinc-200 py-1.5 pl-3 pr-8 rounded-lg outline-none appearance-none cursor-pointer border border-zinc-200 dark:border-zinc-700 shadow-sm focus:ring-2 focus:ring-sky-500/50 transition-all">
                  <option v-for="n in proxyNodes" :key="n.id" :value="n.id">{{ $t(n.label) }}</option>
                </select>
                <div class="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none">
                  <svg class="w-3.5 h-3.5 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                </div>
              </div>
            </div>
            
            <div class="flex gap-3">
              <button v-if="!update.status?.mandatory" @click="update.ignoreCurrentVersion()" class="flex-1 py-3 rounded-xl border border-zinc-200 dark:border-zinc-700 text-zinc-600 dark:text-zinc-300 font-bold text-sm hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors active:scale-[0.98]">
                {{ $t('update.skip') || 'Later' }}
              </button>
              <button @click="update.downloadAndApply()" class="flex-[2] py-3 rounded-xl bg-sky-500 hover:bg-sky-600 text-white font-bold text-sm shadow-lg shadow-sky-500/25 active:scale-[0.98] transition-all flex items-center justify-center gap-2">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                {{ $t('update.download_update') || 'Update Now' }}
              </button>
            </div>
          </div>
          
        </div>
      </div>
    </div>
  </Transition>
</template>

<style scoped>
@keyframes shimmer {
  100% { transform: translateX(100%); }
}
@keyframes slide {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(200%); }
}
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease, backdrop-filter 0.3s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  backdrop-filter: blur(0px);
}
</style>