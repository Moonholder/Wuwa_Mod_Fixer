<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { getCurrentWindow, PhysicalSize, PhysicalPosition } from '@tauri-apps/api/window'
import { useFixStore } from './stores/fix'
import { useSettingsStore } from './stores/settings'
import { useUpdateStore } from './stores/update'
import UpdateModal from './components/UpdateModal.vue'
import LogConsole from './components/LogConsole.vue'
import Rollback from './components/Rollback.vue'
import { useI18n } from 'vue-i18n'

const fix = useFixStore()
const settings = useSettingsStore()
const update = useUpdateStore()
const { t, locale } = useI18n()
const appWindow = getCurrentWindow()

const currentView = ref('main')
const isDragging = ref(false)
const fixFinished = ref(false)
const showUpToDateFeedback = ref(false)
const os = ref('windows')
const isMaximized = ref(false)
let unlistenResize: UnlistenFn | null = null

const configMeta = ref({
  version: 'Loading...',
  support_url_cn: 'https://support.jix.de5.net',
  support_url_intl: 'https://ko-fi.com/moonholder',
  app_version: 'Loading...'
})

const isPickingFolder = ref(false)
let isChinaMainland = false

let unlistenDrop: UnlistenFn | null = null
let unlistenEnter: UnlistenFn | null = null
let unlistenLeave: UnlistenFn | null = null
let unlistenConfig: UnlistenFn | null = null

const options = ref({
  enableTextureOverride: false,
  enableStableTexture: false,
  enableFixAemeathMech: false,
  aeroFixMode: 0,
})



async function winClose() {
  try {
    const size = await appWindow.innerSize()
    const pos = await appWindow.outerPosition()
    settings.window_width = size.width
    settings.window_height = size.height
    settings.window_x = pos.x
    settings.window_y = pos.y
  } catch (e) {
    console.warn('Failed to save window state', e)
  }
  await settings.save()
  appWindow.close()
}

function winMinimize() { appWindow.minimize() }
function winMaximize() { appWindow.toggleMaximize() }

async function startWindowDrag(e: MouseEvent) {
  if (e.button === 0) {
    const target = e.target as HTMLElement
    if (target.closest('button') || target.closest('[style*="no-drag"]')) {
      return
    }
    try {
      await appWindow.startDragging()
    } catch (err) {
      console.warn('Failed to drag window:', err)
    }
  }
}

function toggleAeroFixMode() {
  if (options.value.aeroFixMode > 0) {
    options.value.aeroFixMode = 0
  } else {
    options.value.aeroFixMode = 1
    setTimeout(() => {
      const el = document.getElementById('aero-fix-card')
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      }
    }, 120)
  }
}

async function pickFolder() {
  if (isPickingFolder.value) return
  isPickingFolder.value = true
  try {
    const path = await invoke<string | null>('pick_folder', { defaultPath: settings.last_folder || null })
    if (path) { settings.last_folder = path; await settings.save() }
  } catch (e) {
    console.error(e)
  } finally {
    isPickingFolder.value = false
  }
}

async function startFix() {
  if (!settings.last_folder) return
  fixFinished.value = false
  await fix.startFix({ path: settings.last_folder, ...options.value })
  // Show success button state temporarily after processing
  fixFinished.value = true
  setTimeout(() => { fixFinished.value = false }, 3500)
}

function changeLang(e: Event) {
  settings.setLanguage((e.target as HTMLSelectElement).value)
}

function applyTheme(isLight: boolean) {
  if (isLight) {
    document.documentElement.classList.remove('dark')
  } else {
    document.documentElement.classList.add('dark')
  }
}

function toggleTheme() {
  settings.light_theme = !settings.light_theme
  applyTheme(settings.light_theme)
  settings.save()
}

interface Toast {
  id: number
  message: string
  type: 'success' | 'info' | 'error'
}
const toasts = ref<Toast[]>([])
let nextToastId = 0

function showToast(message: string, type: 'success' | 'info' | 'error' = 'success') {
  const id = nextToastId++
  toasts.value.push({ id, message, type })
  setTimeout(() => {
    toasts.value = toasts.value.filter(t => t.id !== id)
  }, 3000)
}

(window as any).showToast = showToast

function openGithub() { invoke('open_url', { url: 'https://github.com/Moonholder/Wuwa_Mod_Fixer' }) }
function openSupport() { 
  const url = isChinaMainland ? configMeta.value.support_url_cn : configMeta.value.support_url_intl
  invoke('open_url', { url }) 
}

async function manualCheckUpdate() {
  if (update.checking) return
  showUpToDateFeedback.value = false
  const success = await update.checkUpdate(true)
  if (!success) {
    showToast(t('console.config_failed') || 'Failed to check updates', 'error')
    return
  }
  if (!update.status || !update.status.available) {
    showUpToDateFeedback.value = true
    setTimeout(() => {
      showUpToDateFeedback.value = false
    }, 2500)
  }
}

// Fetch and display the intro logs in the console
async function fetchAndPrintIntroLogs(force = false) {
  if (!force && fix.logs.length > 0) return
  if (force) {
    fix.logs = []
  }
  try {
    const logs = await invoke<string[]>('get_intro_logs', { lang: locale.value })
    fix.pushLog('INFO', '=================================')
    logs.forEach(logLine => {
      if (logLine && logLine.trim().length > 0) {
        logLine.split('\n').forEach(line => {
          if (line.trim().length > 0) fix.pushLog('INFO', line)
        })
      }
    })
    fix.pushLog('INFO', '=================================')
    fix.pushLog('INFO', t('app.ready') || 'Ready...')
  } catch (e) {
    fix.pushLog('INFO', t('app.ready') || 'Ready...')
  }
}

async function handleConfigUpdated() {
  try { configMeta.value = await invoke<any>('get_config_meta') } catch (e) { }
  await fetchAndPrintIntroLogs(true)
}

onMounted(async () => {
  try {
    try {
      os.value = await invoke<string>('get_os')
    } catch (e) {
      console.warn("Failed to retrieve OS", e)
    }
    await settings.load()
    applyTheme(settings.light_theme ?? false)
    
    try {
      isMaximized.value = await appWindow.isMaximized()
      unlistenResize = await appWindow.onResized(async () => {
        isMaximized.value = await appWindow.isMaximized()
      })
    } catch (e) {
      console.warn("Initialize window maximize state failed", e)
    }
    
    if (settings.window_width && settings.window_height) {
      try {
        await appWindow.setSize(new PhysicalSize(settings.window_width, settings.window_height))
        if (settings.window_x !== undefined && settings.window_y !== undefined && settings.window_x > -8000) {
          await appWindow.setPosition(new PhysicalPosition(settings.window_x, settings.window_y))
        }
      } catch (e) {
        console.warn("Restore window bounds failed")
      }
    }

    // Ensure window comes to the foreground upon update restart
    try { await appWindow.setFocus() } catch (e) {}
  } catch (e) {
    console.error("Initialization failed:", e)
  } finally {
    // Show the window now that the correct size and position have been restored, or fallback to default
    try { await appWindow.show() } catch (e) {}
  }


  
  try { configMeta.value = await invoke<any>('get_config_meta') } catch (e) { }
  try { isChinaMainland = await invoke<boolean>('is_chinese_mainland') } catch (e) {}

  if (import.meta.env.DEV) {
    await fetchAndPrintIntroLogs()
  } else {
    update.checkUpdate()
  }

  // Listen to background remote config reload
  unlistenConfig = await listen('config:reloaded', async () => {
    try { configMeta.value = await invoke<any>('get_config_meta') } catch (e) { }
    await fetchAndPrintIntroLogs(true)
  })

  unlistenEnter = await listen('tauri://drag-enter', () => isDragging.value = true)
  unlistenLeave = await listen('tauri://drag-leave', () => isDragging.value = false)
  unlistenDrop = await listen<{ paths: string[] }>('tauri://drag-drop', (event) => {
    isDragging.value = false
    if (event.payload?.paths?.length > 0) {
      settings.last_folder = event.payload.paths[0]
      settings.save()
    }
  })
})

onUnmounted(() => {
  if (unlistenDrop) unlistenDrop()
  if (unlistenEnter) unlistenEnter()
  if (unlistenLeave) unlistenLeave()
  if (unlistenConfig) unlistenConfig()
  if (unlistenResize) unlistenResize()
})
</script>

<template>
  <div :class="[
    'bg-[#f4f5f6] dark:bg-[#0a0b0d] text-zinc-900 dark:text-zinc-100 font-sans overflow-hidden transition-colors duration-300 flex flex-col',
    (os === 'linux' || isMaximized) ? 'absolute inset-0 rounded-none ring-0 shadow-none' : 'absolute inset-0 rounded-xl border border-zinc-300/60 dark:border-zinc-800/80 shadow-none'
  ]" style="transform: translateZ(0);">
    
    <div v-if="os !== 'linux'" @mousedown="startWindowDrag" @dblclick="winMaximize" data-tauri-drag-region 
         :class="[
           'h-8 w-full flex justify-between items-center pl-4 shrink-0 bg-white/80 dark:bg-[#12131a]/80 border-b border-zinc-250/85 dark:border-zinc-800/80 z-50 select-none cursor-grab active:cursor-grabbing backdrop-blur-xl',
           isMaximized ? 'rounded-t-none' : 'rounded-t-xl'
         ]" 
         style="-webkit-app-region: drag;">
      
      <div class="pointer-events-none flex items-center gap-2 select-none">
        <img src="/app-icon.png" class="w-4 h-4 object-contain" alt="Logo" />
        <span class="text-[11px] font-medium text-zinc-700 dark:text-zinc-300 h-4 flex items-center">Wuwa Mod Fixer</span>
      </div>

      <div class="flex h-full items-center" style="-webkit-app-region: no-drag;">
        <button @click="winMinimize" class=" w-12 h-full flex justify-center items-center hover:bg-zinc-200/80 dark:hover:bg-zinc-800/80 text-zinc-500 transition-colors">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" d="M4 12h16" /></svg>
        </button>
        <button @click="winMaximize" class="w-12 h-full flex justify-center items-center hover:bg-zinc-200/80 dark:hover:bg-zinc-800/80 text-zinc-500 transition-colors">
          <svg v-if="!isMaximized" class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" /></svg>
          <svg v-else class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path d="M6 3h12v12" />
            <rect x="3" y="6" width="12" height="12" />
          </svg>
        </button>
        <button @click="winClose" class="w-12 h-full flex justify-center items-center hover:bg-[#e81123] hover:text-white text-zinc-500 transition-colors">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
    </div>

    <div v-if="isDragging" class="absolute inset-0 z-[60] bg-sky-500/20 backdrop-blur-sm flex items-center justify-center border-4 border-dashed animate-pulse-glow m-3 rounded-2xl pointer-events-none transition-all duration-200">
      <div class="text-3xl font-bold text-sky-600 dark:text-sky-300 drop-shadow-md flex flex-col items-center gap-4">
        <svg class="w-16 h-16 animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
        {{ $t('app.drop_folder_here') || 'Drop Folder Here' }}
      </div>
    </div>

    <!-- Soft ambient background glow instead of bright templates -->
    <div class="absolute top-0 right-0 w-[40%] h-[40%] bg-gradient-to-br from-sky-500/5 to-transparent blur-[120px] pointer-events-none"></div>



    <div class="flex-1 flex flex-col px-3 lg:px-4 pb-3 w-full relative z-10 min-h-0">
      <!-- Main responsive layout -->
      <main class="flex-1 flex flex-col lg:flex-row gap-3 min-h-0 w-full overflow-y-auto lg:overflow-hidden hide-scrollbar pt-3">
        
        <!-- Left options panel -->
        <div class="w-full lg:w-[45%] lg:min-w-[400px] lg:max-w-[480px] shrink-0 flex flex-col bg-white/80 dark:bg-[#14161d]/85 backdrop-blur-2xl rounded-xl border border-zinc-200/80 dark:border-white/5 shadow-sm shadow-zinc-950/5 h-[55vh] max-h-[calc(100vh-160px)] lg:max-h-none lg:h-full overflow-hidden">
          
          <!-- Shared Panel Header with Segmented Control -->
          <div class="px-4 py-3 shrink-0 flex select-none border-b border-zinc-200/80 dark:border-white/5 rounded-t-xl bg-zinc-50/80 dark:bg-[#101115]/80 justify-center">
            <div class="w-full grid grid-cols-2 bg-zinc-200/50 dark:bg-[#0a0b0d] p-1 rounded-[10px] border border-black/5 dark:border-white/5 shadow-inner">
              <button @click="currentView = 'main'" class="py-1.5 text-[12px] rounded-md transition-all font-medium duration-200 flex justify-center items-center gap-1.5" :class="currentView === 'main' ? 'bg-white dark:bg-[#1f2128] text-zinc-900 dark:text-white shadow-sm ring-1 ring-black/5 dark:ring-white/5' : 'text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300'">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                {{ $t('app.tab_fix') }}
              </button>
              <button @click="currentView = 'rollback'" class="py-1.5 text-[12px] rounded-md transition-all font-medium duration-200 flex justify-center items-center gap-1.5" :class="currentView === 'rollback' ? 'bg-white dark:bg-[#1f2128] text-zinc-900 dark:text-white shadow-sm ring-1 ring-black/5 dark:ring-white/5' : 'text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300'">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                {{ $t('app.tab_rollback') }}
              </button>
            </div>
          </div>

          <div class="flex-1 min-h-0 flex flex-col relative">
            <Transition name="fade" mode="out-in">
              <!-- Fix interface -->
              <div v-if="currentView === 'main'" class="flex flex-col flex-1 min-h-0 w-full">
                
                <!-- Target folder selection -->
                <div class="p-4 border-b border-zinc-200/80 dark:border-white/5 shrink-0">
                  <h3 class="text-[11px] font-bold text-zinc-400 uppercase tracking-widest mb-2.5 flex justify-between items-center select-none">
                    <span>{{ $t('app.target_folder') }}</span>
                    <span class="text-[9px] font-bold text-zinc-500 dark:text-zinc-400 border border-zinc-200/80 dark:border-white/10 bg-zinc-50 dark:bg-white/5 px-1.5 py-0.5 rounded flex items-center gap-1 shadow-sm shrink-0">
                      <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                      {{ $t('app.drag_and_drop') }}
                    </span>
                  </h3>
                  <div class="group relative flex items-center bg-zinc-50 dark:bg-[#0a0b0d] hover:bg-zinc-100 dark:hover:bg-[#121318] transition-all duration-200 rounded-[10px] border p-3 pl-4 cursor-pointer shadow-sm active:scale-[0.995]" 
                       :class="[
                         settings.last_folder 
                           ? 'border-zinc-200/80 dark:border-white/10 ring-1 ring-black/5 dark:ring-0' 
                           : 'border-dashed border-zinc-300 dark:border-zinc-700 hover:border-zinc-400 dark:hover:border-zinc-600',
                         fix.running ? 'opacity-50 pointer-events-none' : ''
                       ]" 
                       @click="!fix.running && pickFolder()">
                    
                    <!-- Path tooltip -->
                    <div v-if="settings.last_folder" class="absolute top-full left-1/2 -translate-x-1/2 mt-2 px-3 py-1.5 bg-zinc-950/95 dark:bg-zinc-900/95 backdrop-blur border border-zinc-800 text-white text-[11px] font-mono rounded-lg shadow-lg opacity-0 group-hover:opacity-100 pointer-events-none transition-all duration-200 z-50 whitespace-normal max-w-[280px] break-all leading-relaxed shadow-sky-500/5">
                      <div class="font-sans font-bold text-zinc-400 mb-0.5 text-[9px] uppercase tracking-wider select-none">{{ $t('app.selected_path') }}</div>
                      {{ settings.last_folder }}
                    </div>
                    
                    <div class="w-9 h-9 rounded-lg flex items-center justify-center transition-colors shadow-sm shrink-0"
                         :class="settings.last_folder ? 'bg-sky-100 dark:bg-sky-900/30 text-sky-500 dark:text-sky-400' : 'bg-zinc-200 dark:bg-zinc-900 text-zinc-400 group-hover:text-zinc-500'">
                      <svg class="w-4.5 h-4.5 flex-shrink-0 transition-transform group-hover:scale-110 duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path>
                      </svg>
                    </div>
                    
                    <div class="ml-3 flex-1 min-w-0 pr-6 flex flex-col justify-center">
                      <div class="text-[9px] text-zinc-400 font-bold uppercase tracking-wider mb-0.5 leading-none select-none">
                        {{ settings.last_folder ? $t('app.selected_path') : $t('app.click_to_select') }}
                      </div>
                      <div class="text-xs truncate font-mono font-bold text-zinc-700 dark:text-zinc-300" :class="{'text-zinc-400 dark:text-zinc-500 italic font-normal': !settings.last_folder}">
                        {{ settings.last_folder || $t('app.no_folder_selected') }}
                      </div>
                    </div>

                    <!-- Right arrow indicator -->
                    <div class="absolute right-4 top-1/2 -translate-y-1/2 text-zinc-400 group-hover:text-zinc-600 dark:group-hover:text-zinc-200 transition-colors">
                      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 5l7 7-7 7"></path></svg>
                    </div>
                  </div>
                </div>

                <!-- Options list -->
                <div class="flex-1 overflow-y-auto p-4 space-y-3">
                  
                  <div @click="!fix.running && !options.enableStableTexture && (options.enableTextureOverride = !options.enableTextureOverride)" class="cursor-pointer p-4 rounded-[10px] border border-zinc-200/80 dark:border-white/5 bg-white/50 dark:bg-[#101115]/50 transition-all hover:bg-zinc-50 dark:hover:bg-[#1a1b22] active:scale-[0.99] duration-200 flex gap-4 items-start" :class="{'opacity-50 pointer-events-none': options.enableStableTexture || fix.running}">
                    <div class="flex-1">
                      <div class="text-[13px] font-semibold text-zinc-800 dark:text-zinc-200">{{ $t('options.derived_hashes') }}</div>
                      <div class="text-[11px] text-zinc-500 mt-0.5 leading-relaxed">{{ $t('options.derived_hashes_desc') }}</div>
                    </div>
                    <button class="pointer-events-none relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out shadow-inner" :class="options.enableTextureOverride ? ((options.enableStableTexture || fix.running) ? 'bg-blue-600/40 dark:bg-blue-500/30' : 'bg-blue-600 dark:bg-blue-500') : 'bg-zinc-200 dark:bg-zinc-700'"><span class="inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform duration-200 ease-in-out" :class="options.enableTextureOverride ? 'translate-x-4' : 'translate-x-0'"></span></button>
                  </div>

                  <div @click="!fix.running && !options.enableTextureOverride && (options.enableStableTexture = !options.enableStableTexture)" class="cursor-pointer p-4 rounded-[10px] border border-zinc-200/80 dark:border-white/5 bg-white/50 dark:bg-[#101115]/50 transition-all hover:bg-zinc-50 dark:hover:bg-[#1a1b22] active:scale-[0.99] duration-200 flex gap-4 items-start" :class="{'opacity-50 pointer-events-none': options.enableTextureOverride || fix.running}">
                    <div class="flex-1">
                      <div class="text-[13px] font-semibold text-zinc-800 dark:text-zinc-200">{{ $t('options.stable_texture') }}</div>
                      <div class="text-[11px] text-zinc-500 mt-0.5 leading-relaxed">{{ $t('options.stable_texture_desc') }}</div>
                    </div>
                    <button class="pointer-events-none relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out shadow-inner" :class="options.enableStableTexture ? ((options.enableTextureOverride || fix.running) ? 'bg-blue-600/40 dark:bg-blue-500/30' : 'bg-blue-600 dark:bg-blue-500') : 'bg-zinc-200 dark:bg-zinc-700'"><span class="inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform duration-200 ease-in-out" :class="options.enableStableTexture ? 'translate-x-4' : 'translate-x-0'"></span></button>
                  </div>

                  <div @click="!fix.running && (options.enableFixAemeathMech = !options.enableFixAemeathMech)" class="cursor-pointer p-4 rounded-[10px] border border-zinc-200/80 dark:border-white/5 bg-white/50 dark:bg-[#101115]/50 transition-all hover:bg-zinc-50 dark:hover:bg-[#1a1b22] active:scale-[0.99] duration-200 flex gap-4 items-start" :class="{'pointer-events-none': fix.running}">
                    <div class="flex-1">
                      <div class="text-[13px] font-semibold text-zinc-800 dark:text-zinc-200">{{ $t('options.aemeath_mech') || 'Fix Aemeath Mech' }}</div>
                      <div class="text-[11px] text-zinc-500 mt-0.5 leading-relaxed">{{ $t('options.aemeath_mech_desc') || 'Fix abnormal model geometry for Aemeath Mech.' }}</div>
                    </div>
                    <button class="pointer-events-none relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out shadow-inner" :class="options.enableFixAemeathMech ? (fix.running ? 'bg-rose-600/40 dark:bg-rose-500/30' : 'bg-rose-600 dark:bg-rose-500') : 'bg-zinc-200 dark:bg-zinc-700'"><span class="inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform duration-200 ease-in-out" :class="options.enableFixAemeathMech ? 'translate-x-4' : 'translate-x-0'"></span></button>
                  </div>

                  <div id="aero-fix-card" @click="!fix.running && toggleAeroFixMode()" class="cursor-pointer p-4 rounded-[10px] border border-zinc-200/80 dark:border-white/5 bg-white/50 dark:bg-[#101115]/50 transition-all hover:bg-zinc-50 dark:hover:bg-[#1a1b22] active:scale-[0.99] duration-200" :class="{'pointer-events-none': fix.running}">
                    <div class="flex gap-4 items-start">
                      <div class="flex-1">
                        <div class="text-[13px] font-semibold text-zinc-800 dark:text-zinc-200">{{ $t('options.aero_eye') }}</div>
                        <div v-if="options.aeroFixMode > 0" class="text-[11px] text-rose-600 dark:text-rose-400 mt-0.5 font-medium">{{ $t('options.aero_eye_warn') }}</div>
                      </div>
                      <button class="pointer-events-none relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out shadow-inner" :class="options.aeroFixMode > 0 ? (fix.running ? 'bg-rose-600/40 dark:bg-rose-500/30' : 'bg-rose-600 dark:bg-rose-500') : 'bg-zinc-200 dark:bg-zinc-700'"><span class="inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform duration-200 ease-in-out" :class="options.aeroFixMode > 0 ? 'translate-x-4' : 'translate-x-0'"></span></button>
                    </div>
                    <div v-if="options.aeroFixMode > 0" @click.stop class="mt-3 animate-in fade-in duration-200">
                      <div class="flex p-1 bg-zinc-200/50 dark:bg-[#0a0b0d] rounded-lg border border-black/5 dark:border-white/5 shadow-inner">
                        <button @click="options.aeroFixMode = 1" class="flex-1 py-1.5 text-xs font-medium rounded-md transition-all" :class="options.aeroFixMode === 1 ? 'bg-white dark:bg-[#1f2128] shadow-sm ring-1 ring-black/5 dark:ring-white/5 text-zinc-900 dark:text-white' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'">{{ $t('options.aero_mode_1') }}</button>
                        <button @click="options.aeroFixMode = 2" class="flex-1 py-1.5 text-xs font-medium rounded-md transition-all" :class="options.aeroFixMode === 2 ? 'bg-white dark:bg-[#1f2128] shadow-sm ring-1 ring-black/5 dark:ring-white/5 text-zinc-900 dark:text-white' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'">{{ $t('options.aero_mode_2') }}</button>
                      </div>
                      <!-- Help tip for aero fix mode -->
                      <div class="mt-2.5 text-[10.5px] text-zinc-500 dark:text-zinc-400 font-normal leading-relaxed flex items-start gap-1.5">
                        <svg class="w-3.5 h-3.5 shrink-0 mt-[1px]" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        <span class="flex-1">{{ $t('options.aero_eye_tip') }}</span>
                      </div>
                    </div>
                  </div>
                </div>
                
                <!-- Bottom action button -->
                <div class="p-4 shrink-0 border-t border-zinc-200/80 dark:border-white/5 bg-zinc-50/50 dark:bg-[#101115]/30 rounded-b-xl">
                  <!-- Cancelling state -->
                  <button v-if="fix.isCancelling" disabled class="w-full relative overflow-hidden bg-amber-600 text-white font-medium py-3 rounded-[10px] shadow-[inset_0_1px_0_rgba(255,255,255,0.2),0_1px_2px_rgba(0,0,0,0.1)] cursor-not-allowed opacity-80 flex items-center justify-center gap-2">
                    <svg class="animate-spin h-5 w-5 text-white" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    {{ $t('app.cancelling') }}
                  </button>
                  
                  <!-- Running state -->
                  <button v-else-if="fix.running" @click="fix.cancelFix()" class="group w-full relative overflow-hidden bg-rose-600 text-white font-medium py-3 rounded-[10px] shadow-[inset_0_1px_0_rgba(255,255,255,0.2),0_1px_2px_rgba(0,0,0,0.1)] active:scale-[0.98] transition-all hover:bg-rose-500 duration-200 flex items-center justify-center gap-2">
                    <svg class="w-5 h-5 text-rose-200 group-hover:text-white transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"></path></svg>
                    {{ $t('app.stop_fix') }}
                  </button>
                  
                  <!-- Completed state -->
                  <button v-else-if="fixFinished" @click="fixFinished = false" class="group w-full relative overflow-hidden bg-emerald-600 dark:bg-emerald-600 text-white font-medium py-3 rounded-[10px] shadow-[inset_0_1px_0_rgba(255,255,255,0.2),0_1px_2px_rgba(0,0,0,0.1)] active:scale-[0.98] transition-all hover:bg-emerald-500 dark:hover:bg-emerald-500 duration-200 flex items-center justify-center gap-2">
                    <svg class="w-5 h-5 text-emerald-250 dark:text-emerald-200 group-hover:text-white transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"></path></svg>
                    {{ $t('app.fix_done') || 'Completed!' }}
                  </button>
                  
                  <!-- Idle state -->
                  <button v-else @click="startFix" :disabled="!settings.last_folder || update.status?.mandatory" :title="!settings.last_folder ? $t('app.click_to_select') : ''" class="group w-full relative overflow-hidden bg-[#0066ff] dark:bg-[#0a84ff] text-white font-medium py-3 rounded-[10px] shadow-[inset_0_1px_0_rgba(255,255,255,0.2),0_1px_2px_rgba(0,0,0,0.1)] active:scale-[0.98] transition-all hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100 disabled:bg-zinc-300 dark:disabled:bg-zinc-800 disabled:text-zinc-500 disabled:shadow-none duration-200 flex items-center justify-center gap-2">
                    <span class="relative z-10 flex justify-center items-center gap-1.5 tracking-wider text-sm font-semibold">
                      {{ update.status?.mandatory ? $t('update.mandatory_btn_text') || 'Update Required' : $t('app.start_fix') }}
                      <svg class="w-4 h-4 transform group-hover:translate-x-0.5 transition-transform duration-200 text-blue-200 dark:text-blue-200" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"></path>
                      </svg>
                    </span>
                  </button>

                </div>
              </div>
              
              <Rollback v-else @back="currentView = 'main'" />
            </Transition>
          </div>        </div>

        <!-- Right console panel -->
        <div class="w-full lg:flex-1 h-[40vh] min-h-[250px] lg:h-full shrink-0 lg:shrink min-h-0 min-w-0">
          <LogConsole :modPath="settings.last_folder" @config-updated="handleConfigUpdated" />
        </div>
      </main>
      
      <!-- Footer -->
      <footer class="mt-2 flex justify-between items-center text-xs text-zinc-500 dark:text-zinc-400 shrink-0 px-1.5 select-none">
        <!-- Status indicator & Version info -->
        <div class="flex items-center gap-3">
          <div class="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider">
            <span class="w-1.5 h-1.5 rounded-full" :class="[fix.running ? 'bg-sky-500 animate-pulse' : (fix.isCancelling ? 'bg-amber-500 animate-pulse' : 'bg-emerald-500')]"></span>
            <span class="text-zinc-500 dark:text-zinc-400 font-mono tracking-widest">{{ fix.running ? 'FIXING' : (fix.isCancelling ? 'CANCELLING' : 'READY') }}</span>
          </div>
          <span class="text-zinc-300 dark:text-zinc-800">|</span>
          <span class="text-[10px] font-mono text-zinc-400 dark:text-zinc-500 font-semibold">
            v{{ configMeta.app_version }} (cfg: {{ configMeta.version }})
          </span>
        </div>
        
        <div class="flex items-center gap-2.5">
          <!-- Support button -->
          <button @click="openSupport" class="group px-2.5 py-1 rounded-full border border-pink-400/20 dark:border-pink-500/20 bg-pink-500/5 text-pink-600 dark:text-pink-400 hover:bg-pink-500/15 dark:hover:bg-pink-500/25 hover:border-pink-400/40 dark:hover:border-pink-500/40 transition-all font-bold text-[10px] flex items-center gap-1 select-none">
            <svg class="w-3 h-3 group-hover:scale-110 transition-transform" fill="currentColor" viewBox="0 0 24 24"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"></path></svg>
            {{ $t('app.support') }}
          </button>

          <!-- Check Update button -->
          <button 
            @click="manualCheckUpdate" 
            :disabled="update.checking || showUpToDateFeedback"
            class="group px-2.5 py-1 rounded-full border transition-all font-bold text-[10px] flex items-center gap-1 active:scale-[0.97]"
            :class="[
              update.checking 
                ? 'border-zinc-200 dark:border-zinc-800 bg-zinc-100/50 dark:bg-zinc-900/50 text-zinc-400 dark:text-zinc-500 cursor-not-allowed'
                : showUpToDateFeedback
                  ? 'border-emerald-500 bg-emerald-500 text-white shadow-emerald-500/20'
                  : 'border-sky-400/30 dark:border-sky-500/30 bg-sky-500/5 text-sky-600 dark:text-sky-400 hover:bg-sky-500/15 dark:hover:bg-sky-500/25 hover:border-sky-400/50 dark:hover:border-sky-500/50'
            ]"
          >
            <svg v-if="update.checking" class="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <svg v-else-if="showUpToDateFeedback" class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"></path>
            </svg>
            <svg v-else class="w-3 h-3 group-hover:rotate-180 transition-transform duration-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
            </svg>
            <span>
              {{ 
                update.checking 
                  ? $t('update.checking') 
                  : showUpToDateFeedback 
                    ? $t('update.up_to_date') 
                    : $t('update.check') 
              }}
            </span>
          </button>

          <span class="text-zinc-300 dark:text-zinc-800">|</span>

          <!-- Language select -->
          <div class="flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"></path></svg>
            <select :value="locale" @change="changeLang" class="bg-transparent border-none outline-none font-bold cursor-pointer appearance-none text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white transition-colors text-[11px]">
              <option value="en" class="bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white">English</option>
              <option value="zh" class="bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white">简体中文</option>
              <option value="zh-Hant" class="bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white">繁體中文</option>
              <option value="ja" class="bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white">日本語</option>
              <option value="ko" class="bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white">한국어</option>
              <option value="ua" class="bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white">Українська</option>
            </select>
          </div>

          <span class="text-zinc-300 dark:text-zinc-800">|</span>

          <!-- GitHub button -->
          <button @click="openGithub" class="flex items-center justify-center w-6 h-6 hover:text-zinc-900 dark:hover:text-white transition-colors rounded hover:bg-zinc-200/60 dark:hover:bg-zinc-800/60" title="GitHub Repository">
            <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
          </button>
          
          <!-- Theme toggle button -->
          <button @click="toggleTheme" class="flex items-center justify-center w-6 h-6 hover:text-zinc-900 dark:hover:text-white transition-colors rounded hover:bg-zinc-200/60 dark:hover:bg-zinc-800/60" :title="$t('settings.theme')">
            <svg v-if="!settings.light_theme" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
            <svg v-else class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
          </button>
        </div>
      </footer>

    </div>
  </div>

  <UpdateModal />

  <!-- Toast notifications -->
  <div class="fixed top-12 right-4 z-[999] flex flex-col gap-2 pointer-events-none max-w-sm w-full px-4 select-none">
    <TransitionGroup name="toast" tag="div" class="flex flex-col gap-2 w-full items-end">
      <div v-for="t in toasts" :key="t.id" class="pointer-events-auto px-4 py-2.5 rounded-xl border border-zinc-200 dark:border-zinc-800 backdrop-blur-md shadow-lg flex items-center gap-2.5 animate-in slide-in-from-right duration-200 font-sans text-xs font-bold leading-none"
           :class="[
             t.type === 'success' 
               ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400 shadow-emerald-500/5'
               : t.type === 'error'
                 ? 'bg-rose-500/10 border-rose-500/20 text-rose-600 dark:text-rose-400 shadow-rose-500/5'
                 : 'bg-sky-500/10 border-sky-500/20 text-sky-600 dark:text-sky-400 shadow-sky-500/5'
           ]">
        <svg v-if="t.type === 'success'" class="w-4 h-4 text-emerald-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        <svg v-else-if="t.type === 'error'" class="w-4 h-4 text-rose-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        <svg v-else class="w-4 h-4 text-sky-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        <span class="truncate pr-1">{{ t.message }}</span>
      </div>
    </TransitionGroup>
  </div>
</template>