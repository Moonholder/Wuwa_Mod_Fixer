<script setup lang="ts">
import { useAppWindow } from '../composables/useAppWindow'
import { useAppStore } from '../stores/app'

const isDev = import.meta.env.DEV
const app = useAppStore()
const { os, isMaximized, winMinimize, winMaximize, winClose, startWindowDrag } = useAppWindow()
</script>

<template>
  <div
    v-if="os !== 'linux'"
    @mousedown="startWindowDrag"
    @dblclick="winMaximize"
    data-tauri-drag-region
    class="h-8 w-full flex justify-between items-center pl-4 shrink-0 bg-white/80 dark:bg-[#12131a]/80 border-b border-zinc-250/85 dark:border-zinc-800/80 z-[150] select-none cursor-grab active:cursor-grabbing backdrop-blur-xl rounded-t-none"
    style="-webkit-app-region: drag;"
  >
    <div class="pointer-events-none flex items-center gap-2 select-none">
      <img src="/app-icon.png" class="w-4 h-4 object-contain" alt="Logo" />
      <span class="text-[11px] font-medium text-zinc-700 dark:text-zinc-300 h-4 flex items-center">
        Wuwa Mod Fixer
      </span>
      <span
        v-if="app.configMeta.build_tag"
        class="text-[9px] font-bold px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/25 uppercase tracking-wider scale-90 origin-left"
      >
        TEST {{ app.configMeta.build_tag }}
      </span>
      <span
        v-else-if="isDev"
        class="text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/25 uppercase tracking-wider scale-90 origin-left"
      >
        DEV
      </span>
    </div>

    <div class="flex h-full items-center" style="-webkit-app-region: no-drag;">
      <button
        @click="winMinimize"
        class="w-12 h-full flex justify-center items-center hover:bg-zinc-200/80 dark:hover:bg-zinc-800/80 text-zinc-500 transition-colors"
        title="Minimize"
      >
        <svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" d="M4 12h16" />
        </svg>
      </button>
      <button
        @click="winMaximize"
        class="w-12 h-full flex justify-center items-center hover:bg-zinc-200/80 dark:hover:bg-zinc-800/80 text-zinc-500 transition-colors"
        title="Maximize"
      >
        <svg v-if="!isMaximized" class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <rect x="4" y="4" width="16" height="16" />
        </svg>
        <svg v-else class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path d="M6 3h12v12" />
          <rect x="3" y="6" width="12" height="12" />
        </svg>
      </button>
      <button
        @click="winClose"
        class="w-12 h-full flex justify-center items-center hover:bg-[#e81123] hover:text-white text-zinc-500 transition-colors"
        title="Close"
      >
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  </div>
</template>
