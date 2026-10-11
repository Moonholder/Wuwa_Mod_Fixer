<script setup lang="ts">
import { useSettingsStore } from '../stores/settings'
import { useFixStore } from '../stores/fix'
import { useAppStore } from '../stores/app'

const settings = useSettingsStore()
const fix = useFixStore()
const app = useAppStore()
</script>

<template>
  <div class="p-4 border-b border-zinc-200/80 dark:border-white/5 shrink-0">
    <h3 class="text-[11px] font-bold text-zinc-400 uppercase tracking-widest mb-2.5 flex justify-between items-center select-none">
      <span>{{ $t('app.target_folder') }}</span>
      <span class="text-[9px] font-bold text-zinc-500 dark:text-zinc-400 border border-zinc-200/80 dark:border-white/10 bg-zinc-50 dark:bg-white/5 px-1.5 py-0.5 rounded flex items-center gap-1 shadow-sm shrink-0">
        <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2.5"
            d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
          />
        </svg>
        {{ $t('app.drag_and_drop') }}
      </span>
    </h3>

    <div
      class="group relative flex items-center bg-zinc-50 dark:bg-[#0a0b0d] hover:bg-zinc-100 dark:hover:bg-[#121318] transition-all duration-200 rounded-[10px] border p-3 pl-4 cursor-pointer shadow-sm active:scale-[0.995]"
      :class="[
        app.isDragging
          ? 'border-sky-500 dark:border-sky-400 ring-2 ring-sky-500/30 bg-sky-50/80 dark:bg-sky-500/10 shadow-[0_0_16px_rgba(56,189,248,0.2)]'
          : (settings.last_folder
              ? 'border-zinc-200/80 dark:border-white/10 ring-1 ring-black/5 dark:ring-0'
              : 'border-dashed border-blue-500/50 dark:border-blue-500/40 hover:border-blue-500 dark:hover:border-blue-400 shadow-[0_0_12px_rgba(59,130,246,0.08)] dark:shadow-[0_0_12px_rgba(10,132,255,0.05)]'),
        fix.running ? 'opacity-50 pointer-events-none' : ''
      ]"
      @click="!fix.running && app.pickFolder()"
    >
      <!-- Path tooltip -->
      <div
        v-if="settings.last_folder"
        class="absolute top-full left-1/2 -translate-x-1/2 mt-2 px-3 py-1.5 bg-zinc-950/95 dark:bg-zinc-900/95 backdrop-blur border border-zinc-800 text-white text-[11px] font-mono rounded-lg shadow-lg opacity-0 group-hover:opacity-100 pointer-events-none transition-all duration-200 z-50 whitespace-normal max-w-[280px] break-all leading-relaxed shadow-sky-500/5"
      >
        <div class="font-sans font-bold text-zinc-400 mb-0.5 text-[9px] uppercase tracking-wider select-none">
          {{ $t('app.selected_path') }}
        </div>
        {{ settings.last_folder }}
      </div>

      <div
        class="w-9 h-9 rounded-lg flex items-center justify-center transition-all shadow-sm shrink-0"
        :class="[
          app.isDragging
            ? 'bg-sky-500 text-white shadow-sky-500/40 scale-105'
            : (settings.last_folder
                ? 'bg-sky-100 dark:bg-sky-900/30 text-sky-500 dark:text-sky-400'
                : 'bg-blue-50 dark:bg-blue-950/40 text-blue-500 dark:text-blue-400 group-hover:bg-blue-100 dark:group-hover:bg-blue-900/50')
        ]"
      >
        <svg class="w-4.5 h-4.5 flex-shrink-0 transition-transform group-hover:scale-110 duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
      </div>

      <div class="ml-3 flex-1 min-w-0 pr-6 flex flex-col justify-center">
          <div class="text-[9px] text-zinc-400 font-bold uppercase tracking-wider mb-0.5 leading-none select-none">
            {{ settings.last_folder ? $t('app.selected_path') : $t('app.click_to_select') }}
          </div>
          <div
            class="text-xs truncate font-mono font-bold text-zinc-700 dark:text-zinc-300"
            :class="{ 'text-zinc-400 dark:text-zinc-500 italic font-normal': !settings.last_folder }"
          >
            {{ settings.last_folder || $t('app.no_folder_selected') }}
          </div>
        </div>

        <!-- Right arrow indicator -->
        <div class="absolute right-4 top-1/2 -translate-y-1/2 text-zinc-400 group-hover:text-zinc-600 dark:group-hover:text-zinc-200 transition-colors">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 5l7 7-7 7" />
          </svg>
        </div>
      </div>
    </div>
  </template>
