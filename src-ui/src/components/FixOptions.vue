<script setup lang="ts">
import { useAppStore } from '../stores/app'
import { useFixStore } from '../stores/fix'

const app = useAppStore()
const fix = useFixStore()
</script>

<template>
  <div class="flex-1 overflow-y-auto p-4 space-y-3">
    <!-- Derived Hashes -->
    <div
      @click="!fix.running && app.toggleTextureOverride()"
      class="cursor-pointer p-4 rounded-[10px] border border-zinc-200/80 dark:border-white/5 bg-white/50 dark:bg-[#101115]/50 transition-all hover:bg-zinc-50 dark:hover:bg-[#1a1b22] active:scale-[0.99] duration-200 flex gap-4 items-start"
      :class="{ 'opacity-50 pointer-events-none': app.options.enableStableTexture || fix.running }"
    >
      <div class="flex-1">
        <div class="text-[13px] font-semibold text-zinc-800 dark:text-zinc-200">
          {{ $t('options.derived_hashes') }}
        </div>
        <div class="text-[11px] text-zinc-500 mt-0.5 leading-relaxed">
          {{ $t('options.derived_hashes_desc') }}
        </div>
      </div>
      <button
        class="pointer-events-none relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out shadow-inner"
        :class="app.options.enableTextureOverride ? ((app.options.enableStableTexture || fix.running) ? 'bg-blue-600/40 dark:bg-blue-500/30' : 'bg-blue-600 dark:bg-blue-500') : 'bg-zinc-200 dark:bg-zinc-700'"
      >
        <span
          class="inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform duration-200 ease-in-out"
          :class="app.options.enableTextureOverride ? 'translate-x-4' : 'translate-x-0'"
        />
      </button>
    </div>

    <!-- Stable Texture -->
    <div
      @click="!fix.running && app.toggleStableTexture()"
      class="cursor-pointer p-4 rounded-[10px] border border-zinc-200/80 dark:border-white/5 bg-white/50 dark:bg-[#101115]/50 transition-all hover:bg-zinc-50 dark:hover:bg-[#1a1b22] active:scale-[0.99] duration-200 flex gap-4 items-start"
      :class="{ 'opacity-50 pointer-events-none': app.options.enableTextureOverride || fix.running }"
    >
      <div class="flex-1">
        <div class="text-[13px] font-semibold text-zinc-800 dark:text-zinc-200">
          {{ $t('options.stable_texture') }}
        </div>
        <div class="text-[11px] text-zinc-500 mt-0.5 leading-relaxed">
          {{ $t('options.stable_texture_desc') }}
        </div>
      </div>
      <button
        class="pointer-events-none relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out shadow-inner"
        :class="app.options.enableStableTexture ? ((app.options.enableTextureOverride || fix.running) ? 'bg-blue-600/40 dark:bg-blue-500/30' : 'bg-blue-600 dark:bg-blue-500') : 'bg-zinc-200 dark:bg-zinc-700'"
      >
        <span
          class="inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform duration-200 ease-in-out"
          :class="app.options.enableStableTexture ? 'translate-x-4' : 'translate-x-0'"
        />
      </button>
    </div>

    <!-- Rendering 3.3 -->
    <div
      id="rendering-33-fix-card"
      @click="!fix.running && app.toggleRendering33Fix()"
      class="cursor-pointer p-4 rounded-[10px] border border-zinc-200/80 dark:border-white/5 bg-white/50 dark:bg-[#101115]/50 transition-all hover:bg-zinc-50 dark:hover:bg-[#1a1b22] active:scale-[0.99] duration-200 select-none"
      :class="{ 'pointer-events-none opacity-60': fix.running }"
    >
      <div class="flex gap-4 items-start">
        <div class="flex-1">
          <div class="text-[13px] font-semibold text-zinc-800 dark:text-zinc-200">
            {{ $t('options.rendering_3_3') }}
          </div>
          <div v-if="app.options.enableRendering33Fix" class="text-[11px] text-amber-600 dark:text-amber-400 mt-0.5 font-medium leading-tight">
            {{ $t('options.rendering_3_3_warn') }}
          </div>
        </div>

        <button
          class="pointer-events-none relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out shadow-inner mt-0.5"
          :class="app.options.enableRendering33Fix ? (fix.running ? 'bg-amber-600/40 dark:bg-amber-500/30' : 'bg-amber-500 dark:bg-amber-500') : 'bg-zinc-200 dark:bg-zinc-700'"
        >
          <span
            class="inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform duration-200 ease-in-out"
            :class="app.options.enableRendering33Fix ? 'translate-x-4' : 'translate-x-0'"
          />
        </button>
      </div>

      <div v-if="app.options.enableRendering33Fix" @click.stop class="mt-3 animate-in fade-in duration-200">
        <div class="pt-2.5 border-t border-zinc-100 dark:border-white/5 text-[10.5px] text-zinc-500 dark:text-zinc-400 font-normal leading-relaxed flex items-start gap-1.5">
          <svg class="w-3.5 h-3.5 shrink-0 mt-[1px] text-amber-500/80" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span class="flex-1">
            {{ $t('options.rendering_3_3_desc') }}
          </span>
        </div>
      </div>
    </div>

    <!-- Fix Aemeath Mech -->
    <div
      @click="!fix.running && app.toggleFixAemeathMech()"
      class="cursor-pointer p-4 rounded-[10px] border border-zinc-200/80 dark:border-white/5 bg-white/50 dark:bg-[#101115]/50 transition-all hover:bg-zinc-50 dark:hover:bg-[#1a1b22] active:scale-[0.99] duration-200 flex gap-4 items-start"
      :class="{ 'pointer-events-none': fix.running }"
    >
      <div class="flex-1">
        <div class="text-[13px] font-semibold text-zinc-800 dark:text-zinc-200">
          {{ $t('options.aemeath_mech') || 'Fix Aemeath Mech' }}
        </div>
        <div class="text-[11px] text-zinc-500 mt-0.5 leading-relaxed">
          {{ $t('options.aemeath_mech_desc') || 'Fix abnormal model geometry for Aemeath Mech.' }}
        </div>
      </div>
      <button
        class="pointer-events-none relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out shadow-inner"
        :class="app.options.enableFixAemeathMech ? (fix.running ? 'bg-rose-600/40 dark:bg-rose-500/30' : 'bg-rose-600 dark:bg-rose-500') : 'bg-zinc-200 dark:bg-zinc-700'"
      >
        <span
          class="inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform duration-200 ease-in-out"
          :class="app.options.enableFixAemeathMech ? 'translate-x-4' : 'translate-x-0'"
        />
      </button>
    </div>

    <!-- Aero Eye Fix -->
    <div
      id="aero-fix-card"
      @click="!fix.running && app.toggleAeroFixMode()"
      class="cursor-pointer p-4 rounded-[10px] border border-zinc-200/80 dark:border-white/5 bg-white/50 dark:bg-[#101115]/50 transition-all hover:bg-zinc-50 dark:hover:bg-[#1a1b22] active:scale-[0.99] duration-200"
      :class="{ 'pointer-events-none': fix.running }"
    >
      <div class="flex gap-4 items-start">
        <div class="flex-1">
          <div class="text-[13px] font-semibold text-zinc-800 dark:text-zinc-200">
            {{ $t('options.aero_eye') }}
          </div>
          <div v-if="app.options.aeroFixMode > 0" class="text-[11px] text-rose-600 dark:text-rose-400 mt-0.5 font-medium">
            {{ $t('options.aero_eye_warn') }}
          </div>
        </div>
        <button
          class="pointer-events-none relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out shadow-inner"
          :class="app.options.aeroFixMode > 0 ? (fix.running ? 'bg-rose-600/40 dark:bg-rose-500/30' : 'bg-rose-600 dark:bg-rose-500') : 'bg-zinc-200 dark:bg-zinc-700'"
        >
          <span
            class="inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform duration-200 ease-in-out"
            :class="app.options.aeroFixMode > 0 ? 'translate-x-4' : 'translate-x-0'"
          />
        </button>
      </div>

      <div v-if="app.options.aeroFixMode > 0" @click.stop class="mt-3 animate-in fade-in duration-200">
        <div class="flex p-1 bg-zinc-200/50 dark:bg-[#0a0b0d] rounded-lg border border-black/5 dark:border-white/5 shadow-inner">
          <button
            @click="app.setAeroFixMode(1)"
            class="flex-1 py-1.5 text-xs font-medium rounded-md transition-all"
            :class="app.options.aeroFixMode === 1 ? 'bg-white dark:bg-[#1f2128] shadow-sm ring-1 ring-black/5 dark:ring-white/5 text-zinc-900 dark:text-white' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'"
          >
            {{ $t('options.aero_mode_1') }}
          </button>
          <button
            @click="app.setAeroFixMode(2)"
            class="flex-1 py-1.5 text-xs font-medium rounded-md transition-all"
            :class="app.options.aeroFixMode === 2 ? 'bg-white dark:bg-[#1f2128] shadow-sm ring-1 ring-black/5 dark:ring-white/5 text-zinc-900 dark:text-white' : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'"
          >
            {{ $t('options.aero_mode_2') }}
          </button>
        </div>

        <div class="mt-2.5 text-[10.5px] text-zinc-500 dark:text-zinc-400 font-normal leading-relaxed flex items-start gap-1.5">
          <svg class="w-3.5 h-3.5 shrink-0 mt-[1px]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span class="flex-1">{{ $t('options.aero_eye_tip') }}</span>
        </div>
      </div>
    </div>
  </div>
</template>
