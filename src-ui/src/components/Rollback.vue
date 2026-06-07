<script setup lang="ts">
import { ref, watch } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { useFixStore } from '../stores/fix'
import { useSettingsStore } from '../stores/settings'
import { useI18n } from 'vue-i18n'

const emit = defineEmits(['back'])
const fix = useFixStore()
const settings = useSettingsStore()
const { t } = useI18n()

interface BackupFile { original_path: string }
interface BackupGroup { group_key: string; files: BackupFile[] }

const backups = ref<BackupGroup[]>([])
const loading = ref(false)
const pendingRollback = ref<string | null>(null)

const backupSizeText = ref<string>('')
const backupCount = ref<number>(0)
const cleanLoading = ref(false)
const showCleanConfirm = ref(false)
const cleanConfirmInput = ref('')
const showAdvanced = ref(false)

watch(showCleanConfirm, (val) => {
  if (!val) cleanConfirmInput.value = ''
})

watch(showAdvanced, (val) => {
  if (!val) showCleanConfirm.value = false
})

async function loadBackupSize() {
  if (!settings.last_folder) {
    backupSizeText.value = ''
    backupCount.value = 0
    return
  }
  try {
    const [sizeBytes, count] = await invoke<[number, number]>('get_backup_size', { path: settings.last_folder })
    backupCount.value = count
    if (count === 0) {
      backupSizeText.value = ''
    } else {
      backupSizeText.value = sizeBytes > 1048576 
        ? `${(sizeBytes / 1048576).toFixed(1)} MB` 
        : `${(sizeBytes / 1024).toFixed(1)} KB`
    }
  } catch (e) {
    backupSizeText.value = ''
    backupCount.value = 0
  }
}

async function executeCleanBackups() {
  if (!settings.last_folder) return
  cleanLoading.value = true
  try {
    await invoke('clean_backups', { path: settings.last_folder });
    (window as any).showToast?.(t('rollback.clean_success') || 'Backup files cleaned successfully!', 'success')
    await refreshBackups()
  } catch (e) {
    (window as any).showToast?.(`Clean failed: ${e}`, 'error')
  } finally {
    cleanLoading.value = false
    showCleanConfirm.value = false
  }
}

async function refreshBackups() {
  pendingRollback.value = null
  showCleanConfirm.value = false
  if (!settings.last_folder) { backups.value = []; return }
  loading.value = true
  try {
    let res = await invoke<BackupGroup[]>('scan_backups', { path: settings.last_folder })
    backups.value = res.sort((a, b) => b.group_key.localeCompare(a.group_key))
    await loadBackupSize()
  } catch (e) {
    backups.value = []
  } finally {
    loading.value = false
  }
}

function formatGroupKey(key: string) {
  return key.replace(/(\d{2})-(\d{2})-(\d{2})$/, '$1:$2:$3')
}

async function executeRollback(group_key: string) {
  if (!settings.last_folder) return
  const targetKey = group_key === '__RESTORE_ALL__' && backups.value.length > 0 
    ? backups.value[backups.value.length - 1].group_key 
    : group_key

  try {
    pendingRollback.value = null
    fix.pushLog('INFO', `<< Reverting state to ${targetKey} ...`)
    await invoke('do_rollback', { path: settings.last_folder, groupKey: targetKey })
    fix.pushLog('INFO', '[OK] Rollback success.')
    await refreshBackups()
  } catch (e) { fix.pushLog('ERROR', `[ERR] Rollback failed: ${e}`) }
}

function groupFilesByDir(files: BackupFile[], basePath: string) {
  const map = new Map<string, string[]>()
  files.forEach(f => {
    let relPath = f.original_path.replace(basePath, '').replace(/^[\\\/]/, '')
    const parts = relPath.split(/[\\\/]/)
    const fileName = parts.pop() || ''
    const dirName = parts.length > 0 ? parts.join('/') : '.'
    if (!map.has(dirName)) map.set(dirName,[])
    map.get(dirName)!.push(fileName)
  })
  return map
}

watch(() => settings.last_folder, refreshBackups, { immediate: true })
</script>

<template>
  <div class="h-full flex flex-col bg-white dark:bg-zinc-900/50 relative select-none">

    <!-- Header Bar -->
    <div class="px-6 py-4 border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50/80 dark:bg-zinc-950/80 backdrop-blur-md flex justify-between items-center shrink-0">
      <h2 class="text-lg font-bold text-zinc-800 dark:text-zinc-100 flex items-center gap-2">
        <svg class="w-4 h-4 text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12.066 11.2a1 1 0 000 1.6l5.334 4A1 1 0 0019 16V8a1 1 0 00-1.6-.8l-5.334 4zM4.066 11.2a1 1 0 000 1.6l5.334 4A1 1 0 0011 16V8a1 1 0 00-1.6-.8l-5.334 4z"/></svg>
        {{ $t('rollback.title') || 'Rollback Manager' }}
      </h2>
      <button @click="emit('back')" class="px-3.5 py-1.5 bg-white dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 hover:border-zinc-300 dark:hover:border-zinc-600 text-zinc-700 dark:text-zinc-300 text-xs font-bold rounded-lg shadow-sm hover:bg-zinc-50 dark:hover:bg-zinc-700/50 transition-all duration-200 active:scale-[0.98]">
        &lt; {{ $t('app.back') || 'Back' }}
      </button>
    </div>

    <!-- Toolbar -->
    <div class="px-6 py-3 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between bg-white/50 dark:bg-zinc-900/30 shrink-0 gap-4">
      <button @click="refreshBackups" class="px-3.5 py-1.5 bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-300 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 shadow-sm active:scale-[0.98] shrink-0" :disabled="loading">
        <svg class="w-3.5 h-3.5" :class="{'animate-spin': loading}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
        {{ $t('rollback.refresh') || 'Refresh' }}
      </button>

      <!-- Backup volume info -->
      <div v-if="settings.last_folder && backupCount > 0" class="flex items-center gap-1.5 text-xs text-zinc-500 select-none">
        <svg class="w-3.5 h-3.5 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"/></svg>
        <span class="font-semibold">{{ $t('rollback.backup_size_label') || 'Backup Volume:' }}</span>
        <span class="font-mono text-zinc-700 dark:text-zinc-300 font-bold px-1.5 py-0.5 rounded border border-zinc-200 dark:border-zinc-700/60 bg-zinc-100 dark:bg-zinc-800 shadow-sm leading-none">{{ backupSizeText }}</span>
      </div>
    </div>

    <!-- Backup List -->
    <div class="flex-1 overflow-y-auto p-4 min-h-0 bg-zinc-50/30 dark:bg-zinc-950/30">
      <div v-if="loading" class="text-center text-zinc-400 py-10 animate-pulse text-sm font-medium">{{ $t('rollback.scanning') || 'Scanning file histories...' }}</div>

      <div v-else-if="backups.length === 0" class="flex flex-col items-center justify-center h-full text-zinc-400">
        <svg class="w-12 h-12 mb-4 opacity-20" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"></path></svg>
        <span class="font-medium text-xs">{{ $t('rollback.no_backups') || 'No backup files (.BAK) found in target folder' }}</span>
      </div>

      <div v-else class="space-y-4">
        <div v-for="(group, idx) in backups" :key="group.group_key" class="bg-white dark:bg-zinc-900 rounded-xl border shadow-sm overflow-hidden transition-all duration-300" :class="pendingRollback === group.group_key ? 'border-amber-400/50 dark:border-amber-500/50 ring-2 ring-amber-400/10' : 'border-zinc-200 dark:border-zinc-800/80'">
          <div class="p-4 flex flex-col gap-3">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2.5 border-b border-zinc-100 dark:border-zinc-800/60">
              <div class="flex flex-wrap items-center gap-1.5">
                <span class="font-mono text-[10px] font-bold text-sky-600 dark:text-sky-400 bg-sky-50 dark:bg-sky-950/40 px-2 py-0.5 rounded border border-sky-200/50 dark:border-sky-500/20 shadow-sm leading-relaxed">
                  {{ formatGroupKey(group.group_key) }}
                </span>
                <span class="text-[9px] font-bold px-1.5 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700/60 leading-none select-none">
                  {{ $t('rollback.file_count', { n: group.files.length }) || `${group.files.length} files` }}
                </span>
                <span v-if="idx === 0" class="px-1.5 py-0.5 bg-emerald-150 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 text-[9px] font-black rounded uppercase tracking-wider leading-none select-none border border-emerald-200/40 dark:border-emerald-500/10">
                  {{ $t('rollback.latest_state') || 'Latest' }}
                </span>
              </div>

              <div class="flex items-center gap-2 justify-end shrink-0 select-none">
                <div v-if="pendingRollback === group.group_key" class="flex gap-1.5">
                  <button @click="executeRollback(group.group_key)" class="px-3 py-1.5 bg-rose-500 hover:bg-rose-600 text-white rounded-lg text-xs font-bold transition-all shadow-sm active:scale-95">
                    {{ $t('rollback.confirm_restore') || 'Confirm' }}
                  </button>
                  <button @click="pendingRollback = null" class="px-3 py-1.5 bg-zinc-200 dark:bg-zinc-800 hover:bg-zinc-300 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-300 rounded-lg text-xs font-bold transition-all active:scale-95">
                    {{ $t('common.cancel') || 'Cancel' }}
                  </button>
                </div>
                <button v-else @click="pendingRollback = group.group_key" class="px-3 py-1.5 bg-sky-500 hover:bg-sky-600 text-white rounded-lg text-xs font-bold transition-all border border-sky-600 shadow-sm active:scale-95 flex items-center gap-1">
                  <svg class="w-3.5 h-3.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12.066 11.2a1 1 0 000 1.6l5.334 4A1 1 0 0019 16V8a1 1 0 00-1.6-.8l-5.334 4z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4.066 11.2a1 1 0 000 1.6l5.334 4A1 1 0 0011 16V8a1 1 0 00-1.6-.8l-5.334 4z"></path></svg>
                  {{ $t('rollback.restore') || 'Restore' }}
                </button>
              </div>
            </div>

            <!-- Files List -->
            <div class="bg-zinc-50 dark:bg-[#0c0c0e]/80 rounded-lg p-3 border border-zinc-100 dark:border-zinc-800/80 shadow-inner max-h-[150px] overflow-y-auto space-y-2.5">
              <div v-for="[dir, files] in groupFilesByDir(group.files, settings.last_folder || '')" :key="dir" class="text-[10px] font-mono leading-normal flex flex-col">
                <span class="text-sky-600 dark:text-sky-400 font-bold flex items-center gap-1 select-all break-all mb-0.5">
                  <svg class="w-3 h-3 shrink-0 text-sky-500/80" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg>
                  {{ dir }}/
                </span>
                <span class="text-zinc-500 dark:text-zinc-400 break-all pl-4 select-text leading-relaxed">
                  {{ files.join(', ') }}
                </span>
              </div>
            </div>

            <!-- Revert Warning Indicator -->
            <div v-if="pendingRollback === group.group_key" class="mt-0.5 bg-amber-500/5 dark:bg-amber-500/5 text-amber-600 dark:text-amber-400 text-[11px] p-2.5 rounded-lg border border-amber-500/20 dark:border-amber-500/10 flex items-start gap-2 animate-in slide-in-from-top-1 duration-200">
              <svg class="w-4 h-4 shrink-0 mt-0.5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
              <div class="font-bold leading-relaxed flex-1">
                {{ $t('rollback.warn_restore') || 'Will restore files to this state.' }}
                <span v-if="idx > 0" class="block mt-0.5 text-[9px] text-amber-500/90 dark:text-amber-400/80 font-medium">
                  {{ $t('rollback.warn_clean_newer', { n: idx }) || `(+${idx} newer backups will be cleaned)` }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Advanced / Destructive Operations (collapsed by default) -->
    <div class="shrink-0 border-t border-zinc-200 dark:border-zinc-800">
      <!-- Toggle Header -->
      <button
        @click="showAdvanced = !showAdvanced"
        class="w-full px-6 py-2.5 flex items-center gap-2 text-xs text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-900/40 transition-colors select-none"
      >
        <svg class="w-3 h-3 transition-transform duration-200" :class="showAdvanced ? 'rotate-90' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 5l7 7-7 7"/></svg>
        <span class="font-semibold">{{ $t('rollback.advanced') || 'Advanced' }}</span>
        <span class="ml-auto font-normal opacity-60 text-[10px]">{{ $t('rollback.advanced_hint') || 'Destructive operations' }}</span>
      </button>

      <!-- Advanced Panel -->
      <div v-if="showAdvanced" class="px-6 pb-5 pt-3 bg-zinc-50/60 dark:bg-zinc-950/40 space-y-3 animate-in slide-in-from-bottom-1 duration-150">

        <!-- Restore to Oldest -->
        <div class="flex items-start gap-3 p-3 rounded-lg border border-zinc-200 dark:border-zinc-800/80 bg-white dark:bg-zinc-900/60">
          <div class="flex-1 min-w-0">
            <p class="text-xs font-bold text-zinc-700 dark:text-zinc-200">{{ $t('rollback.restore_all') || 'Restore to Oldest Backup' }}</p>
            <p class="text-[10px] text-zinc-400 mt-0.5 leading-relaxed">{{ $t('rollback.restore_all_desc') || 'Reverts all files to the oldest recorded state and removes all intermediate backups.' }}</p>
          </div>
          <div v-if="backups.length > 0">
            <div v-if="pendingRollback === '__RESTORE_ALL__'" class="flex flex-col items-end gap-1.5">
              <span class="text-[10px] text-rose-500 font-bold">{{ $t('rollback.warn_delete_all', { n: backups.length }) || `All ${backups.length} backups will be removed` }}</span>
              <div class="flex gap-1.5">
                <button @click="executeRollback('__RESTORE_ALL__')" class="px-3 py-1 bg-rose-500 hover:bg-rose-600 text-white rounded-md text-[10px] font-bold transition-all shadow-sm active:scale-95">
                  {{ $t('common.confirm') || 'Confirm' }}
                </button>
                <button @click="pendingRollback = null" class="px-3 py-1 bg-zinc-200 dark:bg-zinc-700 hover:bg-zinc-300 dark:hover:bg-zinc-600 text-zinc-700 dark:text-zinc-300 rounded-md text-[10px] font-bold transition-all active:scale-95">
                  {{ $t('common.cancel') || 'Cancel' }}
                </button>
              </div>
            </div>
            <button v-else @click="pendingRollback = '__RESTORE_ALL__'" class="px-3 py-1.5 text-[11px] font-bold text-amber-600 dark:text-amber-400 border border-amber-400/40 rounded-lg hover:bg-amber-500/10 transition-colors active:scale-95">
              {{ $t('rollback.restore_all_action') || 'Restore...' }}
            </button>
          </div>
          <span v-else class="text-[10px] text-zinc-400 italic self-center">{{ $t('rollback.no_backups_short') || 'No backups' }}</span>
        </div>

        <!-- Delete All Backups -->
        <div class="flex items-start gap-3 p-3 rounded-lg border border-rose-200/50 dark:border-rose-900/40 bg-rose-50/40 dark:bg-rose-950/10">
          <div class="flex-1 min-w-0">
            <p class="text-xs font-bold text-zinc-700 dark:text-zinc-200">{{ $t('rollback.clean_backups') || 'Delete All Backup Files' }}</p>
            <p class="text-[10px] text-zinc-400 mt-0.5 leading-relaxed">{{ $t('rollback.clean_backups_desc') || 'Permanently removes all .BAK files from the target folder. This cannot be undone.' }}</p>
          </div>
          <div v-if="backupCount > 0">
            <div v-if="showCleanConfirm" class="flex flex-col items-end gap-1.5 animate-in fade-in duration-150">
              <span class="text-[10px] text-rose-500 font-bold">{{ $t('rollback.warn_clean') || 'Type WIPE to confirm:' }}</span>
              <div class="flex items-center gap-1.5">
                <input
                  type="text"
                  v-model="cleanConfirmInput"
                  placeholder="WIPE"
                  class="w-14 px-1.5 py-1 text-[10px] font-mono uppercase font-bold text-center border rounded-md bg-white dark:bg-zinc-900 border-zinc-300 dark:border-zinc-700 focus:outline-none focus:border-rose-500 transition-colors"
                />
                <button
                  @click="executeCleanBackups"
                  :disabled="cleanLoading || cleanConfirmInput.toUpperCase() !== 'WIPE'"
                  class="px-3 py-1 text-[10px] font-bold bg-rose-500 hover:bg-rose-600 disabled:bg-zinc-200 dark:disabled:bg-zinc-800 disabled:text-zinc-400 text-white rounded-md shadow-sm active:scale-95 transition-colors disabled:pointer-events-none"
                >
                  {{ $t('common.confirm') || 'Delete' }}
                </button>
                <button @click="showCleanConfirm = false" class="px-3 py-1 text-[10px] font-bold bg-zinc-200 dark:bg-zinc-800 hover:bg-zinc-300 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-300 rounded-md shadow-sm active:scale-95 transition-colors">
                  {{ $t('common.cancel') || 'Cancel' }}
                </button>
              </div>
            </div>
            <button v-else @click="showCleanConfirm = true" class="px-3 py-1.5 text-[11px] font-bold text-rose-600 dark:text-rose-400 border border-rose-400/40 rounded-lg hover:bg-rose-500/10 transition-colors active:scale-95">
              {{ $t('rollback.clean_action') || 'Delete...' }}
            </button>
          </div>
          <span v-else class="text-[10px] text-zinc-400 italic self-center">{{ $t('rollback.no_backups_short') || 'No backups' }}</span>
        </div>

      </div>
    </div>

  </div>
</template>