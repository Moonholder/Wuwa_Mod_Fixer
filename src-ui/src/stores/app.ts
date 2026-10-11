import { defineStore } from 'pinia'
import { invoke } from '@tauri-apps/api/core'
import { useSettingsStore } from './settings'
import { useFixStore } from './fix'
import { i18n } from '../i18n'

export interface ToastItem {
  id: number
  message: string
  type: 'success' | 'info' | 'error'
}

export interface ConfigMeta {
  version: string
  support_url_cn: string
  support_url_intl: string
  app_version: string
  build_tag: string | null
}

export interface FixOptionsState {
  enableTextureOverride: boolean
  enableStableTexture: boolean
  enableRendering33Fix: boolean
  enableFixAemeathMech: boolean
  aeroFixMode: number
}

let nextToastId = 0

export const useAppStore = defineStore('app', {
  state: () => ({
    currentView: 'main' as 'main' | 'rollback',
    isDragging: false,
    isPickingFolder: false,
    isChinaMainland: false,
    configMeta: {
      version: 'Loading...',
      support_url_cn: 'https://support.jix.de5.net',
      support_url_intl: 'https://ko-fi.com/moonholder',
      app_version: 'Loading...',
      build_tag: null as string | null,
    } as ConfigMeta,
    options: {
      enableTextureOverride: false,
      enableStableTexture: false,
      enableRendering33Fix: false,
      enableFixAemeathMech: false,
      aeroFixMode: 0,
    } as FixOptionsState,
    toasts: [] as ToastItem[],
  }),

  actions: {
    showToast(message: string, type: ToastItem['type'] = 'success') {
      const id = nextToastId++
      this.toasts.push({ id, message, type })
      setTimeout(() => {
        this.toasts = this.toasts.filter(t => t.id !== id)
      }, 3000)
    },

    async fetchConfigMeta() {
      try {
        this.configMeta = await invoke<ConfigMeta>('get_config_meta')
      } catch (e) {
        console.warn('Failed to fetch config meta', e)
      }
    },

    async detectMainland() {
      try {
        this.isChinaMainland = await invoke<boolean>('is_chinese_mainland')
      } catch (e) {
        console.warn('Failed to detect region', e)
      }
    },

    async pickFolder() {
      const settings = useSettingsStore()
      if (this.isPickingFolder) return
      this.isPickingFolder = true
      try {
        const path = await invoke<string | null>('pick_folder', {
          defaultPath: settings.last_folder || null,
        })
        if (path) {
          settings.last_folder = path
          await settings.save()
        }
      } catch (e) {
        console.error('Pick folder failed:', e)
      } finally {
        this.isPickingFolder = false
      }
    },

    openGithub() {
      invoke('open_url', { url: 'https://github.com/Moonholder/Wuwa_Mod_Fixer' })
    },

    openSupport() {
      const url = this.isChinaMainland
        ? this.configMeta.support_url_cn
        : this.configMeta.support_url_intl
      invoke('open_url', { url })
    },

    toggleTextureOverride() {
      if (this.options.enableStableTexture) return
      this.options.enableTextureOverride = !this.options.enableTextureOverride
    },

    toggleStableTexture() {
      if (this.options.enableTextureOverride) return
      this.options.enableStableTexture = !this.options.enableStableTexture
    },

    toggleFixAemeathMech() {
      this.options.enableFixAemeathMech = !this.options.enableFixAemeathMech
    },

    toggleRendering33Fix() {
      this.options.enableRendering33Fix = !this.options.enableRendering33Fix
      if (this.options.enableRendering33Fix) {
        setTimeout(() => {
          const el = document.getElementById('rendering-33-fix-card')
          if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
          }
        }, 120)
      }
    },

    toggleAeroFixMode() {
      if (this.options.aeroFixMode > 0) {
        this.options.aeroFixMode = 0
      } else {
        this.options.aeroFixMode = 1
        setTimeout(() => {
          const el = document.getElementById('aero-fix-card')
          if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
          }
        }, 120)
      }
    },

    setAeroFixMode(mode: number) {
      this.options.aeroFixMode = mode
    },

    async fetchAndPrintIntroLogs(force = false, currentLocale?: string) {
      const fix = useFixStore()
      if (!force && fix.logs.length > 0) return
      if (force) {
        fix.clearLogs()
      }
      const lang = currentLocale || (i18n.global.locale as any).value || 'en'
      try {
        const logs = await invoke<string[]>('get_intro_logs', { lang })
        const sections = logs
          .map(item => item?.trim())
          .filter((item): item is string => !!item && item.length > 0 && !item.endsWith('_note'))

        if (sections.length > 0) {
          const fullIntroMarkdown = sections.join('\n\n')
          fix.pushMarkdownLog(fullIntroMarkdown, 'INFO')
        }
        fix.pushLog('INFO', (i18n.global.t('app.ready') as string) || 'Ready...')
      } catch (e) {
        fix.pushLog('INFO', (i18n.global.t('app.ready') as string) || 'Ready...')
      }
    },
  },
})
