import { defineStore } from 'pinia'
import { invoke } from '@tauri-apps/api/core'
import { i18n, SUPPORTED_LOCALES, type SupportedLocale } from '../i18n'

/**
 * the closest supported locale code.
 */
function mapLocale(raw: string): SupportedLocale {
  const normalized = raw.trim()
  if ((SUPPORTED_LOCALES as readonly string[]).includes(normalized)) {
    return normalized as SupportedLocale
  }
  // Language-region matching
  const upper = normalized.toUpperCase()
  if (upper.startsWith('ZH')) {
    if (upper.includes('TW') || upper.includes('HK') || upper.includes('HANT')) {
      return 'zh-Hant'
    }
    return 'zh'
  }
  if (upper.startsWith('JA')) return 'ja'
  if (upper.startsWith('KO')) return 'ko'
  if (upper.startsWith('UA') || upper.startsWith('UK')) return 'ua'
  return 'en'
}

export interface Settings {
  last_folder:    string | null
  light_theme:    boolean | null
  window_width:   number | null
  window_height:  number | null
  window_x:       number | null
  window_y:       number | null
  proxy_node:     string | null
  language:       string | null
}

export const useSettingsStore = defineStore('settings', {
  state: (): Settings => ({
    last_folder: null, light_theme: null,
    window_width: null, window_height: null,
    window_x: null, window_y: null,
    proxy_node: 'direct',
    language: null,
  }),

  actions: {
    async load() {
      const s = await invoke<Settings>('get_settings')
      Object.assign(this, s)
      if (this.language) {
        // @ts-ignore
        i18n.global.locale.value = this.language
      } else {
        // Ask the Rust backend for the system-detected locale
        // (uses sys_locale which reads the real OS setting)
        try {
          const detected = await invoke<string>('get_detected_locale')
          // @ts-ignore
          i18n.global.locale.value = mapLocale(detected)
        } catch {
          const navLang = navigator.language
          // @ts-ignore
          i18n.global.locale.value = mapLocale(navLang)
        }
      }
    },
    async save() {
      await invoke('save_settings', { settings: { ...this.$state } })
    },
    async setProxy(node: string) {
      this.proxy_node = node
      await this.save()
    },
    async setLanguage(lang: string) {
      this.language = lang
      // @ts-ignore
      i18n.global.locale.value = lang
      await this.save()
    }
  },
})
