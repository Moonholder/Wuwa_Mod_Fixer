import { defineStore } from 'pinia'
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

export interface UpdateManifest {
  version:              string
  notes:                Record<string, string>
  pub_date:             string
  min_required_version: string
  platforms?:           Record<string, any>
}

export interface UpdateCheck {
  available:  boolean
  mandatory:  boolean
  manifest:   UpdateManifest | null
}

export const useUpdateStore = defineStore('update', {
  state: () => ({
    status:      null as UpdateCheck | null,
    downloading: false,
    checking:    false,
    dlProgress:  { downloaded: 0, total: 0 },
    proxyNode:   'direct' as string,
    activeNodeId: 'direct' as string, 
    showModal:   false,
  }),

  getters: {
    dlPct: (s) => s.dlProgress.total
      ? Math.round((s.dlProgress.downloaded / s.dlProgress.total) * 100)
      : 0,
    dlProgressMb: (s) => s.dlProgress.total
      ? `${(s.dlProgress.downloaded / 1048576).toFixed(1)} MB / ${(s.dlProgress.total / 1048576).toFixed(1)} MB`
      : '0 MB',
  },

  actions: {
    async checkUpdate(isManual = false): Promise<boolean> {
      if (this.checking) return false
      this.checking = true
      try {
        const res = await invoke<UpdateCheck>('check_update', { proxyNode: this.proxyNode })
        this.status = res
        
        if (res.available && res.manifest) {
          const ignoredVersion = localStorage.getItem('wuwa_fixer_ignored_version')
          // If it's an automatic check, matches ignored version, and is NOT mandatory, we don't show the modal.
          if (!isManual && res.manifest.version === ignoredVersion && !res.mandatory) {
            this.showModal = false
          } else {
            this.showModal = true
          }
        } else {
          this.showModal = false
        }
        return true
      } catch (e) {
        console.warn('Check update failed (network or timeout):', e)
        return false
      } finally {
        this.checking = false
      }
    },

    ignoreCurrentVersion() {
      if (this.status?.manifest?.version) {
        localStorage.setItem('wuwa_fixer_ignored_version', this.status.manifest.version)
      }
      this.status = null
      this.showModal = false
    },

    async downloadAndApply() {
      if (!this.status?.manifest) return
      
      this.downloading = true
      this.dlProgress = { downloaded: 0, total: 1 } 
      this.activeNodeId = this.proxyNode

      let unlisteners: UnlistenFn[] = []
      
      unlisteners.push(await listen<{ downloaded: number; total: number }>('updater:progress', (e) => {
        this.dlProgress = e.payload
      }))
      
      unlisteners.push(await listen<string>('updater:node_switch', (e) => {
        this.activeNodeId = e.payload
      }))

      try {
        await invoke('download_and_apply_update', {
          manifest: this.status.manifest,
          proxyNode: this.proxyNode,
        })
      } catch (e) {
        let errMsg = String(e)
        if (e && typeof e === 'object') {
          const errObj = e as Record<string, any>
          if ('kind' in errObj && 'message' in errObj) {
            errMsg = `${errObj.kind}: ${errObj.message}`
          } else {
            const keys = Object.keys(e)
            if (keys.length > 0) {
              errMsg = `${keys[0]}: ${(e as any)[keys[0]]}`
            } else {
              errMsg = JSON.stringify(e)
            }
          }
        }
        
        console.error('Update apply error:', errMsg)
        alert(`Update Failed / 更新失败:\n${errMsg}`)
      } finally {
        this.downloading = false
        unlisteners.forEach(fn => fn())
      }
    },
  },
})