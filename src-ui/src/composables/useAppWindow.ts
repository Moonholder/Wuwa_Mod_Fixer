import { ref } from 'vue'
import { getCurrentWindow, PhysicalSize, PhysicalPosition } from '@tauri-apps/api/window'
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { useSettingsStore } from '../stores/settings'
import { useAppStore } from '../stores/app'

export function useAppWindow() {
  const settings = useSettingsStore()
  const app = useAppStore()
  const appWindow = getCurrentWindow()

  const os = ref('windows')
  const isMaximized = ref(false)
  let unlistenResize: UnlistenFn | null = null
  let unlistenEnter: UnlistenFn | null = null
  let unlistenLeave: UnlistenFn | null = null
  let unlistenDrop: UnlistenFn | null = null
  let unlistenConfig: UnlistenFn | null = null

  async function initWindow(onConfigReloaded?: () => Promise<void>) {
    try {
      os.value = await invoke<string>('get_os')
    } catch (e) {
      console.warn('Failed to retrieve OS', e)
    }

    try {
      isMaximized.value = await appWindow.isMaximized()
      unlistenResize = await appWindow.onResized(async () => {
        isMaximized.value = await appWindow.isMaximized()
      })
    } catch (e) {
      console.warn('Initialize window maximize state failed', e)
    }

    if (settings.window_width && settings.window_height) {
      try {
        await appWindow.setSize(new PhysicalSize(settings.window_width, settings.window_height))
        if (typeof settings.window_x === 'number' && typeof settings.window_y === 'number' && settings.window_x > -8000) {
          await appWindow.setPosition(new PhysicalPosition(settings.window_x, settings.window_y))
        }
      } catch (e) {
        console.warn('Restore window bounds failed', e)
      }
    }

    try {
      await appWindow.setFocus()
    } catch {}

    try {
      await appWindow.show()
    } catch {}

    // Encapsulate desktop drag & drop interactions
    try {
      unlistenEnter = await listen('tauri://drag-enter', () => {
        app.isDragging = true
      })
      unlistenLeave = await listen('tauri://drag-leave', () => {
        app.isDragging = false
      })
      unlistenDrop = await listen<{ paths: string[] }>('tauri://drag-drop', async (event) => {
        app.isDragging = false
        if (event.payload?.paths?.length > 0) {
          settings.last_folder = event.payload.paths[0]
          await settings.save()
          if (app.currentView !== 'main') {
            app.currentView = 'main'
          }
        }
      })
    } catch (e) {
      console.warn('Initialize drag-and-drop listener failed', e)
    }

    // Encapsulate background config reload event
    if (onConfigReloaded) {
      try {
        unlistenConfig = await listen('config:reloaded', async () => {
          await onConfigReloaded()
        })
      } catch (e) {
        console.warn('Initialize config reload listener failed', e)
      }
    }
  }

  function cleanupWindow() {
    if (unlistenResize) {
      unlistenResize()
      unlistenResize = null
    }
    if (unlistenEnter) {
      unlistenEnter()
      unlistenEnter = null
    }
    if (unlistenLeave) {
      unlistenLeave()
      unlistenLeave = null
    }
    if (unlistenDrop) {
      unlistenDrop()
      unlistenDrop = null
    }
    if (unlistenConfig) {
      unlistenConfig()
      unlistenConfig = null
    }
  }

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
    await appWindow.close()
  }

  async function winMinimize() {
    await appWindow.minimize()
  }

  async function winMaximize() {
    await appWindow.toggleMaximize()
  }

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

  return {
    os,
    isMaximized,
    initWindow,
    cleanupWindow,
    winClose,
    winMinimize,
    winMaximize,
    startWindowDrag,
  }
}
