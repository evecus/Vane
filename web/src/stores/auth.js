import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import router from '@/router'
import { useUiStore } from '@/stores/ui'

export const api = axios.create({
  baseURL: '/api',
  withCredentials: true,
})

api.interceptors.request.use(cfg => {
  const ui = useUiStore()
  if (!cfg.silentUI) {
    ui.beginLoading()
  }
  return cfg
})

api.interceptors.response.use(
  r => {
    const ui = useUiStore()
    if (!r.config?.silentUI) {
      ui.endLoading()
    }
    return r
  },
  err => {
    const ui = useUiStore()
    if (!err.config?.silentUI) {
      ui.endLoading()
    }

    if (err.response?.status === 401) {
      const auth = useAuthStore()
      auth.markUnauthenticated()
      if (router.currentRoute.value.name !== 'login') {
        router.push('/login')
      }
    } else {
      const message = err.response?.data?.error || err.message || 'Request failed'
      ui.showError(message)
    }
    return Promise.reject(err)
  }
)

export const useAuthStore = defineStore('auth', () => {
  const authenticated = ref(false)
  const checked = ref(false)
  let checkingPromise = null

  async function ensureSession() {
    if (checked.value) return authenticated.value
    if (checkingPromise) return checkingPromise

    checkingPromise = api.get('/session', { silentUI: true })
      .then(() => {
        authenticated.value = true
        checked.value = true
        return true
      })
      .catch(() => {
        authenticated.value = false
        checked.value = true
        return false
      })
      .finally(() => {
        checkingPromise = null
      })

    return checkingPromise
  }

  function markUnauthenticated() {
    authenticated.value = false
    checked.value = true
  }

  async function login(username, password) {
    await api.post('/login', { username, password })
    authenticated.value = true
    checked.value = true
    router.push('/dashboard')
  }

  function logout() {
    api.post('/logout').catch(() => {})
    markUnauthenticated()
    router.push('/login')
  }

  return { authenticated, ensureSession, markUnauthenticated, login, logout }
})
