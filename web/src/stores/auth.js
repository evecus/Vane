import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'
import router from '@/router'

// ── Axios instance ──────────────────────────────────────────────────────────
export const api = axios.create({ baseURL: '/api' })

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('vane_token')
  if (token) cfg.headers.Authorization = token
  return cfg
})

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('vane_token')
      router.push('/login')
    }
    return Promise.reject(err)
  }
)

// ── Auth store ──────────────────────────────────────────────────────────────
export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('vane_token') || '')

  async function login(username, password) {
    const { data } = await api.post('/login', { username, password })
    token.value = data.token
    localStorage.setItem('vane_token', data.token)
    router.push('/dashboard')
  }

  function logout() {
    api.post('/logout').catch(() => {})
    token.value = ''
    localStorage.removeItem('vane_token')
    router.push('/login')
  }

  return { token, login, logout }
})
