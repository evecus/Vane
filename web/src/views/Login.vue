<template>
  <div class="min-h-screen flex items-center justify-center relative overflow-hidden"
       style="background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f64f59 100%)">

    <!-- Animated background blobs -->
    <div class="absolute inset-0 overflow-hidden pointer-events-none">
      <div class="blob blob-1"></div>
      <div class="blob blob-2"></div>
      <div class="blob blob-3"></div>
    </div>

    <!-- Grid overlay -->
    <div class="absolute inset-0 opacity-10"
         style="background-image: radial-gradient(circle, white 1px, transparent 1px); background-size: 40px 40px;"></div>

    <!-- Login card -->
    <div class="relative z-10 w-full max-w-sm px-4">
      <!-- Logo -->
      <div class="text-center mb-8">
        <div class="inline-flex items-center justify-center w-20 h-20 rounded-3xl bg-white/20 backdrop-blur-sm border border-white/30 mb-4 shadow-glass animate-float">
          <svg class="w-10 h-10 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z"/>
            <path d="M9.879 16.121A3 3 0 1012.015 11L11 14H9c0 .768.293 1.536.879 2.121z"/>
          </svg>
        </div>
        <h1 class="text-4xl font-bold text-white tracking-tight">Vane</h1>
        <p class="text-white/70 text-sm mt-1">Network Services Manager</p>
      </div>

      <!-- Card -->
      <div class="bg-white/15 backdrop-blur-xl rounded-3xl border border-white/25 p-8 shadow-glass">
        <h2 class="text-xl font-semibold text-white mb-6 text-center">Welcome back</h2>

        <form @submit.prevent="handleLogin" class="space-y-4">
          <div>
            <label class="block text-white/70 text-xs font-semibold uppercase tracking-wide mb-1.5">Username</label>
            <input v-model="form.username" type="text" placeholder="admin"
                   class="w-full px-4 py-3 rounded-xl bg-white/10 border border-white/20 text-white placeholder:text-white/40
                          focus:outline-none focus:ring-2 focus:ring-white/40 focus:bg-white/20 transition-all" />
          </div>
          <div>
            <label class="block text-white/70 text-xs font-semibold uppercase tracking-wide mb-1.5">Password</label>
            <input v-model="form.password" :type="showPass ? 'text' : 'password'" placeholder="••••••••"
                   class="w-full px-4 py-3 rounded-xl bg-white/10 border border-white/20 text-white placeholder:text-white/40
                          focus:outline-none focus:ring-2 focus:ring-white/40 focus:bg-white/20 transition-all" />
          </div>

          <div v-if="error" class="flex items-center gap-2 text-red-200 text-sm bg-red-500/20 rounded-xl px-3 py-2">
            <AlertCircle :size="14" />
            {{ error }}
          </div>

          <button type="submit" :disabled="loading"
                  class="w-full py-3.5 rounded-xl bg-white text-vane-600 font-semibold text-sm
                         hover:bg-white/90 active:scale-[0.98] transition-all duration-200
                         disabled:opacity-50 disabled:cursor-not-allowed mt-2 shadow-lg">
            <span v-if="!loading">Sign In →</span>
            <span v-else class="flex items-center justify-center gap-2">
              <Loader2 :size="16" class="animate-spin" /> Signing in...
            </span>
          </button>
        </form>

        <p class="text-white/40 text-xs text-center mt-6">
          Default: admin / vane1234
        </p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { AlertCircle, Loader2 } from 'lucide-vue-next'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const form = ref({ username: '', password: '' })
const error = ref('')
const loading = ref(false)
const showPass = ref(false)

async function handleLogin() {
  error.value = ''
  loading.value = true
  try {
    await auth.login(form.value.username, form.value.password)
  } catch (e) {
    error.value = e.response?.data?.error || 'Login failed'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.blob {
  position: absolute;
  border-radius: 50%;
  filter: blur(60px);
  opacity: 0.4;
  animation: blobFloat 8s ease-in-out infinite;
}
.blob-1 {
  width: 400px; height: 400px;
  background: rgba(255,100,100,0.4);
  top: -100px; left: -100px;
  animation-delay: 0s;
}
.blob-2 {
  width: 350px; height: 350px;
  background: rgba(100,150,255,0.4);
  bottom: -80px; right: -80px;
  animation-delay: -3s;
}
.blob-3 {
  width: 300px; height: 300px;
  background: rgba(200,100,255,0.3);
  top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  animation-delay: -5s;
}
@keyframes blobFloat {
  0%, 100% { transform: translate(0, 0) scale(1); }
  33%       { transform: translate(20px, -20px) scale(1.05); }
  66%       { transform: translate(-15px, 15px) scale(0.95); }
}
</style>
