<template>
  <div class="min-h-screen flex items-center justify-center bg-white relative overflow-hidden">

    <!-- 极简装饰：右上角和左下角淡色圆 -->
    <div class="absolute -top-32 -right-32 w-96 h-96 rounded-full bg-slate-100 pointer-events-none"></div>
    <div class="absolute -bottom-24 -left-24 w-80 h-80 rounded-full bg-slate-50 pointer-events-none"></div>

    <!-- Lang toggle -->
    <button @click="i18n.toggle()"
            class="absolute top-4 right-4 text-slate-500 hover:text-slate-800 text-xs bg-slate-100 hover:bg-slate-200 px-3 py-1.5 rounded-full border border-slate-200 transition-all z-20">
      {{ i18n.t('switchLang') }}
    </button>

    <div class="relative z-10 w-full max-w-sm px-5 py-8">
      <div class="text-center mb-8">
        <div class="inline-flex items-center justify-center w-16 h-16 sm:w-20 sm:h-20 rounded-3xl bg-vane-600 mb-4 shadow-lg">
          <svg class="w-8 h-8 sm:w-10 sm:h-10 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z"/>
            <path d="M9.879 16.121A3 3 0 1012.015 11L11 14H9c0 .768.293 1.536.879 2.121z"/>
          </svg>
        </div>
        <h1 class="text-3xl sm:text-4xl font-bold text-slate-900 tracking-tight">Vane</h1>
      </div>

      <div class="bg-white/15 backdrop-blur-xl rounded-3xl border border-slate-200/60 p-6 sm:p-8 shadow-xl" style="background: rgba(120,100,200,0.08); backdrop-filter: blur(20px); border: 1px solid rgba(120,100,200,0.15);">
        <h2 class="text-lg sm:text-xl font-semibold text-slate-800 mb-5 text-center">{{ i18n.t('welcomeBack') }}</h2>

        <form @submit.prevent="handleLogin" class="space-y-4">
          <div>
            <label class="block text-slate-500 text-xs font-semibold uppercase tracking-wide mb-1.5">{{ i18n.t('username') }}</label>
            <input v-model="form.username" type="text" autocomplete="username"
                   class="w-full px-4 py-3 rounded-xl bg-slate-100/60 border border-slate-200/80 text-slate-900 placeholder:text-slate-400
                          focus:outline-none focus:ring-2 focus:ring-vane-400 focus:border-transparent transition-all text-base" />
          </div>
          <div>
            <label class="block text-slate-500 text-xs font-semibold uppercase tracking-wide mb-1.5">{{ i18n.t('password') }}</label>
            <div class="relative">
              <input v-model="form.password" :type="showPass ? 'text' : 'password'"
                     autocomplete="current-password"
                     class="w-full px-4 py-3 pr-11 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400
                            focus:outline-none focus:ring-2 focus:ring-vane-400 focus:border-transparent transition-all text-base" />
              <button type="button" @click="showPass=!showPass"
                      class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-1">
                <Eye v-if="!showPass" :size="16" />
                <EyeOff v-else :size="16" />
              </button>
            </div>
          </div>

          <div v-if="error" class="flex items-center gap-2 text-red-600 text-sm bg-red-50 rounded-xl px-3 py-2 border border-red-100">
            <AlertCircle :size="14" />{{ error }}
          </div>

          <button type="submit" :disabled="loading"
                  class="w-full py-3.5 rounded-xl bg-vane-600 text-white font-semibold text-sm
                         hover:bg-vane-700 active:scale-[0.98] transition-all duration-200
                         disabled:opacity-50 disabled:cursor-not-allowed mt-2 shadow-md">
            <span v-if="!loading">{{ i18n.t('signIn') }} →</span>
            <span v-else class="flex items-center justify-center gap-2">
              <Loader2 :size="16" class="animate-spin" /> {{ i18n.t('signingIn') }}
            </span>
          </button>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { AlertCircle, Loader2, Eye, EyeOff } from 'lucide-vue-next'
import { useAuthStore } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'

const auth = useAuthStore()
const i18n = useI18n()
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
    error.value = e.response?.data?.error || i18n.t('loginFailed')
  } finally {
    loading.value = false
  }
}
</script>
