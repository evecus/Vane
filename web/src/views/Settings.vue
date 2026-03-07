<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ i18n.t('systemSettings') }}</h1>
        <p class="page-subtitle">{{ i18n.t('systemSettingsDesc') }}</p>
      </div>
    </div>

    <div class="grid grid-cols-1 xl:grid-cols-2 gap-6">
      <!-- Left column -->
      <div class="space-y-6">
        <!-- Account Security -->
        <section class="glass-card overflow-hidden">
          <div class="flex items-center gap-3 px-6 py-4 border-b border-slate-100 bg-slate-50/50">
            <div class="w-8 h-8 rounded-lg bg-vane-100 flex items-center justify-center">
              <User :size="15" class="text-vane-600" />
            </div>
            <div>
              <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('accountSecurity') }}</h3>
              <p class="text-xs text-slate-400">{{ i18n.t('accountSecurityDesc') }}</p>
            </div>
          </div>
          <div class="p-6 space-y-5">
            <div>
              <label class="input-label">{{ i18n.t('username') }}</label>
              <input v-model="form.username" class="input" autocomplete="username" />
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="input-label">{{ i18n.t('newPassword') }}</label>
                <div class="relative">
                  <input v-model="form.new_password"
                         :type="showPwd ? 'text' : 'password'"
                         class="input pr-10" :placeholder="i18n.t('passwordPlaceholder')"
                         autocomplete="new-password" />
                  <button type="button" @click="showPwd=!showPwd"
                          class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                    <Eye v-if="!showPwd" :size="15" /><EyeOff v-else :size="15" />
                  </button>
                </div>
              </div>
              <div>
                <label class="input-label">{{ i18n.t('confirmPassword') }}</label>
                <input v-model="form.confirm_password"
                       :type="showPwd ? 'text' : 'password'"
                       class="input" :placeholder="i18n.t('confirmPlaceholder')"
                       autocomplete="new-password" />
              </div>
            </div>
            <!-- Password strength -->
            <div v-if="form.new_password" class="flex items-center gap-2">
              <div class="flex gap-1">
                <div v-for="i in 4" :key="i"
                     class="h-1.5 w-8 rounded-full transition-colors duration-300"
                     :class="pwdStrength >= i ? pwdStrengthColor : 'bg-slate-200'"></div>
              </div>
              <span class="text-xs" :class="pwdStrength >= 3 ? 'text-emerald-600' : 'text-amber-600'">
                {{ pwdStrengthLabel }}
              </span>
            </div>
          </div>
        </section>

        <!-- System Config -->
        <section class="glass-card overflow-hidden">
          <div class="flex items-center gap-3 px-6 py-4 border-b border-slate-100 bg-slate-50/50">
            <div class="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center">
              <Settings2 :size="15" class="text-slate-600" />
            </div>
            <div>
              <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('sysConfig') }}</h3>
              <p class="text-xs text-slate-400">{{ i18n.t('sysConfigDesc') }}</p>
            </div>
          </div>
          <div class="p-6 space-y-5">
            <div>
              <label class="input-label">{{ i18n.t('adminPortLabel') }}</label>
              <input v-model.number="form.port" type="number" min="1" max="65535" class="input max-w-xs" />
              <p class="text-xs text-slate-400 mt-1.5 flex items-center gap-1">
                <AlertTriangle :size="11" class="text-amber-400" />{{ i18n.t('portRestartHint') }}
              </p>
            </div>
            <div>
              <label class="input-label">{{ i18n.t('safeEntry') }}</label>
              <div class="flex items-stretch gap-0 max-w-sm rounded-xl overflow-hidden border border-slate-200 focus-within:ring-2 focus-within:ring-vane-400 focus-within:border-transparent bg-slate-50">
                <span class="flex items-center px-3 text-xs text-slate-400 bg-slate-100 border-r border-slate-200 whitespace-nowrap select-none">:{{ form.port }}/</span>
                <input v-model="form.safe_entry" class="flex-1 px-3 py-2.5 text-sm bg-transparent focus:outline-none font-mono"
                       :placeholder="i18n.t('safeEntryPlaceholder')" />
              </div>
              <p class="text-xs text-slate-400 mt-1.5">
                {{ i18n.t('safeEntryHint1') }}
                <code class="bg-slate-100 px-1.5 py-0.5 rounded text-slate-700 font-mono mx-1">:{{ form.port }}/{{ form.safe_entry || '…' }}</code>
                {{ i18n.t('safeEntryHint2') }}
              </p>
              <div v-if="form.safe_entry" class="flex items-center gap-1.5 text-xs text-amber-600 mt-1">
                <AlertTriangle :size="11" />{{ i18n.t('safeEntryWarn') }}
              </div>
            </div>
          </div>
        </section>

        <!-- Feedback + Save -->
        <div v-if="saved" class="flex items-center gap-2 text-emerald-700 bg-emerald-50 px-4 py-3 rounded-xl border border-emerald-200 text-sm">
          <CheckCircle :size="15" /> {{ i18n.t('settingsSaved') }}
        </div>
        <div v-if="saveError" class="flex items-center gap-2 text-red-600 bg-red-50 px-4 py-3 rounded-xl border border-red-200 text-sm">
          <AlertCircle :size="15" /> {{ saveError }}
        </div>
        <button class="btn-primary" @click="save" :disabled="saving">
          <Save :size="15" /> {{ saving ? i18n.t('saving') : i18n.t('saveSettings') }}
        </button>
      </div>

      <!-- Right column -->
      <div class="space-y-6">
        <!-- Backup & Restore -->
        <section class="glass-card overflow-hidden">
          <div class="flex items-center gap-3 px-6 py-4 border-b border-slate-100 bg-slate-50/50">
            <div class="w-8 h-8 rounded-lg bg-emerald-50 flex items-center justify-center">
              <HardDrive :size="15" class="text-emerald-600" />
            </div>
            <div>
              <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('backupRestore') }}</h3>
              <p class="text-xs text-slate-400">{{ i18n.t('backupRestoreDesc') }}</p>
            </div>
          </div>
          <div class="p-6 space-y-4">
            <div class="grid grid-cols-1 gap-4">
              <div class="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
                <div class="flex items-center gap-2">
                  <Download :size="15" class="text-slate-500" />
                  <span class="text-sm font-medium text-slate-700">{{ i18n.t('backupTitle') }}</span>
                </div>
                <p class="text-xs text-slate-400">{{ i18n.t('backupDesc') }}</p>
                <button class="btn-secondary btn-sm w-full justify-center" @click="backup">
                  <Download :size="13" /> {{ i18n.t('downloadBackup') }}
                </button>
              </div>
              <div class="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
                <div class="flex items-center gap-2">
                  <Upload :size="15" class="text-slate-500" />
                  <span class="text-sm font-medium text-slate-700">{{ i18n.t('restoreTitle') }}</span>
                </div>
                <p class="text-xs text-slate-400">{{ i18n.t('restoreDesc') }}</p>
                <label class="btn btn-secondary btn-sm w-full justify-center cursor-pointer">
                  <Upload :size="13" /> {{ i18n.t('selectBackup') }}
                  <input type="file" accept=".enc,.json" class="hidden" @change="restore" />
                </label>
              </div>
            </div>
            <div v-if="restoreMsg" class="flex items-center gap-2 text-emerald-700 bg-emerald-50 px-4 py-3 rounded-xl border border-emerald-200 text-sm">
              <CheckCircle :size="14" /> {{ restoreMsg }}
            </div>
            <div v-if="restoreError" class="flex items-center gap-2 text-red-600 bg-red-50 px-4 py-3 rounded-xl border border-red-200 text-sm">
              <AlertCircle :size="14" /> {{ restoreError }}
            </div>
          </div>
        </section>

        <!-- Language -->
        <section class="glass-card overflow-hidden">
          <div class="flex items-center gap-3 px-6 py-4 border-b border-slate-100 bg-slate-50/50">
            <div class="w-8 h-8 rounded-lg bg-blue-50 flex items-center justify-center">
              <Languages :size="15" class="text-blue-500" />
            </div>
            <div>
              <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('language') }}</h3>
            </div>
          </div>
          <div class="p-6">
            <div class="grid grid-cols-2 gap-3">
              <button @click="setLang('zh')"
                      :class="['p-3 rounded-xl border-2 text-left transition-all', i18n.locale === 'zh' ? 'border-vane-500 bg-vane-50' : 'border-slate-200 hover:border-vane-300']">
                <div class="font-semibold text-sm">🇨🇳 中文</div>
                <div class="text-xs text-slate-400 mt-0.5">简体中文</div>
              </button>
              <button @click="setLang('en')"
                      :class="['p-3 rounded-xl border-2 text-left transition-all', i18n.locale === 'en' ? 'border-vane-500 bg-vane-50' : 'border-slate-200 hover:border-vane-300']">
                <div class="font-semibold text-sm">🇺🇸 English</div>
                <div class="text-xs text-slate-400 mt-0.5">English (US)</div>
              </button>
            </div>
          </div>
        </section>

        <!-- About -->
        <section class="glass-card overflow-hidden">
          <div class="flex items-center gap-3 px-6 py-4 border-b border-slate-100 bg-slate-50/50">
            <div class="w-8 h-8 rounded-lg bg-purple-50 flex items-center justify-center">
              <Info :size="15" class="text-purple-500" />
            </div>
            <div>
              <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('aboutVane') }}</h3>
              <p class="text-xs text-slate-400">{{ i18n.t('aboutDesc') }}</p>
            </div>
          </div>
          <div class="p-6">
            <div class="grid grid-cols-2 gap-x-8 gap-y-3 text-sm">
              <div class="flex justify-between">
                <span class="text-slate-500">{{ i18n.t('encryption') }}</span>
                <span class="font-mono text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded">AES-256-GCM</span>
              </div>
              <div class="flex justify-between">
                <span class="text-slate-500">{{ i18n.t('passwordHash') }}</span>
                <span class="font-mono text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded">bcrypt</span>
              </div>
              <div class="flex justify-between">
                <span class="text-slate-500">{{ i18n.t('certIssuance') }}</span>
                <span class="text-slate-700 text-xs">ACME DNS-01</span>
              </div>
              <div class="flex justify-between">
                <span class="text-slate-500">{{ i18n.t('dataDir') }}</span>
                <span class="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-0.5 rounded">./data/</span>
              </div>
              <div class="flex justify-between">
                <span class="text-slate-500">{{ i18n.t('configFile') }}</span>
                <span class="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-0.5 rounded">config.enc</span>
              </div>
              <div class="flex justify-between">
                <span class="text-slate-500">{{ i18n.t('backupDir') }}</span>
                <span class="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-0.5 rounded">./data/backups/</span>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import {
  User, Settings2, Save, CheckCircle, AlertCircle,
  HardDrive, Download, Upload, AlertTriangle, Eye, EyeOff, Info, Languages
} from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'

const i18n = useI18n()
const form = ref({ username: '', new_password: '', confirm_password: '', port: 4455, safe_entry: '' })
const saved    = ref(false)
const saveError = ref('')
const saving   = ref(false)
const showPwd  = ref(false)
const restoreMsg   = ref('')
const restoreError = ref('')

const pwdStrength = computed(() => {
  const p = form.value.new_password; if (!p) return 0
  let s = 0
  if (p.length >= 8)  s++
  if (p.length >= 12) s++
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++
  if (/[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) s++
  return Math.min(4, s)
})
const pwdStrengthColor = computed(() => ['bg-red-400','bg-orange-400','bg-amber-400','bg-emerald-500'][pwdStrength.value - 1] || 'bg-slate-200')
const pwdStrengthLabel = computed(() => [i18n.t('weak'), i18n.t('fair'), i18n.t('good'), i18n.t('strong')][pwdStrength.value - 1] || '')

function setLang(lang) { i18n.locale = lang; localStorage.setItem('vane_lang', lang) }

async function load() {
  const { data } = await api.get('/settings')
  form.value.username  = data.username
  form.value.port      = data.port
  form.value.safe_entry = data.safe_entry || ''
}

async function save() {
  saveError.value = ''
  if (form.value.new_password && form.value.new_password !== form.value.confirm_password) {
    saveError.value = i18n.t('pwdMismatch'); return
  }
  if (form.value.new_password && form.value.new_password.length < 6) {
    saveError.value = i18n.t('pwdTooShort'); return
  }
  saving.value = true
  try {
    await api.put('/settings', {
      username: form.value.username, new_password: form.value.new_password || '',
      port: form.value.port, safe_entry: form.value.safe_entry,
    })
    form.value.new_password = ''; form.value.confirm_password = ''
    saved.value = true; setTimeout(() => saved.value = false, 3000)
  } catch (e) { saveError.value = e.response?.data?.error || e.message }
  finally { saving.value = false }
}

async function backup() {
  const resp = await api.get('/settings/backup', { responseType: 'blob' })
  const url = URL.createObjectURL(resp.data)
  const a = document.createElement('a'); a.href = url
  a.download = `vane-backup-${new Date().toISOString().slice(0,10)}.enc`; a.click()
  URL.revokeObjectURL(url)
}

async function restore(e) {
  restoreMsg.value = ''; restoreError.value = ''
  const file = e.target.files[0]; if (!file) return
  try {
    const buf = await file.arrayBuffer()
    await api.post('/settings/restore', new Uint8Array(buf), { headers: { 'Content-Type': 'application/octet-stream' } })
    restoreMsg.value = i18n.t('restoreSuccess')
  } catch (err) { restoreError.value = i18n.t('restoreFailed') + (err.response?.data?.error || err.message) }
  e.target.value = ''
}

onMounted(load)
</script>
