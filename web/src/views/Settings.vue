<template>
  <div class="animate-fade-in">
    <!--
      桌面：2列网格，左列=账号安全+系统配置，右列=备份与恢复+关于Vane
      移动：单列，顺序 账号安全→系统配置→备份与恢复→关于Vane
    -->
    <div class="grid grid-cols-1 xl:grid-cols-2 gap-4 sm:gap-6">

      <!-- ── 账号安全 (左上) ─────────────────────────────────────── -->
      <section class="glass-card overflow-hidden">
        <div class="flex items-center gap-3 px-5 py-4 border-b border-slate-100 bg-slate-50/50">
          <div class="w-8 h-8 rounded-lg bg-vane-100 flex items-center justify-center flex-shrink-0">
            <User :size="15" class="text-vane-600" />
          </div>
          <div>
            <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('accountSecurity') }}</h3>
            <p class="text-xs text-slate-400">{{ i18n.t('accountSecurityDesc') }}</p>
          </div>
        </div>
        <div class="p-5 space-y-4">
          <div>
            <label class="input-label">{{ i18n.t('username') }}</label>
            <input v-model="form.username" class="input" autocomplete="username" />
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
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
                   class="h-1.5 w-7 rounded-full transition-colors duration-300"
                   :class="pwdStrength >= i ? pwdStrengthColor : 'bg-slate-200'"></div>
            </div>
            <span class="text-xs" :class="pwdStrength >= 3 ? 'text-emerald-600' : 'text-amber-600'">
              {{ pwdStrengthLabel }}
            </span>
          </div>
        </div>
      </section>

      <!-- ── 备份与恢复 (右上) ──────────────────────────────────── -->
      <!-- 移动端：order-3 让它在系统配置之后 -->
      <section class="glass-card overflow-hidden order-3 xl:order-none">
        <div class="flex items-center gap-3 px-5 py-4 border-b border-slate-100 bg-slate-50/50">
          <div class="w-8 h-8 rounded-lg bg-emerald-50 flex items-center justify-center flex-shrink-0">
            <HardDrive :size="15" class="text-emerald-600" />
          </div>
          <div>
            <h3 class="font-semibold text-slate-800 text-sm">备份与恢复</h3>
            <p class="text-xs text-slate-400">{{ i18n.t('backupRestoreDesc') }}</p>
          </div>
        </div>
        <div class="p-5 space-y-3">
          <div class="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
            <div class="flex items-center gap-2">
              <Download :size="14" class="text-slate-500" />
              <span class="text-sm font-medium text-slate-700">{{ i18n.t('backupTitle') }}</span>
            </div>
            <p class="text-xs text-slate-400">{{ i18n.t('backupDesc') }}</p>
            <button class="btn-secondary btn-sm w-full justify-center" @click="backup">
              <Download :size="13" /> {{ i18n.t('downloadBackup') }}
            </button>
          </div>
          <div class="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
            <div class="flex items-center gap-2">
              <Upload :size="14" class="text-slate-500" />
              <span class="text-sm font-medium text-slate-700">{{ i18n.t('restoreTitle') }}</span>
            </div>
            <p class="text-xs text-slate-400">{{ i18n.t('restoreDesc') }}</p>
            <label class="btn btn-secondary btn-sm w-full justify-center cursor-pointer">
              <Upload :size="13" /> {{ i18n.t('selectBackup') }}
              <input type="file" accept=".enc,.json" class="hidden" @change="restore" />
            </label>
          </div>
          <div v-if="restoreMsg" class="flex items-center gap-2 text-emerald-700 bg-emerald-50 px-4 py-2.5 rounded-xl border border-emerald-200 text-sm">
            <CheckCircle :size="14" /> {{ restoreMsg }}
          </div>
          <div v-if="restoreError" class="flex items-center gap-2 text-red-600 bg-red-50 px-4 py-2.5 rounded-xl border border-red-200 text-sm">
            <AlertCircle :size="14" /> {{ restoreError }}
          </div>
        </div>
      </section>

      <!-- ── 系统配置 (左下) ─────────────────────────────────────── -->
      <!-- 移动端：order-2 -->
      <section class="glass-card overflow-hidden order-2 xl:order-none">
        <div class="flex items-center gap-3 px-5 py-4 border-b border-slate-100 bg-slate-50/50">
          <div class="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center flex-shrink-0">
            <Settings2 :size="15" class="text-slate-600" />
          </div>
          <div>
            <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('sysConfig') }}</h3>
            <p class="text-xs text-slate-400">{{ i18n.t('sysConfigDesc') }}</p>
          </div>
        </div>
        <div class="p-5 space-y-4">
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

      <!-- ── 关于 Vane (右下) ───────────────────────────────────── -->
      <!-- 移动端：order-4 -->
      <section class="glass-card overflow-hidden order-4 xl:order-none">
        <div class="flex items-center gap-3 px-5 py-4 border-b border-slate-100 bg-slate-50/50">
          <div class="w-8 h-8 rounded-lg bg-purple-50 flex items-center justify-center flex-shrink-0">
            <Info :size="15" class="text-purple-500" />
          </div>
          <div class="flex-1">
            <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('aboutVane') }}</h3>
            <p class="text-xs text-slate-400">{{ i18n.t('aboutDesc') }}</p>
          </div>
        </div>
        <div class="p-5 space-y-4">
          <!-- Version + GitHub -->
          <div class="flex items-center justify-between">
            <div>
              <div class="text-xs text-slate-400 mb-0.5">版本</div>
              <div class="font-mono text-sm font-semibold text-slate-700">
                {{ form.version || 'dev' }}
              </div>
            </div>
            <a href="https://github.com/evecus/Vane" target="_blank" rel="noopener noreferrer"
               class="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium transition-all active:scale-95 shadow-sm">
              <!-- GitHub SVG icon -->
              <svg viewBox="0 0 24 24" class="w-4 h-4 fill-current" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
              </svg>
              GitHub
            </a>
          </div>

          <div class="border-t border-slate-100 pt-4 grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <div class="flex justify-between items-center">
              <span class="text-slate-500 text-xs">{{ i18n.t('encryption') }}</span>
              <span class="font-mono text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded">AES-256-GCM</span>
            </div>
            <div class="flex justify-between items-center">
              <span class="text-slate-500 text-xs">{{ i18n.t('passwordHash') }}</span>
              <span class="font-mono text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded">bcrypt</span>
            </div>
          </div>
        </div>
      </section>

    </div>

    <!-- ── 底部：反馈 + 保存按钮，靠右下 ────────────────────────── -->
    <div class="mt-6 flex flex-col sm:flex-row items-start sm:items-center justify-end gap-3">
      <div v-if="saveError" class="flex items-center gap-2 text-red-600 bg-red-50 px-4 py-2.5 rounded-xl border border-red-200 text-sm">
        <AlertCircle :size="15" /> {{ saveError }}
      </div>
      <button class="btn-primary" @click="confirmSave" :disabled="saving">
        <Save :size="15" /> {{ saving ? i18n.t('saving') : i18n.t('saveSettings') }}
      </button>
    </div>

    <!-- ── 重启确认弹窗 ────────────────────────────────────────── -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showRestartModal"
             class="fixed inset-0 z-50 flex items-center justify-center p-4"
             style="background: rgba(0,0,0,0.45); backdrop-filter: blur(4px);">
          <div class="bg-white rounded-2xl shadow-2xl w-full max-w-sm p-6">
            <div class="flex items-center justify-center w-12 h-12 rounded-2xl bg-amber-100 mb-4 mx-auto">
              <RefreshCw :size="22" class="text-amber-600" />
            </div>
            <h3 class="text-base font-bold text-slate-800 text-center mb-2">确认保存并重启</h3>
            <p class="text-slate-500 text-sm text-center leading-relaxed mb-1">
              修改了端口或安全访问路径，保存后程序将自动重启。
            </p>
            <p class="text-slate-400 text-xs text-center mb-5">
              重启后将跳转至
              <code class="bg-slate-100 px-1.5 py-0.5 rounded text-slate-700 font-mono">{{ newUrl }}</code>
            </p>
            <div class="flex gap-3">
              <button @click="showRestartModal = false"
                      class="flex-1 py-2.5 rounded-xl border border-slate-200 text-slate-600 text-sm font-medium hover:bg-slate-50 active:scale-[0.98] transition-all">
                取消
              </button>
              <button @click="doSave"
                      class="flex-1 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-600 text-white text-sm font-semibold active:scale-[0.98] transition-all shadow-sm">
                确认保存
              </button>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import {
  User, Settings2, Save, CheckCircle, AlertCircle,
  HardDrive, Download, Upload, AlertTriangle, Eye, EyeOff, Info, RefreshCw
} from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'

const i18n = useI18n()
const form = ref({ username: '', new_password: '', confirm_password: '', port: 4455, safe_entry: '', version: '' })
const savedPort      = ref(4455)   // port at load time
const savedEntry     = ref('')     // safe_entry at load time
const saveError      = ref('')
const saving         = ref(false)
const showPwd        = ref(false)
const restoreMsg     = ref('')
const restoreError   = ref('')
const showRestartModal = ref(false)

// 是否修改了端口或安全路径（需要重启）
const needsRestart = computed(() =>
  form.value.port !== savedPort.value ||
  (form.value.safe_entry || '') !== (savedEntry.value || '')
)

// 重启后应跳转的新 URL
const newUrl = computed(() => {
  const { hostname } = window.location
  const port  = form.value.port || 4455
  const entry = (form.value.safe_entry || '').trim().replace(/^\/+/, '')
  const portStr = port === 80 ? '' : `:${port}`
  return entry
    ? `${window.location.protocol}//${hostname}${portStr}/${entry}`
    : `${window.location.protocol}//${hostname}${portStr}`
})

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

async function load() {
  const { data } = await api.get('/settings')
  form.value.username   = data.username
  form.value.port       = data.port
  form.value.safe_entry = data.safe_entry || ''
  form.value.version    = data.version || 'dev'
  savedPort.value  = data.port
  savedEntry.value = data.safe_entry || ''
}

// 点保存按钮：先校验，如需重启则弹确认框，否则直接保存
function confirmSave() {
  saveError.value = ''
  if (form.value.new_password && form.value.new_password !== form.value.confirm_password) {
    saveError.value = i18n.t('pwdMismatch'); return
  }
  if (form.value.new_password && form.value.new_password.length < 6) {
    saveError.value = i18n.t('pwdTooShort'); return
  }
  if (needsRestart.value) {
    showRestartModal.value = true
  } else {
    doSave()
  }
}

// 真正执行保存
async function doSave() {
  showRestartModal.value = false
  saving.value = true
  const willRestart = needsRestart.value
  const targetUrl   = newUrl.value
  try {
    await api.put('/settings', {
      username:     form.value.username,
      new_password: form.value.new_password || '',
      port:         form.value.port,
      safe_entry:   form.value.safe_entry,
    })
    form.value.new_password = ''
    form.value.confirm_password = ''
    savedPort.value  = form.value.port
    savedEntry.value = form.value.safe_entry || ''

    if (willRestart) {
      // 等待后端重启（约 1.5s），然后轮询新 URL 直到可访问，再跳转
      await new Promise(r => setTimeout(r, 1500))
      await pollUntilAlive(targetUrl)
      window.location.href = targetUrl
    }
  } catch (e) {
    saveError.value = e.response?.data?.error || e.message
  } finally {
    saving.value = false
  }
}

// 轮询新地址直到响应（最多 15s）
async function pollUntilAlive(url, maxMs = 15000, interval = 600) {
  const deadline = Date.now() + maxMs
  while (Date.now() < deadline) {
    try {
      await fetch(url, { method: 'HEAD', mode: 'no-cors', cache: 'no-store' })
      return // 能连上了
    } catch {
      await new Promise(r => setTimeout(r, interval))
    }
  }
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
