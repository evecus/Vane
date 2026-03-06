<template>
  <div class="space-y-6 animate-fade-in max-w-2xl">
    <div class="page-header">
      <div>
        <h1 class="page-title">系统设置</h1>
        <p class="page-subtitle">账号、端口、安全入口、配置备份与恢复</p>
      </div>
    </div>

    <!-- Account -->
    <div class="glass-card p-6 space-y-5">
      <h3 class="font-semibold text-slate-800 flex items-center gap-2">
        <User :size="18" class="text-vane-500" /> 账号设置
      </h3>
      <div>
        <label class="input-label">用户名</label>
        <input v-model="form.username" class="input max-w-xs" />
      </div>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <label class="input-label">新密码</label>
          <input v-model="form.new_password" type="password" class="input" placeholder="留空不修改" />
        </div>
        <div>
          <label class="input-label">确认新密码</label>
          <input v-model="form.confirm_password" type="password" class="input" placeholder="留空不修改" />
        </div>
      </div>
    </div>

    <!-- System config -->
    <div class="glass-card p-6 space-y-5">
      <h3 class="font-semibold text-slate-800 flex items-center gap-2">
        <Settings2 :size="18" class="text-vane-500" /> 系统配置
      </h3>
      <div>
        <label class="input-label">管理界面端口</label>
        <input v-model.number="form.port" type="number" class="input max-w-xs" />
        <p class="text-xs text-slate-400 mt-1">修改后需重启 Vane 进程生效</p>
      </div>
      <div>
        <label class="input-label">安全入口后缀</label>
        <div class="flex items-center gap-2 max-w-sm">
          <span class="text-sm text-slate-400 whitespace-nowrap">http://ip:{{ form.port }}/</span>
          <input v-model="form.safe_entry" class="input font-mono text-sm"
                 placeholder="留空则不启用（如 lucky88）" />
        </div>
        <p class="text-xs text-slate-400 mt-1">
          设置后，只有访问 <code class="bg-slate-100 px-1 rounded text-slate-600">http://ip:{{ form.port }}/{{ form.safe_entry || '后缀' }}</code> 才能进入管理界面
        </p>
        <p class="text-xs text-amber-600 mt-1 flex items-center gap-1" v-if="form.safe_entry">
          <AlertTriangle :size="12" /> 请务必记住此后缀，设置后直接访问将返回 403
        </p>
      </div>
    </div>

    <!-- Feedback -->
    <div v-if="saved" class="flex items-center gap-2 text-emerald-600 bg-emerald-50 px-4 py-3 rounded-xl border border-emerald-200 text-sm">
      <CheckCircle :size="16" /> 设置已保存
    </div>
    <div v-if="error" class="flex items-center gap-2 text-red-600 bg-red-50 px-4 py-3 rounded-xl border border-red-200 text-sm">
      <AlertCircle :size="16" /> {{ error }}
    </div>

    <button class="btn-primary" @click="save">
      <Save :size="16" /> 保存设置
    </button>

    <!-- Backup & Restore -->
    <div class="glass-card p-6 space-y-5">
      <h3 class="font-semibold text-slate-800 flex items-center gap-2">
        <HardDrive :size="18" class="text-vane-500" /> 配置备份与恢复
      </h3>
      <p class="text-sm text-slate-500">备份包含所有规则、证书配置（不含证书私钥明文）。恢复后服务将自动重启。</p>

      <div class="flex gap-3 flex-wrap">
        <button class="btn-secondary" @click="backup">
          <Download :size="15" /> 备份当前配置
        </button>
        <label class="btn btn-secondary cursor-pointer">
          <Upload :size="15" /> 恢复配置
          <input type="file" accept=".json" class="hidden" @change="restore" />
        </label>
      </div>

      <div v-if="restoreMsg" class="flex items-center gap-2 text-emerald-600 bg-emerald-50 px-4 py-3 rounded-xl border border-emerald-200 text-sm">
        <CheckCircle :size="16" /> {{ restoreMsg }}
      </div>
      <div v-if="restoreError" class="flex items-center gap-2 text-red-600 bg-red-50 px-4 py-3 rounded-xl border border-red-200 text-sm">
        <AlertCircle :size="16" /> {{ restoreError }}
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import {
  User, Settings2, Save, CheckCircle, AlertCircle,
  HardDrive, Download, Upload, AlertTriangle
} from 'lucide-vue-next'
import { api } from '@/stores/auth'

const form = ref({ username: '', new_password: '', confirm_password: '', port: 4455, safe_entry: '' })
const saved = ref(false)
const error = ref('')
const restoreMsg = ref('')
const restoreError = ref('')

async function load() {
  const { data } = await api.get('/settings')
  form.value.username = data.username
  form.value.port = data.port
  form.value.safe_entry = data.safe_entry || ''
}

async function save() {
  error.value = ''
  if (form.value.new_password && form.value.new_password !== form.value.confirm_password) {
    error.value = '两次密码不一致'
    return
  }
  await api.put('/settings', {
    username: form.value.username,
    new_password: form.value.new_password || '',
    port: form.value.port,
    safe_entry: form.value.safe_entry,
  })
  saved.value = true
  setTimeout(() => saved.value = false, 3000)
}

async function backup() {
  const resp = await api.get('/settings/backup', { responseType: 'blob' })
  const url = URL.createObjectURL(resp.data)
  const a = document.createElement('a')
  a.href = url
  a.download = `vane-backup-${new Date().toISOString().slice(0,10)}.json`
  a.click()
  URL.revokeObjectURL(url)
}

async function restore(e) {
  restoreMsg.value = ''
  restoreError.value = ''
  const file = e.target.files[0]
  if (!file) return
  try {
    const text = await file.text()
    await api.post('/settings/restore', JSON.parse(text), {
      headers: { 'Content-Type': 'application/json' }
    })
    restoreMsg.value = '配置已恢复，服务已重启'
  } catch (err) {
    restoreError.value = '恢复失败：' + (err.response?.data?.error || err.message)
  }
  e.target.value = ''
}

onMounted(load)
</script>
