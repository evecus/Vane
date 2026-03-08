<template>
  <div class="space-y-4 sm:space-y-6 animate-fade-in">

    <!-- Header：去除副标题，按钮移动端全宽 -->
    <div class="flex items-center justify-between gap-3">
      <h1 class="page-title">{{ t('pfTitle') }}</h1>
      <button class="btn-primary flex-shrink-0" @click="openModal()">
        <Plus :size="16" /> <span class="hidden sm:inline">{{ t('addRule') }}</span><span class="sm:hidden">添加</span>
      </button>
    </div>

    <!-- Empty state -->
    <div v-if="rules.length === 0" class="glass-card p-12 sm:p-16 text-center">
      <div class="w-14 h-14 sm:w-16 sm:h-16 rounded-3xl bg-blue-50 flex items-center justify-center mx-auto mb-4">
        <ArrowLeftRight :size="26" class="text-blue-400" />
      </div>
      <p class="text-slate-500 font-medium">{{ t('noRules') }}</p>
      <p class="text-slate-400 text-sm mt-1">{{ t('noRulesHint') }}</p>
    </div>

    <!-- Rules list -->
    <div v-else class="grid gap-3 sm:gap-4">
      <div v-for="rule in rules" :key="rule.id"
           class="glass-card p-4 sm:p-5 flex items-center gap-3 sm:gap-4 group hover:shadow-colored-blue transition-all duration-300">

        <!-- Protocol badge -->
        <div class="w-10 h-10 sm:w-12 sm:h-12 rounded-2xl flex items-center justify-center flex-shrink-0 font-bold text-xs text-white"
             :style="rule.enabled ? 'background: linear-gradient(135deg, #3b82f6, #06b6d4)' : 'background: #e2e8f0; color: #94a3b8'">
          {{ rule.protocol?.toUpperCase() || 'TCP' }}
        </div>

        <!-- Info -->
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1">
            <span class="font-semibold text-slate-900 text-sm sm:text-base truncate">{{ rule.name || t('unnamed') }}</span>
            <span class="status-dot flex-shrink-0" :class="rule.enabled ? 'active' : 'inactive'"></span>
          </div>
          <div class="flex items-center gap-1.5 text-xs text-slate-500 font-mono flex-wrap">
            <span class="bg-blue-50 text-blue-700 px-2 py-0.5 rounded-lg">:{{ rule.listen_port }}</span>
            <ArrowRight :size="12" class="text-slate-300" />
            <span class="bg-slate-50 text-slate-600 px-2 py-0.5 rounded-lg truncate max-w-[150px]">{{ rule.target_ip }}:{{ rule.target_port }}</span>
          </div>
        </div>

        <!-- Traffic stats (desktop only) -->
        <div class="hidden lg:flex items-center gap-5 text-xs text-slate-400">
          <div class="text-center">
            <div class="font-mono text-slate-700 font-semibold">{{ fmtBytes(stats[rule.id]?.bytes_in || 0) }}</div>
            <div>{{ t('inbound') }}</div>
          </div>
          <div class="text-center">
            <div class="font-mono text-slate-700 font-semibold">{{ fmtBytes(stats[rule.id]?.bytes_out || 0) }}</div>
            <div>{{ t('outbound') }}</div>
          </div>
          <div class="text-center">
            <div class="font-mono text-slate-700 font-semibold">{{ stats[rule.id]?.conns || 0 }}</div>
            <div>{{ t('conns') }}</div>
          </div>
        </div>

        <!-- Actions -->
        <div class="flex items-center gap-1.5 sm:gap-2 flex-shrink-0">
          <label class="toggle">
            <input type="checkbox" :checked="rule.enabled" @change="toggle(rule.id)" />
            <div class="toggle-track"></div>
            <div class="toggle-thumb"></div>
          </label>
          <button @click="openModal(rule)" class="btn-ghost btn-sm sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
            <Pencil :size="14" />
          </button>
          <button @click="del(rule.id)" class="btn-ghost btn-sm text-red-400 hover:text-red-500 hover:bg-red-50 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
            <Trash2 :size="14" />
          </button>
        </div>
      </div>
    </div>

    <!-- Modal -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box w-full max-w-md mx-4 sm:mx-auto">

          <!-- Modal header -->
          <div class="flex items-center justify-between p-5 sm:p-6 border-b border-slate-100">
            <h3 class="font-semibold text-slate-900">{{ editing ? t('editRule') : t('addRule') }}</h3>
            <button @click="modal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>

          <!-- Modal body -->
          <div class="p-5 sm:p-6 space-y-4">
            <div>
              <label class="input-label">{{ t('ruleName') }}</label>
              <input v-model="form.name" class="input" placeholder="My Rule" />
            </div>
            <div class="grid grid-cols-2 gap-3 sm:gap-4">
              <div>
                <label class="input-label">{{ t('protocol') }}</label>
                <select v-model="form.protocol" class="select">
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="both">TCP+UDP</option>
                </select>
              </div>
              <div>
                <label class="input-label">{{ t('listenPort') }}</label>
                <input v-model.number="form.listen_port" type="number" class="input" placeholder="8080" />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3 sm:gap-4">
              <div>
                <label class="input-label">{{ t('targetIp') }}</label>
                <input v-model="form.target_ip" class="input" placeholder="192.168.1.100" />
              </div>
              <div>
                <label class="input-label">{{ t('targetPort') }}</label>
                <input v-model.number="form.target_port" type="number" class="input" placeholder="80" />
              </div>
            </div>

            <!-- Error -->
            <div v-if="formError" class="flex items-center gap-2 text-red-600 bg-red-50 px-3 py-2.5 rounded-xl border border-red-200 text-sm">
              <AlertCircle :size="14" /> {{ formError }}
            </div>
          </div>

          <!-- Modal footer：启用开关在右，保存/取消居中对称 -->
          <div class="px-5 sm:px-6 pb-5 sm:pb-6 space-y-4">
            <!-- Enable toggle：右对齐 -->
            <div class="flex justify-end items-center gap-2.5">
              <span class="text-sm text-slate-600">启用</span>
              <label class="toggle">
                <input type="checkbox" v-model="form.enabled" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
            </div>
            <!-- Buttons：保存左，取消右，居中对称 -->
            <div class="flex justify-center gap-3">
              <button class="btn-primary flex-1 max-w-[140px] justify-center" @click="save">{{ t('save') }}</button>
              <button class="btn-secondary flex-1 max-w-[140px] justify-center" @click="modal=null">{{ t('cancel') }}</button>
            </div>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { Plus, ArrowLeftRight, ArrowRight, Pencil, Trash2, X, AlertCircle } from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'

const { t } = useI18n()

const rules = ref([])
const stats = ref({})
const modal = ref(null)
const editing = ref(false)
const form = ref({})
const formError = ref('')

let ws = null

function fmtBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i]
}

async function load() {
  const { data } = await api.get('/portforward')
  rules.value = data
}

function openModal(rule = null) {
  editing.value = !!rule
  formError.value = ''
  form.value = rule
    ? { ...rule }
    : { name: '', protocol: 'tcp', listen_port: '', target_ip: '', target_port: '', enabled: true }
  modal.value = true
}

async function save() {
  formError.value = ''
  try {
    if (editing.value) {
      await api.put(`/portforward/${form.value.id}`, form.value)
    } else {
      await api.post('/portforward', form.value)
    }
    modal.value = null
    await load()
  } catch (e) {
    const port = e.response?.data?.port || form.value.listen_port
    if (e.response?.status === 409) {
      formError.value = t('portOccupied', { port })
    } else {
      formError.value = e.response?.data?.error || e.message
    }
  }
}

async function toggle(id) {
  await api.post(`/portforward/${id}/toggle`)
  await load()
}

async function del(id) {
  if (!confirm(t('confirmDelRule'))) return
  await api.delete(`/portforward/${id}`)
  await load()
}

function connectWS() {
  const token = localStorage.getItem('vane_token')
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  ws = new WebSocket(`${proto}://${location.host}/api/ws/stats?token=${token}`)
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data)
    if (msg.type === 'stats') stats.value = msg.data
  }
  ws.onclose = () => setTimeout(connectWS, 3000)
}

onMounted(() => { load(); connectWS() })
onUnmounted(() => ws?.close())
</script>
