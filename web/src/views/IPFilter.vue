<template>
  <div class="space-y-4 sm:space-y-6 animate-fade-in">

    <!-- 页面标题 -->
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ t('ipfilterTitle') }}</h1>
        <p class="text-slate-400 text-sm mt-0.5">{{ t('ipfilterSubtitle') }}</p>
      </div>
      <button
        v-if="rules.length < 3"
        class="btn-primary btn-sm sm:btn-normal"
        @click="openModal(null)"
      >
        <Plus :size="15" />
        <span class="hidden xs:inline">{{ t('addIPFilterRule') }}</span>
      </button>
    </div>

    <!-- 空状态 -->
    <div v-if="rules.length === 0" class="glass-card p-10 sm:p-16 text-center">
      <div class="w-14 h-14 sm:w-16 sm:h-16 rounded-3xl bg-cyan-50 flex items-center justify-center mx-auto mb-4">
        <Filter :size="26" class="text-cyan-400" />
      </div>
      <p class="text-slate-500 font-medium">{{ t('noIPFilterRules') }}</p>
      <p class="text-slate-400 text-sm mt-1">{{ t('noIPFilterRulesHint') }}</p>
    </div>

    <!-- 规则卡片列表 -->
    <div v-else class="grid gap-3 sm:gap-4">
      <div
        v-for="rule in rules"
        :key="rule.id"
        class="glass-card p-4 sm:p-5 group transition-all duration-300"
      >
        <div class="flex items-start gap-3 sm:gap-4">
          <!-- 图标区 -->
          <div
            class="w-11 h-11 sm:w-12 sm:h-12 rounded-xl sm:rounded-2xl flex items-center justify-center flex-shrink-0 text-white"
            :style="rule.enabled
              ? (rule.mode === 'whitelist'
                  ? 'background:linear-gradient(135deg,#06b6d4,#3b82f6)'
                  : 'background:linear-gradient(135deg,#f59e0b,#ef4444)')
              : 'background:#e2e8f0'"
          >
            <ShieldCheck v-if="rule.mode === 'whitelist'" :size="18" :class="rule.enabled ? 'text-white' : 'text-slate-400'" />
            <ShieldOff v-else :size="18" :class="rule.enabled ? 'text-white' : 'text-slate-400'" />
          </div>

          <!-- 内容区 -->
          <div class="flex-1 min-w-0">
            <!-- 第一行：模式 + 状态徽章 -->
            <div class="flex items-center gap-2 flex-wrap mb-1.5">
              <span class="font-semibold text-slate-900 text-sm sm:text-base">
                {{ rule.mode === 'whitelist' ? t('ipfWhitelist') : t('ipfBlacklist') }}
              </span>
              <span
                class="text-xs px-2 py-0.5 rounded-full font-medium"
                :class="rule.enabled
                  ? 'bg-emerald-50 text-emerald-600 border border-emerald-200'
                  : 'bg-slate-100 text-slate-400 border border-slate-200'"
              >
                {{ rule.enabled ? t('ipfEnabledBadge') : t('ipfDisabledBadge') }}
              </span>
            </div>

            <!-- 第二行：作用范围标签 -->
            <div class="flex flex-wrap gap-1 mb-2">
              <span
                v-for="scope in rule.scopes"
                :key="scope"
                class="text-xs px-2 py-0.5 rounded-md font-medium"
                :class="scopeBadgeClass(scope)"
              >
                {{ scopeLabel(scope) }}
              </span>
            </div>

            <!-- 第三行：IP数量 + 附件数量 -->
            <div class="flex flex-wrap items-center gap-3 text-xs text-slate-400">
              <span class="flex items-center gap-1">
                <List :size="12" />
                {{ t('ipfIPCount', { n: totalIPCount(rule) }) }}
              </span>
              <span v-if="rule.attachments && rule.attachments.length" class="flex items-center gap-1">
                <Paperclip :size="12" />
                {{ t('ipfAttachCount', { n: rule.attachments.length }) }}
              </span>
            </div>
          </div>

          <!-- 操作按钮 -->
          <div class="flex items-center gap-1.5 flex-shrink-0">
            <!-- 开关 -->
            <button
              @click="toggle(rule)"
              :disabled="toggling === rule.id"
              class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 focus:outline-none flex-shrink-0"
              :class="rule.enabled ? 'bg-cyan-500' : 'bg-slate-200'"
              :title="rule.enabled ? '点击禁用' : '点击启用'"
            >
              <span
                class="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform duration-200"
                :class="rule.enabled ? 'translate-x-4' : 'translate-x-1'"
              />
            </button>
            <button
              @click="openModal(rule)"
              class="btn-ghost btn-sm text-slate-500"
              :title="t('ipfEditRule')"
            >
              <Pencil :size="13" />
            </button>
            <button
              @click="confirmDel(rule)"
              class="btn-ghost btn-sm text-red-400 hover:text-red-500 hover:bg-red-50"
            >
              <Trash2 :size="13" />
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 最多3条提示 -->
    <div v-if="rules.length >= 3" class="text-center text-xs text-slate-400 py-2">
      已创建 3 条规则（每个作用范围最多绑定一条规则，上限已达）
    </div>

  </div>

  <!-- ══ 编辑/新建 Modal ══════════════════════════════════════════════ -->
  <div v-if="modal" class="modal-overlay" @click.self="modal = null">
    <div class="modal-box sm:max-w-xl">

      <!-- 拖动条（移动端） -->
      <div class="sm:hidden flex justify-center pt-3 pb-1 flex-shrink-0">
        <div class="w-10 h-1 bg-slate-200 rounded-full"></div>
      </div>

      <!-- 标题栏 -->
      <div class="flex items-center justify-between px-5 py-4 border-b border-slate-100 flex-shrink-0">
        <h2 class="font-semibold text-slate-800 text-base">
          {{ modal.id ? t('ipfEditRule') : t('ipfNewRule') }}
        </h2>
        <button @click="modal = null" class="btn-ghost btn-sm p-1.5 text-slate-400">
          <X :size="16" />
        </button>
      </div>

      <!-- 表单主体 -->
      <div class="flex-1 overflow-y-auto px-5 py-4 space-y-5">

        <!-- 模式选择 -->
        <div>
          <label class="block text-sm font-medium text-slate-700 mb-2">{{ t('ipfMode') }}</label>
          <div class="grid grid-cols-2 gap-2">
            <button
              type="button"
              @click="modal.mode = 'whitelist'"
              class="flex items-center gap-2.5 p-3 rounded-xl border-2 text-left transition-all"
              :class="modal.mode === 'whitelist'
                ? 'border-cyan-400 bg-cyan-50'
                : 'border-slate-200 hover:border-slate-300 bg-white'"
            >
              <ShieldCheck :size="18" :class="modal.mode === 'whitelist' ? 'text-cyan-500' : 'text-slate-400'" />
              <div>
                <div class="text-sm font-semibold" :class="modal.mode === 'whitelist' ? 'text-cyan-700' : 'text-slate-700'">
                  {{ t('ipfWhitelist') }}
                </div>
                <div class="text-xs text-slate-400">{{ t('ipfWhitelistDesc') }}</div>
              </div>
            </button>
            <button
              type="button"
              @click="modal.mode = 'blacklist'"
              class="flex items-center gap-2.5 p-3 rounded-xl border-2 text-left transition-all"
              :class="modal.mode === 'blacklist'
                ? 'border-amber-400 bg-amber-50'
                : 'border-slate-200 hover:border-slate-300 bg-white'"
            >
              <ShieldOff :size="18" :class="modal.mode === 'blacklist' ? 'text-amber-500' : 'text-slate-400'" />
              <div>
                <div class="text-sm font-semibold" :class="modal.mode === 'blacklist' ? 'text-amber-700' : 'text-slate-700'">
                  {{ t('ipfBlacklist') }}
                </div>
                <div class="text-xs text-slate-400">{{ t('ipfBlacklistDesc') }}</div>
              </div>
            </button>
          </div>
        </div>

        <!-- 作用范围多选 -->
        <div>
          <label class="block text-sm font-medium text-slate-700 mb-2">{{ t('ipfScopes') }}</label>
          <div class="flex flex-col gap-2">
            <label
              v-for="scope in allScopes"
              :key="scope.value"
              class="flex items-center gap-3 p-3 rounded-xl border cursor-pointer transition-all select-none"
              :class="isScopeDisabled(scope.value)
                ? 'border-slate-100 bg-slate-50 cursor-not-allowed opacity-50'
                : modal.scopes.includes(scope.value)
                  ? 'border-cyan-300 bg-cyan-50'
                  : 'border-slate-200 hover:border-slate-300 bg-white'"
            >
              <input
                type="checkbox"
                :value="scope.value"
                :checked="modal.scopes.includes(scope.value)"
                :disabled="isScopeDisabled(scope.value)"
                @change="toggleScope(scope.value)"
                class="w-4 h-4 rounded accent-cyan-500"
              />
              <component :is="scope.icon" :size="15" class="text-slate-500 flex-shrink-0" />
              <div class="flex-1">
                <span class="text-sm font-medium text-slate-700">{{ t(scope.labelKey) }}</span>
                <span v-if="isScopeDisabled(scope.value)" class="ml-2 text-xs text-slate-400">
                  {{ t('ipfScopeConflict') }}
                </span>
              </div>
            </label>
          </div>
          <p v-if="scopeError" class="mt-1.5 text-xs text-red-500">{{ t('ipfScopesMustSelect') }}</p>
        </div>

        <!-- 手动输入 IP -->
        <div>
          <label class="block text-sm font-medium text-slate-700 mb-1.5">{{ t('ipfManualIPs') }}</label>
          <textarea
            v-model="modal.manualIPsText"
            class="input w-full font-mono text-xs resize-none"
            rows="6"
            :placeholder="t('ipfManualIPsPlaceholder')"
          />
        </div>

        <!-- 上传附件区 -->
        <div>
          <label class="block text-sm font-medium text-slate-700 mb-1.5">{{ t('ipfAttachments') }}</label>

          <!-- 已有附件列表 -->
          <div v-if="modal.attachments && modal.attachments.length" class="mb-2 space-y-1.5">
            <div
              v-for="(att, idx) in modal.attachments"
              :key="idx"
              class="flex items-center gap-2 px-3 py-2 bg-slate-50 rounded-lg border border-slate-200"
            >
              <FileText :size="13" class="text-cyan-500 flex-shrink-0" />
              <span class="flex-1 text-xs text-slate-600 font-mono truncate">{{ att.name }}</span>
              <span class="text-xs text-slate-400 flex-shrink-0">{{ att.ips.length }} IPs</span>
              <button
                @click="removeAttachment(idx)"
                class="text-slate-300 hover:text-red-400 transition-colors flex-shrink-0 p-0.5"
              >
                <X :size="13" />
              </button>
            </div>
          </div>

          <!-- 上传按钮 -->
          <button
            type="button"
            @click="triggerFileInput"
            :disabled="uploading"
            class="btn-secondary btn-sm w-full justify-center"
          >
            <Upload :size="13" />
            <span>{{ uploading ? '解析中...' : t('ipfUploadBtn') }}</span>
          </button>
          <input
            ref="fileInputRef"
            type="file"
            accept=".txt,.csv,text/plain"
            multiple
            class="hidden"
            @change="handleFileUpload"
          />
          <p class="mt-1.5 text-xs text-slate-400">{{ t('ipfAttachmentHint') }}</p>
        </div>

      </div>

      <!-- 底部按钮 -->
      <div class="px-5 py-4 border-t border-slate-100 flex-shrink-0">
        <div class="flex gap-2 sm:flex-row-reverse">
          <button
            class="btn-primary flex-1 sm:flex-none sm:min-w-[100px] justify-center"
            :disabled="saving"
            @click="save"
          >
            {{ saving ? t('saving') : t('ipfSave') }}
          </button>
          <button
            class="btn-secondary flex-1 sm:flex-none sm:min-w-[80px] justify-center"
            @click="modal = null"
          >
            {{ t('cancel') }}
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- 删除确认 Modal -->
  <ConfirmModal
    v-if="confirmModal"
    :message="t('ipfConfirmDel')"
    @confirm="doDelete"
    @cancel="confirmModal = null"
  />

</template>

<script setup>
import { ref, computed } from 'vue'
import { useI18n } from '@/stores/i18n'
import { api } from '@/stores/auth'
import {
  Plus, Filter, ShieldCheck, ShieldOff, Pencil, Trash2,
  X, Upload, FileText, List, Paperclip,
  LayoutDashboard, ArrowLeftRight, Server
} from 'lucide-vue-next'
import ConfirmModal from '@/components/ConfirmModal.vue'

const i18n = useI18n()
const t = (k, v) => i18n.t(k, v)

// ── 数据 ────────────────────────────────────────────────────────────────────
const rules = ref([])
const toggling = ref(null)
const saving = ref(false)
const uploading = ref(false)
const modal = ref(null)         // null | rule 对象（编辑态，含 manualIPsText）
const confirmModal = ref(null)  // null | rule
const scopeError = ref(false)
const fileInputRef = ref(null)

// 所有可选 scope
const allScopes = [
  { value: 'admin',       labelKey: 'ipfScopeAdmin',       icon: LayoutDashboard },
  { value: 'portforward', labelKey: 'ipfScopePortforward', icon: ArrowLeftRight  },
  { value: 'webservice',  labelKey: 'ipfScopeWebservice',  icon: Server          },
]

// ── 计算已被其他规则占用的 scope ────────────────────────────────────────────
const occupiedScopes = computed(() => {
  const editingId = modal.value?.id || null
  const set = new Set()
  for (const r of rules.value) {
    if (r.id === editingId) continue
    for (const s of (r.scopes || [])) set.add(s)
  }
  return set
})

function isScopeDisabled(scopeVal) {
  return occupiedScopes.value.has(scopeVal)
}

// ── 加载 ─────────────────────────────────────────────────────────────────────
async function load() {
  try {
    const { data } = await api.get('/ipfilter')
    rules.value = data || []
  } catch {}
}
load()

// ── 总 IP 数（手动 + 所有附件） ─────────────────────────────────────────────
function totalIPCount(rule) {
  const manual = (rule.manual_ips || []).length
  const att = (rule.attachments || []).reduce((s, a) => s + (a.ips || []).length, 0)
  return manual + att
}

// ── scope 标签 / 样式 ────────────────────────────────────────────────────────
function scopeLabel(s) {
  const map = { admin: t('ipfScopeAdmin'), portforward: t('ipfScopePortforward'), webservice: t('ipfScopeWebservice') }
  return map[s] || s
}

function scopeBadgeClass(s) {
  const map = {
    admin:       'bg-violet-50 text-violet-600 border border-violet-200',
    portforward: 'bg-blue-50   text-blue-600   border border-blue-200',
    webservice:  'bg-pink-50   text-pink-600   border border-pink-200',
  }
  return map[s] || 'bg-slate-100 text-slate-500 border border-slate-200'
}

// ── 开关 ─────────────────────────────────────────────────────────────────────
async function toggle(rule) {
  toggling.value = rule.id
  try {
    const { data } = await api.post(`/ipfilter/${rule.id}/toggle`)
    const idx = rules.value.findIndex(r => r.id === rule.id)
    if (idx !== -1) rules.value[idx] = data
  } catch {}
  toggling.value = null
}

// ── 打开 Modal ────────────────────────────────────────────────────────────────
function openModal(rule) {
  scopeError.value = false
  if (rule) {
    // 编辑：把 manual_ips 数组转为文本
    modal.value = {
      id: rule.id,
      mode: rule.mode || 'whitelist',
      scopes: [...(rule.scopes || [])],
      manualIPsText: (rule.manual_ips || []).join('\n'),
      attachments: JSON.parse(JSON.stringify(rule.attachments || [])),
    }
  } else {
    // 新建
    modal.value = {
      id: null,
      mode: 'whitelist',
      scopes: [],
      manualIPsText: '',
      attachments: [],
    }
  }
}

// ── scope 多选切换 ────────────────────────────────────────────────────────────
function toggleScope(val) {
  if (isScopeDisabled(val)) return
  const idx = modal.value.scopes.indexOf(val)
  if (idx === -1) modal.value.scopes.push(val)
  else            modal.value.scopes.splice(idx, 1)
  scopeError.value = false
}

// ── 附件操作 ──────────────────────────────────────────────────────────────────
function triggerFileInput() {
  fileInputRef.value?.click()
}

async function handleFileUpload(e) {
  const files = Array.from(e.target.files)
  if (!files.length) return
  uploading.value = true
  for (const file of files) {
    try {
      const form = new FormData()
      form.append('file', file)
      const { data } = await api.post('/ipfilter/upload', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      // 如果已有同名附件则替换，否则追加
      const existing = modal.value.attachments.findIndex(a => a.name === data.name)
      if (existing !== -1) modal.value.attachments[existing] = { name: data.name, ips: data.ips }
      else modal.value.attachments.push({ name: data.name, ips: data.ips })
    } catch {}
  }
  uploading.value = false
  // 清空 input，允许重新选同一文件
  e.target.value = ''
}

function removeAttachment(idx) {
  modal.value.attachments.splice(idx, 1)
}

// ── 保存 ─────────────────────────────────────────────────────────────────────
async function save() {
  if (!modal.value.scopes.length) {
    scopeError.value = true
    return
  }
  saving.value = true
  try {
    // 将文本框的 IP 解析为数组（去空行、去注释、去重）
    const manualIPs = parseIPText(modal.value.manualIPsText)

    const payload = {
      mode:        modal.value.mode,
      scopes:      modal.value.scopes,
      enabled:     modal.value.id
        ? (rules.value.find(r => r.id === modal.value.id)?.enabled ?? true)
        : true,
      manual_ips:  manualIPs,
      attachments: modal.value.attachments,
    }

    if (modal.value.id) {
      const { data } = await api.put(`/ipfilter/${modal.value.id}`, payload)
      const idx = rules.value.findIndex(r => r.id === modal.value.id)
      if (idx !== -1) rules.value[idx] = data
    } else {
      const { data } = await api.post('/ipfilter', payload)
      rules.value.push(data)
    }
    modal.value = null
  } catch (err) {
    console.error(err)
  }
  saving.value = false
}

// ── 删除 ─────────────────────────────────────────────────────────────────────
function confirmDel(rule) {
  confirmModal.value = rule
}

async function doDelete() {
  const rule = confirmModal.value
  confirmModal.value = null
  if (!rule) return
  try {
    await api.delete(`/ipfilter/${rule.id}`)
    rules.value = rules.value.filter(r => r.id !== rule.id)
  } catch {}
}

// ── 工具：文本 → IP 数组 ──────────────────────────────────────────────────────
function parseIPText(text) {
  const seen = new Set()
  const result = []
  for (const line of text.split('\n')) {
    const s = line.trim()
    if (!s || s.startsWith('#')) continue
    if (!seen.has(s)) { seen.add(s); result.push(s) }
  }
  return result
}
</script>
