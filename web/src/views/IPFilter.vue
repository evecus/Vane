<template>
  <div class="space-y-4 sm:space-y-6 animate-fade-in">

    <!-- 页面标题 -->
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ t('ipfilterTitle') }}</h1>
        <p class="text-slate-400 text-sm mt-0.5">{{ t('ipfilterSubtitle') }}</p>
      </div>
      <button
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
                :key="scope.type + ':' + scope.target_id"
                class="text-xs px-2 py-0.5 rounded-md font-medium"
                :class="scopeBadgeClass(scope.type)"
              >
                {{ scopeDisplayName(scope) }}
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

  </div>

  <!-- ══ 编辑/新建 Modal ══════════════════════════════════════════════ -->
  <div v-if="modal" class="modal-overlay" @click.self="modal = null">
    <div class="modal-box sm:max-w-2xl">

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

        <!-- 作用范围选择 -->
        <div>
          <label class="block text-sm font-medium text-slate-700 mb-2">{{ t('ipfScopes') }}</label>

          <!-- 分组展示 -->
          <div class="space-y-3">
            <div v-for="group in targetGroups" :key="group.type">
              <!-- 分组标题 -->
              <div class="flex items-center gap-2 mb-1.5">
                <component :is="group.icon" :size="13" class="text-slate-400" />
                <span class="text-xs font-semibold text-slate-500 uppercase tracking-wide">{{ group.label }}</span>
              </div>
              <!-- 分组选项 -->
              <div class="grid gap-1.5 pl-1">
                <label
                  v-for="item in group.items"
                  :key="item.type + ':' + item.target_id"
                  class="flex items-center gap-3 px-3 py-2 rounded-lg border cursor-pointer transition-all select-none"
                  :class="isScopeDisabled(item)
                    ? 'border-slate-100 bg-slate-50 cursor-not-allowed opacity-50'
                    : isScopeSelected(item)
                      ? 'border-cyan-300 bg-cyan-50'
                      : 'border-slate-200 hover:border-slate-300 bg-white'"
                >
                  <input
                    type="checkbox"
                    :checked="isScopeSelected(item)"
                    :disabled="isScopeDisabled(item)"
                    @change="toggleScope(item)"
                    class="w-4 h-4 rounded accent-cyan-500 flex-shrink-0"
                  />
                  <span class="flex-1 text-sm text-slate-700">{{ item.target_name }}</span>
                  <span v-if="isScopeDisabled(item)" class="text-xs text-slate-400 flex-shrink-0">
                    {{ t('ipfScopeConflict') }}
                  </span>
                </label>
              </div>
            </div>
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
const allTargets = ref([])   // [{type, target_id, target_name}] from /ipfilter/targets
const toggling = ref(null)
const saving = ref(false)
const uploading = ref(false)
const modal = ref(null)
const confirmModal = ref(null)
const scopeError = ref(false)
const fileInputRef = ref(null)

// ── 加载 ─────────────────────────────────────────────────────────────────────
async function load() {
  try {
    const [rulesRes, targetsRes] = await Promise.all([
      api.get('/ipfilter'),
      api.get('/ipfilter/targets'),
    ])
    rules.value = rulesRes.data || []
    allTargets.value = targetsRes.data || []
  } catch {}
}
load()

// ── 分组目标列表（用于 Modal 中的分组展示）────────────────────────────────
const targetGroups = computed(() => {
  const typeConfig = {
    admin:       { label: '管理后台', icon: LayoutDashboard },
    portforward: { label: '端口转发', icon: ArrowLeftRight },
    webservice:  { label: '网页服务', icon: Server },
  }
  const groups = {}
  for (const item of allTargets.value) {
    if (!groups[item.type]) {
      groups[item.type] = {
        type: item.type,
        label: typeConfig[item.type]?.label || item.type,
        icon: typeConfig[item.type]?.icon || Filter,
        items: [],
      }
    }
    groups[item.type].items.push(item)
  }
  return ['admin', 'portforward', 'webservice']
    .filter(t => groups[t])
    .map(t => groups[t])
})

// ── 已被其他规则占用的 scope key 集合 ────────────────────────────────────
const occupiedScopeKeys = computed(() => {
  const editingId = modal.value?.id || null
  const set = new Set()
  for (const r of rules.value) {
    if (r.id === editingId) continue
    for (const s of (r.scopes || [])) {
      set.add(s.type + ':' + (s.target_id || ''))
    }
  }
  return set
})

function scopeKey(item) {
  return item.type + ':' + (item.target_id || '')
}

function isScopeDisabled(item) {
  return occupiedScopeKeys.value.has(scopeKey(item))
}

function isScopeSelected(item) {
  if (!modal.value) return false
  return modal.value.scopes.some(s => s.type === item.type && (s.target_id || '') === (item.target_id || ''))
}

// ── 总 IP 数（手动 + 所有附件） ─────────────────────────────────────────
function totalIPCount(rule) {
  const manual = (rule.manual_ips || []).length
  const att = (rule.attachments || []).reduce((s, a) => s + (a.ips || []).length, 0)
  return manual + att
}

// ── scope 显示名 / 样式 ──────────────────────────────────────────────────
function scopeDisplayName(scope) {
  // Try to resolve from allTargets for live name
  const found = allTargets.value.find(
    t => t.type === scope.type && (t.target_id || '') === (scope.target_id || '')
  )
  if (found) return found.target_name
  // Fallback to snapshot name stored in the rule
  if (scope.target_name) return scope.target_name
  const typeLabels = { admin: '管理后台', portforward: '端口转发', webservice: '网页服务' }
  return typeLabels[scope.type] || scope.type
}

function scopeBadgeClass(type) {
  const map = {
    admin:       'bg-violet-50 text-violet-600 border border-violet-200',
    portforward: 'bg-blue-50   text-blue-600   border border-blue-200',
    webservice:  'bg-pink-50   text-pink-600   border border-pink-200',
  }
  return map[type] || 'bg-slate-100 text-slate-500 border border-slate-200'
}

// ── 开关 ─────────────────────────────────────────────────────────────────
async function toggle(rule) {
  toggling.value = rule.id
  try {
    const { data } = await api.post(`/ipfilter/${rule.id}/toggle`)
    const idx = rules.value.findIndex(r => r.id === rule.id)
    if (idx !== -1) rules.value[idx] = data
  } catch {}
  toggling.value = null
}

// ── 打开 Modal ────────────────────────────────────────────────────────────
async function openModal(rule) {
  scopeError.value = false
  // 每次打开时刷新目标列表，确保拿到最新的端口转发规则/路由
  try {
    const { data } = await api.get('/ipfilter/targets')
    allTargets.value = data || []
  } catch {}

  if (rule) {
    modal.value = {
      id: rule.id,
      mode: rule.mode || 'whitelist',
      scopes: JSON.parse(JSON.stringify(rule.scopes || [])),
      manualIPsText: (rule.manual_ips || []).join('\n'),
      attachments: JSON.parse(JSON.stringify(rule.attachments || [])),
    }
  } else {
    modal.value = {
      id: null,
      mode: 'whitelist',
      scopes: [],
      manualIPsText: '',
      attachments: [],
    }
  }
}

// ── scope 多选切换 ────────────────────────────────────────────────────────
function toggleScope(item) {
  if (isScopeDisabled(item)) return
  const idx = modal.value.scopes.findIndex(
    s => s.type === item.type && (s.target_id || '') === (item.target_id || '')
  )
  if (idx === -1) {
    modal.value.scopes.push({
      type: item.type,
      target_id: item.target_id || '',
      target_name: item.target_name,
    })
  } else {
    modal.value.scopes.splice(idx, 1)
  }
  scopeError.value = false
}

// ── 附件操作 ──────────────────────────────────────────────────────────────
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
      const existing = modal.value.attachments.findIndex(a => a.name === data.name)
      if (existing !== -1) modal.value.attachments[existing] = { name: data.name, ips: data.ips }
      else modal.value.attachments.push({ name: data.name, ips: data.ips })
    } catch {}
  }
  uploading.value = false
  e.target.value = ''
}

function removeAttachment(idx) {
  modal.value.attachments.splice(idx, 1)
}

// ── 保存 ─────────────────────────────────────────────────────────────────
async function save() {
  if (!modal.value.scopes.length) {
    scopeError.value = true
    return
  }
  saving.value = true
  try {
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

// ── 删除 ─────────────────────────────────────────────────────────────────
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

// ── 工具：文本 → IP 数组 ──────────────────────────────────────────────────
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
