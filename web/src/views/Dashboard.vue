<template>
  <div class="space-y-4 sm:space-y-5 animate-fade-in">

    <!-- ══ First-login welcome modal ════════════════════════════════════ -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showWelcomeModal"
             class="fixed inset-0 z-50 flex items-center justify-center p-4"
             style="background: rgba(0,0,0,0.45); backdrop-filter: blur(4px);">
          <div class="bg-white rounded-2xl shadow-2xl w-full max-w-md p-6 sm:p-8">
            <div class="flex items-center justify-center w-12 h-12 rounded-2xl bg-purple-100 mb-4 mx-auto">
              <ShieldAlert :size="24" class="text-purple-600" />
            </div>
            <h3 class="text-lg font-bold text-slate-800 text-center mb-2">欢迎使用 Vane 👋</h3>
            <p class="text-slate-500 text-sm text-center leading-relaxed mb-6">
              检测到您正在首次登录，建议前往<span class="font-semibold text-slate-700">「设置」</span>修改默认用户名、密码及安全访问路径，以保障系统安全。
            </p>
            <div class="flex gap-3">
              <button @click="dismissModal"
                      class="flex-1 py-2.5 rounded-xl border border-slate-200 text-slate-600 text-sm font-medium hover:bg-slate-50 active:scale-[0.98] transition-all">
                暂不修改
              </button>
              <button @click="goToSettings"
                      class="flex-1 py-2.5 rounded-xl bg-purple-600 text-white text-sm font-semibold hover:bg-purple-700 active:scale-[0.98] transition-all shadow-sm">
                前往设置 →
              </button>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- ══ 系统信息（顶部，最大） ══════════════════════════════════════ -->
    <div class="glass-card p-4 sm:p-6">
      <div class="flex items-center justify-between mb-4 sm:mb-5">
        <div>
          <h2 class="font-bold text-slate-800 text-base sm:text-lg">系统信息</h2>
          <p class="text-xs text-slate-400 mt-0.5">主机运行状态</p>
        </div>
        <Monitor :size="18" class="text-blue-400" />
      </div>

      <div v-if="!sysinfo" class="flex items-center justify-center py-10 text-slate-300 text-xs">
        <Loader2 :size="18" class="animate-spin mr-2" /> 加载中...
      </div>

      <div v-else class="space-y-4">
        <!-- OS / Kernel / Uptime -->
        <div class="grid grid-cols-2 sm:grid-cols-3 gap-2 sm:gap-3">
          <div class="bg-slate-50 rounded-xl px-3 py-2.5">
            <div class="text-xs text-slate-400 mb-1">操作系统</div>
            <div class="text-xs sm:text-sm font-medium text-slate-700 truncate leading-snug" :title="sysinfo.os">{{ sysinfo.os || '—' }}</div>
          </div>
          <div class="bg-slate-50 rounded-xl px-3 py-2.5">
            <div class="text-xs text-slate-400 mb-1">内核版本</div>
            <div class="text-xs sm:text-sm font-mono font-medium text-slate-700 truncate" :title="sysinfo.kernel">{{ sysinfo.kernel || '—' }}</div>
          </div>
          <div class="bg-slate-50 rounded-xl px-3 py-2.5 col-span-2 sm:col-span-1">
            <div class="text-xs text-slate-400 mb-1">运行时间</div>
            <div class="text-xs sm:text-sm font-medium text-slate-700">{{ sysinfo.uptime?.human || '—' }}</div>
          </div>
        </div>

        <!-- Memory + Disk -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div class="bg-slate-50 rounded-xl px-4 py-3">
            <div class="flex items-center justify-between text-xs mb-2">
              <div class="flex items-center gap-1.5 text-slate-600 font-medium">
                <Cpu :size="13" class="text-blue-400" /> 内存
              </div>
              <div class="flex items-center gap-2 text-slate-400">
                <span>{{ fmtBytes(sysinfo.memory?.used_kb * 1024) }} / {{ fmtBytes(sysinfo.memory?.total_kb * 1024) }}</span>
                <span class="font-bold text-sm" :class="memColor(sysinfo.memory?.pct)">{{ sysinfo.memory?.pct }}%</span>
              </div>
            </div>
            <div class="h-2.5 bg-white rounded-full overflow-hidden shadow-inner">
              <div class="h-full rounded-full transition-all duration-700"
                   :style="`width:${sysinfo.memory?.pct}%; background:${memBg(sysinfo.memory?.pct)}`"></div>
            </div>
          </div>
          <div class="bg-slate-50 rounded-xl px-4 py-3">
            <div class="flex items-center justify-between text-xs mb-2">
              <div class="flex items-center gap-1.5 text-slate-600 font-medium">
                <HardDrive :size="13" class="text-purple-400" /> 磁盘 (/)
              </div>
              <div class="flex items-center gap-2 text-slate-400">
                <span>{{ fmtBytes(sysinfo.disk?.used_kb * 1024) }} / {{ fmtBytes(sysinfo.disk?.total_kb * 1024) }}</span>
                <span class="font-bold text-sm" :class="memColor(sysinfo.disk?.pct)">{{ sysinfo.disk?.pct }}%</span>
              </div>
            </div>
            <div class="h-2.5 bg-white rounded-full overflow-hidden shadow-inner">
              <div class="h-full rounded-full transition-all duration-700"
                   :style="`width:${sysinfo.disk?.pct}%; background:${memBg(sysinfo.disk?.pct)}`"></div>
            </div>
          </div>
        </div>

        <!-- 网卡流量 + 网卡 IP -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div class="bg-slate-50 rounded-xl px-4 py-3">
            <div class="flex items-center gap-1.5 text-xs text-slate-500 font-medium mb-2.5">
              <Activity :size="13" class="text-emerald-400" /> 网卡流量
            </div>
            <div v-if="!sysinfo.network?.length" class="text-xs text-slate-300 italic">无数据</div>
            <div v-else class="space-y-1.5">
              <div v-for="n in sysinfo.network" :key="n.iface" class="flex items-center gap-2 text-xs">
                <span class="font-mono text-slate-600 w-14 truncate flex-shrink-0">{{ n.iface }}</span>
                <span class="text-blue-500 flex-1">↓ {{ fmtBytes(n.rx_bytes) }}</span>
                <span class="text-emerald-500">↑ {{ fmtBytes(n.tx_bytes) }}</span>
              </div>
            </div>
          </div>
          <div class="bg-slate-50 rounded-xl px-4 py-3">
            <div class="flex items-center gap-1.5 text-xs text-slate-500 font-medium mb-2.5">
              <NetworkIcon :size="13" class="text-indigo-400" /> 网卡 IP
            </div>
            <div v-if="!sysinfo.ifaces?.length" class="text-xs text-slate-300 italic">无数据</div>
            <div v-else class="space-y-1.5">
              <div v-for="iface in sysinfo.ifaces" :key="iface.name" class="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                <span class="font-mono text-xs font-semibold text-slate-600 flex-shrink-0">{{ iface.name }}</span>
                <span v-for="ip in iface.ips" :key="ip" class="font-mono text-xs text-slate-400 break-all">{{ ip }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══ 四个等宽服务卡片：移动端2列，桌面端4列 ══════════════════ -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">

      <!-- 动态域名 -->
      <div class="glass-card p-4 sm:p-5 flex flex-col min-h-[190px] sm:min-h-[220px]">
        <div class="flex items-start justify-between mb-3">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-9 h-9 rounded-xl flex items-center justify-center text-white shadow flex-shrink-0"
                 style="background: linear-gradient(135deg,#10b981,#059669)">
              <Globe :size="16" />
            </div>
            <div class="min-w-0">
              <div class="font-semibold text-slate-800 text-sm leading-tight">动态域名</div>
              <div class="text-xs text-slate-400 mt-0.5 truncate">{{ ddnsRules.filter(r=>r.enabled).length }}/{{ ddnsRules.length }} 条启用</div>
            </div>
          </div>
          <div class="text-3xl font-bold text-slate-900 tabular-nums leading-none flex-shrink-0 ml-1">{{ ddnsRules.length }}</div>
        </div>
        <div v-if="ddnsRules.length === 0" class="flex-1 flex items-center justify-center text-slate-300 text-xs">暂无规则</div>
        <div v-else class="flex-1 space-y-1 overflow-hidden">
          <div v-for="r in ddnsRules.slice(0,5)" :key="r.id"
               class="flex items-center gap-2 py-1.5 border-b border-slate-50 last:border-0">
            <span class="status-dot flex-shrink-0" :class="r.enabled ? 'active' : 'inactive'"></span>
            <span class="text-slate-700 font-medium text-xs truncate flex-1 font-mono">{{ domainLabel(r) }}</span>
          </div>
          <div v-if="ddnsRules.length > 5" class="text-xs text-slate-400 text-center pt-1">+{{ ddnsRules.length - 5 }} 条</div>
        </div>
      </div>

      <!-- 网页服务 -->
      <div class="glass-card p-4 sm:p-5 flex flex-col min-h-[190px] sm:min-h-[220px]">
        <div class="flex items-start justify-between mb-3">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-9 h-9 rounded-xl flex items-center justify-center text-white shadow flex-shrink-0"
                 style="background: linear-gradient(135deg,#8b5cf6,#ec4899)">
              <Server :size="16" />
            </div>
            <div class="min-w-0">
              <div class="font-semibold text-slate-800 text-sm leading-tight">网页服务</div>
              <div class="text-xs text-slate-400 mt-0.5 truncate">{{ wsRules.filter(r=>r.enabled).length }}/{{ wsRules.length }} 个运行中</div>
            </div>
          </div>
          <div class="text-3xl font-bold text-slate-900 tabular-nums leading-none flex-shrink-0 ml-1">{{ wsRules.length }}</div>
        </div>
        <div v-if="wsRules.length === 0" class="flex-1 flex items-center justify-center text-slate-300">
          <div class="text-center">
            <Server :size="28" class="mx-auto mb-1.5 opacity-40" />
            <span class="text-xs">暂无网页服务</span>
          </div>
        </div>
        <div v-else class="flex-1 space-y-1 overflow-hidden">
          <div v-for="svc in wsRules.slice(0,5)" :key="svc.id"
               class="flex items-center gap-2 py-1.5 border-b border-slate-50 last:border-0">
            <span class="status-dot flex-shrink-0" :class="svc.enabled ? 'active' : 'inactive'"></span>
            <span class="font-medium text-slate-700 text-xs flex-1 truncate">{{ svc.name }}</span>
            <span class="font-mono text-xs text-slate-400 flex-shrink-0">:{{ svc.listen_port }}</span>
          </div>
          <div v-if="wsRules.length > 5" class="text-xs text-slate-400 text-center pt-1">+{{ wsRules.length - 5 }} 条</div>
        </div>
      </div>

      <!-- 证书 -->
      <div class="glass-card p-4 sm:p-5 flex flex-col min-h-[190px] sm:min-h-[220px]">
        <div class="flex items-start justify-between mb-3">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-9 h-9 rounded-xl flex items-center justify-center text-white shadow flex-shrink-0"
                 :style="dashboard.certs_expiring_soon > 0
                   ? 'background:linear-gradient(135deg,#ef4444,#f97316)'
                   : 'background:linear-gradient(135deg,#f59e0b,#eab308)'">
              <Shield :size="16" />
            </div>
            <div class="min-w-0">
              <div class="font-semibold text-slate-800 text-sm leading-tight">证书</div>
              <div class="text-xs mt-0.5 truncate"
                   :class="dashboard.certs_expiring_soon > 0 ? 'text-red-400' : 'text-slate-400'">
                {{ dashboard.certs_expiring_soon > 0 ? `${dashboard.certs_expiring_soon} 张即将到期` : '全部正常' }}
              </div>
            </div>
          </div>
          <div class="text-3xl font-bold text-slate-900 tabular-nums leading-none flex-shrink-0 ml-1">{{ certs.length }}</div>
        </div>
        <div v-if="certs.length === 0" class="flex-1 flex items-center justify-center text-slate-300">
          <div class="text-center">
            <Shield :size="28" class="mx-auto mb-1.5 opacity-40" />
            <span class="text-xs">暂无证书</span>
          </div>
        </div>
        <div v-else class="flex-1 space-y-2 overflow-hidden">
          <div v-for="cert in certs.slice(0,4)" :key="cert.id">
            <div class="flex items-center justify-between mb-1">
              <span class="font-mono text-xs text-slate-600 truncate flex-1 mr-1">{{ cert.domain }}</span>
              <span :class="cert.days_left < 14 ? 'text-red-500' : cert.days_left < 30 ? 'text-amber-500' : 'text-emerald-600'"
                    class="font-bold text-xs flex-shrink-0">
                {{ cert.days_left >= 0 ? cert.days_left + '天' : '?' }}
              </span>
            </div>
            <div class="h-1.5 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full rounded-full transition-all duration-700" :style="certBarStyle(cert.days_left)"></div>
            </div>
          </div>
          <div v-if="certs.length > 4" class="text-xs text-slate-400 text-center pt-1">+{{ certs.length - 4 }} 张</div>
        </div>
      </div>

      <!-- 端口转发 -->
      <div class="glass-card p-4 sm:p-5 flex flex-col min-h-[190px] sm:min-h-[220px]">
        <div class="flex items-start justify-between mb-3">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-9 h-9 rounded-xl flex items-center justify-center text-white shadow flex-shrink-0"
                 style="background: linear-gradient(135deg,#3b82f6,#06b6d4)">
              <ArrowLeftRight :size="16" />
            </div>
            <div class="min-w-0">
              <div class="font-semibold text-slate-800 text-sm leading-tight">端口转发</div>
              <div class="text-xs text-slate-400 mt-0.5 truncate">{{ pfRules.filter(r=>r.enabled).length }}/{{ pfRules.length }} 条启用</div>
            </div>
          </div>
          <div class="text-3xl font-bold text-slate-900 tabular-nums leading-none flex-shrink-0 ml-1">{{ pfRules.length }}</div>
        </div>
        <div v-if="pfRules.length === 0" class="flex-1 flex items-center justify-center text-slate-300 text-xs">暂无规则</div>
        <div v-else class="flex-1 space-y-1 overflow-hidden">
          <div v-for="r in pfRules.slice(0,5)" :key="r.id"
               class="flex items-center gap-2 py-1.5 border-b border-slate-50 last:border-0">
            <span class="status-dot flex-shrink-0" :class="r.enabled ? 'active' : 'inactive'"></span>
            <span class="text-slate-700 font-medium text-xs truncate flex-1">{{ r.name }}</span>
            <span class="text-slate-400 font-mono text-xs flex-shrink-0">:{{ r.listen_port }}</span>
          </div>
          <div v-if="pfRules.length > 5" class="text-xs text-slate-400 text-center pt-1">+{{ pfRules.length - 5 }} 条</div>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import {
  Shield, Server, ShieldAlert, Monitor, Cpu, HardDrive,
  Activity, Network as NetworkIcon, Loader2, ArrowLeftRight, Globe
} from 'lucide-vue-next'
import { useRouter } from 'vue-router'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'

const i18n = useI18n()
const router = useRouter()
const dashboard = ref({})
const certs = ref([])
const ddnsRules = ref([])
const pfRules = ref([])
const wsRules = ref([])
const sysinfo = ref(null)

// ── First-login modal ──────────────────────────────────────────────────────
const WELCOME_KEY = 'vane_welcome_shown'
const showWelcomeModal = ref(false)
function checkWelcomeModal() {
  if (!localStorage.getItem(WELCOME_KEY)) showWelcomeModal.value = true
}
function dismissModal() {
  localStorage.setItem(WELCOME_KEY, '1')
  showWelcomeModal.value = false
}
function goToSettings() {
  localStorage.setItem(WELCOME_KEY, '1')
  showWelcomeModal.value = false
  router.push('/settings')
}

// ── Helpers ────────────────────────────────────────────────────────────────
function fmtBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i]
}
function memColor(pct) {
  const p = parseFloat(pct)
  if (p >= 90) return 'text-red-500'
  if (p >= 70) return 'text-amber-500'
  return 'text-emerald-600'
}
function memBg(pct) {
  const p = parseFloat(pct)
  if (p >= 90) return '#ef4444'
  if (p >= 70) return '#f59e0b'
  return '#10b981'
}
function certBarStyle(days) {
  const pct = Math.min(100, Math.max(0, (days / 90) * 100))
  const color = days < 14 ? '#ef4444' : days < 30 ? '#f59e0b' : '#10b981'
  return `width: ${pct}%; background: ${color}`
}
function domainLabel(r) {
  return (r.sub_domain ? r.sub_domain + '.' : '') + (r.domain || '')
}

// ── Data loading ───────────────────────────────────────────────────────────
async function load() {
  try {
    const [db, certsRes, ddnsRes, pfRes, wsRes, sysinfoRes] = await Promise.all([
      api.get('/dashboard'), api.get('/tls'), api.get('/ddns'),
      api.get('/portforward'), api.get('/webservice'), api.get('/sysinfo'),
    ])
    dashboard.value = db.data
    certs.value = certsRes.data
    ddnsRules.value = ddnsRes.data
    pfRules.value = pfRes.data
    wsRules.value = wsRes.data
    sysinfo.value = sysinfoRes.data
  } catch {}
}

let sysinfoTimer
onMounted(() => {
  load()
  checkWelcomeModal()
  sysinfoTimer = setInterval(async () => {
    try { sysinfo.value = (await api.get('/sysinfo')).data } catch {}
  }, 10000)
})
onUnmounted(() => clearInterval(sysinfoTimer))
</script>

<style scoped>
.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
</style>
