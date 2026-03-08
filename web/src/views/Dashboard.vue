<template>
  <div class="space-y-4 sm:space-y-6 animate-fade-in">

    <!-- First-login welcome modal -->
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

    <!-- Stat cards: 2 cols on mobile, 4 on xl -->
    <div class="grid grid-cols-2 xl:grid-cols-4 gap-3 sm:gap-4">
      <StatCard v-for="s in stats" :key="s.label" v-bind="s" />
    </div>

    <!-- Row: Web services (smaller) + System Info (larger) -->
    <div class="grid grid-cols-1 lg:grid-cols-5 gap-3 sm:gap-4">

      <!-- Web services: 2/5 -->
      <div class="lg:col-span-2 glass-card p-4 sm:p-5">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('webservice') }}</h3>
            <p class="text-xs text-slate-400 mt-0.5">{{ i18n.t('quickStatus') }}</p>
          </div>
          <Server :size="16" class="text-purple-400" />
        </div>
        <div v-if="wsRules.length === 0" class="flex flex-col items-center justify-center py-6 text-slate-300">
          <Server :size="28" class="mb-1.5" />
          <span class="text-xs">暂无 Web 服务</span>
        </div>
        <div v-else class="space-y-2">
          <div v-for="svc in wsRules" :key="svc.id"
               class="flex items-center gap-2 px-3 py-2 bg-slate-50 rounded-xl">
            <span class="status-dot flex-shrink-0" :class="svc.enabled ? 'active' : 'inactive'"></span>
            <span class="font-medium text-slate-700 text-xs flex-1 truncate">{{ svc.name }}</span>
            <span class="font-mono text-xs text-slate-400">:{{ svc.listen_port }}</span>
            <span v-if="svc.enable_https" class="badge badge-green text-xs">HTTPS</span>
            <span v-else class="badge badge-slate text-xs">HTTP</span>
          </div>
        </div>
      </div>

      <!-- System Info: 3/5 -->
      <div class="lg:col-span-3 glass-card p-4 sm:p-5">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h3 class="font-semibold text-slate-800 text-sm">系统信息</h3>
            <p class="text-xs text-slate-400 mt-0.5">主机运行状态</p>
          </div>
          <Monitor :size="16" class="text-blue-400" />
        </div>

        <div v-if="!sysinfo" class="flex items-center justify-center py-8 text-slate-300 text-xs">
          <Loader2 :size="18" class="animate-spin mr-2" /> 加载中...
        </div>

        <div v-else class="space-y-4">
          <!-- OS / Kernel / Uptime row -->
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div class="bg-slate-50 rounded-xl px-3 py-2.5">
              <div class="text-xs text-slate-400 mb-0.5">操作系统</div>
              <div class="text-xs font-medium text-slate-700 truncate" :title="sysinfo.os">{{ sysinfo.os }}</div>
            </div>
            <div class="bg-slate-50 rounded-xl px-3 py-2.5">
              <div class="text-xs text-slate-400 mb-0.5">内核版本</div>
              <div class="text-xs font-mono font-medium text-slate-700 truncate" :title="sysinfo.kernel">{{ sysinfo.kernel }}</div>
            </div>
            <div class="bg-slate-50 rounded-xl px-3 py-2.5">
              <div class="text-xs text-slate-400 mb-0.5">运行时间</div>
              <div class="text-xs font-medium text-slate-700">{{ sysinfo.uptime?.human || '—' }}</div>
            </div>
          </div>

          <!-- Memory bar -->
          <div>
            <div class="flex items-center justify-between text-xs mb-1.5">
              <div class="flex items-center gap-1.5 text-slate-500 font-medium">
                <Cpu :size="12" class="text-blue-400" />
                内存
              </div>
              <div class="flex items-center gap-2 text-slate-400">
                <span>{{ fmtBytes(sysinfo.memory?.used_kb * 1024) }} / {{ fmtBytes(sysinfo.memory?.total_kb * 1024) }}</span>
                <span class="font-bold" :class="memColor(sysinfo.memory?.pct)">{{ sysinfo.memory?.pct }}%</span>
              </div>
            </div>
            <div class="h-2 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full rounded-full transition-all duration-700"
                   :style="`width:${sysinfo.memory?.pct}%; background:${memBg(sysinfo.memory?.pct)}`"></div>
            </div>
          </div>

          <!-- Disk bar -->
          <div>
            <div class="flex items-center justify-between text-xs mb-1.5">
              <div class="flex items-center gap-1.5 text-slate-500 font-medium">
                <HardDrive :size="12" class="text-purple-400" />
                磁盘 (/)
              </div>
              <div class="flex items-center gap-2 text-slate-400">
                <span>{{ fmtBytes(sysinfo.disk?.used_kb * 1024) }} / {{ fmtBytes(sysinfo.disk?.total_kb * 1024) }}</span>
                <span class="font-bold" :class="memColor(sysinfo.disk?.pct)">{{ sysinfo.disk?.pct }}%</span>
              </div>
            </div>
            <div class="h-2 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full rounded-full transition-all duration-700"
                   :style="`width:${sysinfo.disk?.pct}%; background:${memBg(sysinfo.disk?.pct)}`"></div>
            </div>
          </div>

          <!-- Network traffic + IPs -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <!-- Traffic -->
            <div class="bg-slate-50 rounded-xl px-3 py-2.5">
              <div class="flex items-center gap-1.5 text-xs text-slate-400 mb-2 font-medium">
                <Activity :size="12" class="text-emerald-400" /> 网卡流量
              </div>
              <div v-if="!sysinfo.network?.length" class="text-xs text-slate-300">无数据</div>
              <div v-else class="space-y-1">
                <div v-for="n in sysinfo.network" :key="n.iface" class="flex items-center justify-between text-xs">
                  <span class="font-mono text-slate-500 w-16 truncate">{{ n.iface }}</span>
                  <span class="text-blue-500">↓ {{ fmtBytes(n.rx_bytes) }}</span>
                  <span class="text-emerald-500">↑ {{ fmtBytes(n.tx_bytes) }}</span>
                </div>
              </div>
            </div>
            <!-- IPs -->
            <div class="bg-slate-50 rounded-xl px-3 py-2.5">
              <div class="flex items-center gap-1.5 text-xs text-slate-400 mb-2 font-medium">
                <Network :size="12" class="text-indigo-400" /> 网卡 IP
              </div>
              <div v-if="!sysinfo.ifaces?.length" class="text-xs text-slate-300">无数据</div>
              <div v-else class="space-y-1.5">
                <div v-for="iface in sysinfo.ifaces" :key="iface.name">
                  <div class="font-mono text-xs font-semibold text-slate-600">{{ iface.name }}</div>
                  <div v-for="ip in iface.ips" :key="ip" class="font-mono text-xs text-slate-400 pl-2 truncate">{{ ip }}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Row 3: Port forward + DDNS + Cert expiry -->
    <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3 sm:gap-4">
      <QuickStatusCard :title="i18n.t('portforward')" :items="pfRules" color="blue"
                       :active-count="pfRules.filter(r=>r.enabled).length" />
      <QuickStatusCard :title="i18n.t('ddns')" :items="ddnsRules.map(r=>({...r, name: (r.sub_domain ? r.sub_domain+'.' : '')+r.domain}))" color="green"
                       :active-count="ddnsRules.filter(r=>r.enabled).length" />
      <!-- Cert expiry -->
      <div class="glass-card p-4 sm:p-5 sm:col-span-2 xl:col-span-1">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h3 class="font-semibold text-slate-800 text-sm">{{ i18n.t('certExpiry') }}</h3>
            <p class="text-xs text-slate-400 mt-0.5">{{ i18n.t('certExpiryDesc') }}</p>
          </div>
          <Shield :size="16" class="text-amber-500" />
        </div>
        <div v-if="certs.length === 0" class="flex flex-col items-center justify-center py-6 text-slate-300">
          <Shield :size="32" class="mb-1.5" />
          <span class="text-xs">{{ i18n.t('noCerts') }}</span>
        </div>
        <div v-else class="space-y-3">
          <div v-for="cert in certs" :key="cert.id">
            <div class="flex items-center justify-between text-xs mb-1">
              <span class="font-medium text-slate-700 truncate max-w-[130px] font-mono">{{ cert.domain }}</span>
              <span :class="cert.days_left < 14 ? 'text-red-500' : cert.days_left < 30 ? 'text-amber-500' : 'text-emerald-600'"
                    class="font-bold">{{ cert.days_left >= 0 ? cert.days_left + '天' : '?' }}</span>
            </div>
            <div class="h-1.5 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full rounded-full transition-all duration-700" :style="certBarStyle(cert.days_left)"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { Shield, Server, ShieldAlert, Monitor, Cpu, HardDrive, Activity, Network, Loader2 } from 'lucide-vue-next'
import { useRouter } from 'vue-router'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'
import StatCard from '@/components/StatCard.vue'
import QuickStatusCard from '@/components/QuickStatusCard.vue'

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

// ── Stats ──────────────────────────────────────────────────────────────────
const stats = computed(() => [
  { label: i18n.t('portforward'), value: dashboard.value.port_forwards || 0, gradient: 'from-blue-500 to-cyan-400', icon: 'ArrowLeftRight', unit: i18n.t('portForwardRules') },
  { label: i18n.t('ddns'),        value: dashboard.value.ddns || 0,           gradient: 'from-emerald-500 to-teal-400', icon: 'Globe', unit: i18n.t('portForwardRules') },
  { label: i18n.t('webservice'),  value: dashboard.value.web_services || 0,   gradient: 'from-purple-500 to-pink-400', icon: 'Server', unit: i18n.t('webServices') },
  { label: i18n.t('tls'),
    value: dashboard.value.tls_certs || 0,
    gradient: (dashboard.value.certs_expiring_soon > 0) ? 'from-red-500 to-orange-400' : 'from-amber-500 to-yellow-400',
    icon: 'Shield', unit: i18n.t('certCount'),
    alert: dashboard.value.certs_expiring_soon > 0 ? `${dashboard.value.certs_expiring_soon} ${i18n.t('certSoonExpire')}` : null },
])

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
  // Refresh sysinfo every 10s
  sysinfoTimer = setInterval(async () => {
    try {
      const res = await api.get('/sysinfo')
      sysinfo.value = res.data
    } catch {}
  }, 10000)
})
onUnmounted(() => clearInterval(sysinfoTimer))
</script>

<style scoped>
.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
</style>
