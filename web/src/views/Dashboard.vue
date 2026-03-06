<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Stat cards -->
    <div class="grid grid-cols-2 xl:grid-cols-4 gap-4">
      <StatCard v-for="s in stats" :key="s.label" v-bind="s" />
    </div>

    <!-- Charts row -->
    <div class="grid grid-cols-1 xl:grid-cols-3 gap-4">
      <!-- Traffic chart -->
      <div class="xl:col-span-2 glass-card p-6">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h3 class="font-semibold text-slate-800">端口转发流量</h3>
            <p class="text-xs text-slate-400 mt-0.5">实时入站 / 出站字节数</p>
          </div>
          <span class="badge badge-blue">Live</span>
        </div>
        <apexchart type="area" height="200" :options="trafficOptions" :series="trafficSeries" />
      </div>

      <!-- Cert expiry -->
      <div class="glass-card p-6">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h3 class="font-semibold text-slate-800">证书有效期</h3>
            <p class="text-xs text-slate-400 mt-0.5">到期剩余天数</p>
          </div>
          <Shield :size="18" class="text-amber-500" />
        </div>
        <div v-if="certs.length === 0" class="flex flex-col items-center justify-center py-8 text-slate-300">
          <Shield :size="40" class="mb-2" />
          <span class="text-sm">暂无证书</span>
        </div>
        <div v-else class="space-y-3">
          <div v-for="cert in certs" :key="cert.id">
            <div class="flex items-center justify-between text-xs mb-1">
              <span class="font-medium text-slate-700 truncate max-w-[120px]">{{ cert.domain }}</span>
              <span :class="cert.days_left < 14 ? 'text-red-500' : cert.days_left < 30 ? 'text-amber-500' : 'text-emerald-600'"
                    class="font-bold">{{ cert.days_left }}天</span>
            </div>
            <div class="h-2 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full rounded-full transition-all duration-700"
                   :style="certBarStyle(cert.days_left)"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- DDNS IP History -->
    <div class="glass-card p-6">
      <div class="flex items-center justify-between mb-4">
        <div>
          <h3 class="font-semibold text-slate-800">DDNS IP 变化历史</h3>
          <p class="text-xs text-slate-400 mt-0.5">最近 IP 地址变更记录</p>
        </div>
        <Globe :size="18" class="text-emerald-500" />
      </div>
      <div v-if="ddnsRules.length === 0" class="text-center py-8 text-slate-300">
        <Globe :size="40" class="mx-auto mb-2" />
        <span class="text-sm">暂无 DDNS 规则</span>
      </div>
      <div v-else class="space-y-4">
        <div v-for="rule in ddnsRules" :key="rule.id" class="border border-slate-100 rounded-xl p-4">
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center gap-2">
              <span class="status-dot" :class="rule.enabled ? 'active' : 'inactive'"></span>
              <span class="font-medium text-slate-800 text-sm">{{ rule.sub_domain ? rule.sub_domain + '.' : '' }}{{ rule.domain }}</span>
              <ProviderBadge :provider="rule.provider" />
            </div>
            <span class="font-mono text-xs text-slate-500 bg-slate-50 px-2 py-1 rounded">{{ rule.last_ip || '—' }}</span>
          </div>
          <!-- IP history timeline -->
          <div v-if="rule.ip_history?.length" class="flex items-end gap-1 h-8">
            <div v-for="(rec, i) in rule.ip_history.slice(-20)" :key="i"
                 class="flex-1 bg-emerald-400 rounded-sm opacity-70 hover:opacity-100 transition-opacity min-h-[4px]"
                 :style="`height: ${Math.max(4, (i+1)/20*32)}px`"
                 :title="`${rec.ip} @ ${new Date(rec.timestamp).toLocaleString()}`">
            </div>
          </div>
          <div v-else class="text-xs text-slate-300 italic">暂无变更历史</div>
        </div>
      </div>
    </div>

    <!-- Quick status grid -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
      <QuickStatusCard title="端口转发" :items="pfRules" color="blue"
                       :active-count="pfRules.filter(r=>r.enabled).length" />
      <QuickStatusCard title="Web 服务" :items="wsRules" color="purple"
                       :active-count="wsRules.filter(r=>r.enabled).length" />
      <div class="glass-card p-5">
        <h4 class="font-semibold text-slate-700 text-sm mb-3">系统信息</h4>
        <div class="space-y-2 text-xs">
          <div class="flex justify-between">
            <span class="text-slate-400">版本</span>
            <span class="font-mono text-slate-600">v1.0.0</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">运行时间</span>
            <span class="font-mono text-slate-600">{{ uptime }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">管理端口</span>
            <span class="font-mono text-slate-600">4455</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { Shield, Globe } from 'lucide-vue-next'
import { api } from '@/stores/auth'
import StatCard from '@/components/StatCard.vue'
import QuickStatusCard from '@/components/QuickStatusCard.vue'
import ProviderBadge from '@/components/ProviderBadge.vue'

const dashboard = ref({})
const certs = ref([])
const ddnsRules = ref([])
const pfRules = ref([])
const wsRules = ref([])
const uptime = ref('—')
const trafficData = ref({ in: Array(20).fill(0), out: Array(20).fill(0) })
let ws = null
let startTime = Date.now()

const stats = computed(() => [
  { label: '端口转发', value: dashboard.value.port_forwards || 0, gradient: 'from-blue-500 to-cyan-400', icon: 'ArrowLeftRight', unit: '条规则' },
  { label: 'DDNS', value: dashboard.value.ddns || 0, gradient: 'from-emerald-500 to-teal-400', icon: 'Globe', unit: '条规则' },
  { label: 'Web 服务', value: dashboard.value.web_services || 0, gradient: 'from-purple-500 to-pink-400', icon: 'Server', unit: '个服务' },
  { label: 'TLS 证书', value: dashboard.value.tls_certs || 0,
    gradient: (dashboard.value.certs_expiring_soon > 0) ? 'from-red-500 to-orange-400' : 'from-amber-500 to-yellow-400',
    icon: 'Shield', unit: '张证书', alert: dashboard.value.certs_expiring_soon > 0 ? `${dashboard.value.certs_expiring_soon} 即将到期` : null },
])

const trafficOptions = {
  chart: { type: 'area', toolbar: { show: false }, animations: { enabled: true, easing: 'linear', dynamicAnimation: { enabled: true, speed: 1000 } }, background: 'transparent' },
  stroke: { curve: 'smooth', width: 2 },
  fill: { type: 'gradient', gradient: { shadeIntensity: 1, opacityFrom: 0.4, opacityTo: 0.05 } },
  colors: ['#3b82f6', '#10b981'],
  xaxis: { labels: { show: false }, axisBorder: { show: false }, axisTicks: { show: false } },
  yaxis: { labels: { style: { colors: '#94a3b8', fontSize: '11px' }, formatter: v => formatBytes(v) } },
  grid: { borderColor: '#f1f5f9', strokeDashArray: 4 },
  legend: { labels: { colors: '#64748b' } },
  tooltip: { theme: 'light', y: { formatter: v => formatBytes(v) } },
  dataLabels: { enabled: false },
}

const trafficSeries = computed(() => [
  { name: '入站', data: trafficData.value.in },
  { name: '出站', data: trafficData.value.out },
])

function certBarStyle(days) {
  const pct = Math.min(100, (days / 90) * 100)
  const color = days < 14 ? '#ef4444' : days < 30 ? '#f59e0b' : '#10b981'
  return `width: ${pct}%; background: ${color}`
}

function formatBytes(b) {
  if (b > 1e9) return (b/1e9).toFixed(1) + 'GB'
  if (b > 1e6) return (b/1e6).toFixed(1) + 'MB'
  if (b > 1e3) return (b/1e3).toFixed(1) + 'KB'
  return b + 'B'
}

async function load() {
  try {
    const [db, certsRes, ddnsRes, pfRes, wsRes] = await Promise.all([
      api.get('/dashboard'),
      api.get('/tls'),
      api.get('/ddns'),
      api.get('/portforward'),
      api.get('/webservice'),
    ])
    dashboard.value = db.data
    certs.value = certsRes.data
    ddnsRules.value = ddnsRes.data
    pfRules.value = pfRes.data
    wsRules.value = wsRes.data
  } catch {}
}

function connectWS() {
  const token = localStorage.getItem('vane_token')
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  ws = new WebSocket(`${proto}://${location.host}/api/ws/stats?token=${token}`)
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data)
    if (msg.type === 'stats') {
      let totalIn = 0, totalOut = 0
      Object.values(msg.data).forEach(s => { totalIn += s.bytes_in || 0; totalOut += s.bytes_out || 0 })
      trafficData.value.in = [...trafficData.value.in.slice(1), totalIn]
      trafficData.value.out = [...trafficData.value.out.slice(1), totalOut]
    }
  }
  ws.onclose = () => setTimeout(connectWS, 3000)
}

let uptimeTimer
onMounted(() => {
  load()
  connectWS()
  uptimeTimer = setInterval(() => {
    const s = Math.floor((Date.now() - startTime) / 1000)
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60
    uptime.value = `${h}h ${m}m ${sec}s`
  }, 1000)
})
onUnmounted(() => { ws?.close(); clearInterval(uptimeTimer) })
</script>
