<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Stat cards -->
    <div class="grid grid-cols-2 xl:grid-cols-4 gap-4">
      <StatCard v-for="s in stats" :key="s.label" v-bind="s" />
    </div>

    <!-- Charts row -->
    <div class="grid grid-cols-1 xl:grid-cols-3 gap-4">
      <!-- Web services status (replaces useless traffic chart) -->
      <div class="xl:col-span-2 glass-card p-6">
        <div class="flex items-center justify-between mb-5">
          <div>
            <h3 class="font-semibold text-slate-800">{{ i18n.t('webservice') }}</h3>
            <p class="text-xs text-slate-400 mt-0.5">{{ i18n.t('webservice') }} — {{ i18n.t('quickStatus') }}</p>
          </div>
          <Server :size="18" class="text-purple-400" />
        </div>
        <div v-if="wsRules.length === 0" class="flex flex-col items-center justify-center py-10 text-slate-300">
          <Server :size="36" class="mb-2" />
          <span class="text-sm">暂无 Web 服务</span>
        </div>
        <div v-else class="space-y-3">
          <div v-for="svc in wsRules" :key="svc.id"
               class="flex items-center gap-3 px-4 py-3 bg-slate-50 rounded-xl">
            <span class="status-dot flex-shrink-0" :class="svc.enabled ? 'active' : 'inactive'"></span>
            <span class="font-medium text-slate-700 text-sm flex-1 truncate">{{ svc.name }}</span>
            <span class="font-mono text-xs text-slate-400 bg-white border border-slate-100 px-2 py-0.5 rounded-lg">:{{ svc.listen_port }}</span>
            <span v-if="svc.enable_https" class="badge badge-green text-xs">HTTPS</span>
            <span v-else class="badge badge-slate text-xs">HTTP</span>
            <span class="text-xs text-slate-400">{{ (svc.routes||[]).length }} 条路由</span>
          </div>
        </div>
      </div>

      <!-- Cert expiry -->
      <div class="glass-card p-6">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h3 class="font-semibold text-slate-800">{{ i18n.t('certExpiry') }}</h3>
            <p class="text-xs text-slate-400 mt-0.5">{{ i18n.t('certExpiryDesc') }}</p>
          </div>
          <Shield :size="18" class="text-amber-500" />
        </div>
        <div v-if="certs.length === 0" class="flex flex-col items-center justify-center py-8 text-slate-300">
          <Shield :size="40" class="mb-2" />
          <span class="text-sm">{{ i18n.t('noCerts') }}</span>
        </div>
        <div v-else class="space-y-3">
          <div v-for="cert in certs" :key="cert.id">
            <div class="flex items-center justify-between text-xs mb-1">
              <span class="font-medium text-slate-700 truncate max-w-[130px] font-mono">{{ cert.domain }}</span>
              <span :class="cert.days_left < 14 ? 'text-red-500' : cert.days_left < 30 ? 'text-amber-500' : 'text-emerald-600'"
                    class="font-bold">{{ cert.days_left >= 0 ? cert.days_left + '天' : '?' }}</span>
            </div>
            <div class="h-2 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full rounded-full transition-all duration-700" :style="certBarStyle(cert.days_left)"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Port forward + System info row -->
    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      <QuickStatusCard :title="i18n.t('portforward')" :items="pfRules" color="blue"
                       :active-count="pfRules.filter(r=>r.enabled).length" />
      <QuickStatusCard :title="i18n.t('ddns')" :items="ddnsRules.map(r=>({...r, name: (r.sub_domain ? r.sub_domain+'.' : '')+r.domain}))" color="green"
                       :active-count="ddnsRules.filter(r=>r.enabled).length" />
      <div class="glass-card p-5">
        <h4 class="font-semibold text-slate-700 text-sm mb-4">{{ i18n.t('sysInfo') }}</h4>
        <div class="space-y-3 text-xs">
          <div class="flex justify-between items-center">
            <span class="text-slate-400">{{ i18n.t('version') }}</span>
            <span class="font-mono text-slate-600 bg-slate-100 px-2 py-0.5 rounded">v1.0.0</span>
          </div>
          <div class="flex justify-between items-center">
            <span class="text-slate-400">{{ i18n.t('uptime') }}</span>
            <span class="font-mono text-slate-600">{{ uptime }}</span>
          </div>
          <div class="flex justify-between items-center">
            <span class="text-slate-400">{{ i18n.t('adminPort') }}</span>
            <span class="font-mono text-slate-600">4455</span>
          </div>
          <div class="flex justify-between items-center">
            <span class="text-slate-400">Web 服务</span>
            <span class="font-mono text-slate-600">{{ wsRules.filter(s=>s.enabled).length }} / {{ wsRules.length }}</span>
          </div>
          <div class="flex justify-between items-center">
            <span class="text-slate-400">TLS 证书</span>
            <span class="font-mono text-slate-600">{{ certs.length }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue'
import { Shield, Server } from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'
import StatCard from '@/components/StatCard.vue'
import QuickStatusCard from '@/components/QuickStatusCard.vue'

const i18n = useI18n()
const dashboard = ref({})
const certs = ref([])
const ddnsRules = ref([])
const pfRules = ref([])
const wsRules = ref([])
const uptime = ref('—')
let startTime = Date.now()

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

function certBarStyle(days) {
  const pct = Math.min(100, Math.max(0, (days / 90) * 100))
  const color = days < 14 ? '#ef4444' : days < 30 ? '#f59e0b' : '#10b981'
  return `width: ${pct}%; background: ${color}`
}

async function load() {
  try {
    const [db, certsRes, ddnsRes, pfRes, wsRes] = await Promise.all([
      api.get('/dashboard'), api.get('/tls'), api.get('/ddns'),
      api.get('/portforward'), api.get('/webservice'),
    ])
    dashboard.value = db.data
    certs.value = certsRes.data
    ddnsRules.value = ddnsRes.data
    pfRules.value = pfRes.data
    wsRules.value = wsRes.data
  } catch {}
}

let uptimeTimer
onMounted(() => {
  load()
  uptimeTimer = setInterval(() => {
    const s = Math.floor((Date.now() - startTime) / 1000)
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60
    uptime.value = `${h}h ${m}m ${sec}s`
  }, 1000)
})
onUnmounted(() => clearInterval(uptimeTimer))
</script>
