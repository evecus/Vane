<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ t('wsTitle') }}</h1>
        <p class="page-subtitle">{{ t('wsSubtitle') }}</p>
      </div>
      <div class="flex gap-2">
        <button class="btn-secondary" @click="logsModal=true">
          <ScrollText :size="15" /> {{ t('accessLogs') }}
        </button>
        <button class="btn-primary" @click="openServiceModal()">
          <Plus :size="16" /> {{ t('addService') }}
        </button>
      </div>
    </div>

    <!-- Empty state -->
    <div v-if="services.length === 0" class="glass-card p-16 text-center">
      <div class="w-16 h-16 rounded-3xl bg-purple-50 flex items-center justify-center mx-auto mb-4">
        <Server :size="28" class="text-purple-400" />
      </div>
      <p class="text-slate-500 font-medium">{{ t('noServices') }}</p>
      <p class="text-slate-400 text-sm mt-1">{{ t('noServicesHint') }}</p>
    </div>

    <!-- Service cards -->
    <div v-for="svc in services" :key="svc.id" class="glass-card overflow-hidden">
      <!-- Service header -->
      <div class="flex items-center gap-4 p-5 border-b border-slate-100 group">
        <div class="w-12 h-12 rounded-2xl flex items-center justify-center flex-shrink-0 text-white font-bold text-sm"
             :style="svc.enabled ? 'background:linear-gradient(135deg,#8b5cf6,#ec4899)' : 'background:#e2e8f0;color:#94a3b8'">
          :{{ svc.listen_port }}
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="font-semibold text-slate-900">{{ svc.name || t('unnamedService') }}</span>
            <span class="status-dot" :class="svc.enabled ? 'active' : 'inactive'"></span>
            <span v-if="svc.enable_https" class="badge badge-green">HTTPS</span>
            <span v-else class="badge badge-slate">HTTP only</span>
            <span class="badge badge-purple">{{ t('port', {port: svc.listen_port}) }}</span>
          </div>
          <div class="text-xs text-slate-400 mt-0.5">
            {{ t('routeCount', {n: (svc.routes||[]).length}) }} ·
            {{ svc.enable_https ? t('httpRedirect') : t('httpOnly') }}
          </div>
        </div>
        <div class="flex items-center gap-2 flex-shrink-0">
          <button @click="openLogsFor(svc.id)" class="btn-ghost btn-sm text-slate-500" :title="t('accessLogs')">
            <ScrollText :size="14" />
          </button>
          <label class="toggle">
            <input type="checkbox" :checked="svc.enabled" @change="toggleService(svc.id)" />
            <div class="toggle-track"></div>
            <div class="toggle-thumb"></div>
          </label>
          <button @click="openServiceModal(svc)" class="btn-ghost btn-sm opacity-0 group-hover:opacity-100">
            <Pencil :size="14" />
          </button>
          <button @click="delService(svc.id)" class="btn-ghost btn-sm text-red-400 hover:bg-red-50 opacity-0 group-hover:opacity-100">
            <Trash2 :size="14" />
          </button>
        </div>
      </div>

      <!-- Sub-routes table -->
      <div class="p-4">
        <div class="flex items-center justify-between mb-3">
          <span class="text-xs font-bold text-slate-400 uppercase tracking-widest">{{ t('subRoutes') }}</span>
          <button @click="openRouteModal(svc.id)" class="btn-ghost btn-sm text-purple-600 hover:bg-purple-50">
            <Plus :size="12" /> {{ t('addSubRoute') }}
          </button>
        </div>

        <div v-if="!(svc.routes&&svc.routes.length)" class="text-center py-6 text-slate-300 text-sm border border-dashed border-slate-200 rounded-xl">
          {{ t('noSubRoutes') }}
        </div>
        <div v-else class="space-y-2">
          <div v-for="route in svc.routes" :key="route.id"
               class="flex items-center gap-3 px-4 py-3 bg-slate-50 rounded-xl group/route hover:bg-purple-50/50 transition-colors">
            <span class="status-dot flex-shrink-0" :class="route.enabled ? 'active' : 'inactive'"></span>

            <!-- Route info -->
            <div class="flex-1 flex items-center gap-2 flex-wrap min-w-0">
              <span class="font-mono text-sm font-semibold text-purple-700 bg-purple-100 px-2 py-0.5 rounded-lg">
                {{ svc.enable_https ? 'https' : 'http' }}://{{ route.domain }}{{ svc.listen_port !== 443 && svc.listen_port !== 80 ? ':'+svc.listen_port : '' }}
              </span>
              <ArrowRight :size="14" class="text-slate-300 flex-shrink-0" />
              <span class="font-mono text-xs text-slate-600 bg-white border border-slate-100 px-2 py-0.5 rounded-lg">
                {{ route.backend_url }}
              </span>
            </div>

            <!-- Route actions -->
            <div class="flex items-center gap-1.5 flex-shrink-0 opacity-0 group-hover/route:opacity-100 transition-opacity">
              <label class="toggle scale-75">
                <input type="checkbox" :checked="route.enabled" @change="toggleRoute(svc.id, route.id)" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <button @click="openRouteModal(svc.id, route)" class="btn-ghost btn-sm">
                <Pencil :size="12" />
              </button>
              <button @click="delRoute(svc.id, route.id)" class="btn-ghost btn-sm text-red-400 hover:bg-red-50">
                <Trash2 :size="12" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ── Service Modal ───────────────────────────────────── -->
    <Teleport to="body">
      <div v-if="serviceModal" class="modal-overlay" @click.self="serviceModal=null">
        <div class="modal-box">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <h3 class="font-semibold text-slate-900">{{ editingService ? t('editService') : t('addWebService') }}</h3>
            <button @click="serviceModal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div>
              <label class="input-label">{{ t('serviceName') }}</label>
              <input v-model="svcForm.name" class="input" placeholder="My Web App" />
            </div>
            <div>
              <label class="input-label">{{ t('listenPortLabel') }}</label>
              <input v-model.number="svcForm.listen_port" type="number" class="input max-w-xs" placeholder="443" />
              <p class="text-xs text-slate-400 mt-1">
                {{ t('listenPortHint') }}
              </p>
            </div>
            <!-- TLS toggle -->
            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="svcForm.enable_https" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <div>
                <span class="text-sm text-slate-600">{{ t('enableHttps') }}</span>
                <p class="text-xs text-slate-400 mt-0.5">{{ svcForm.enable_https ? t('httpsHint') : t('httpOnlyHint') }}</p>
              </div>
            </div>
            <!-- TLS cert selector, shown only when HTTPS enabled -->
            <div v-if="svcForm.enable_https">
              <div class="p-3 bg-blue-50 rounded-xl border border-blue-100 flex items-center gap-2 text-xs text-blue-700 mb-3">
                <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                {{ t('httpsHint') }}
              </div>
              <label class="input-label">{{ t('tlsCert') }} <span class="text-red-400">*</span></label>
              <select v-model="svcForm.tls_cert_id" class="select">
                <option value="">{{ t('selectCert') }}</option>
                <option v-for="cert in certs.filter(c=>c.status==='active')" :key="cert.id" :value="cert.id">
                  {{ cert.name || cert.domain }}
                </option>
              </select>
              <p v-if="certs.filter(c=>c.status==='active').length === 0" class="text-xs text-amber-500 mt-1">
                {{ t('noCertsAvailable') }}
              </p>
            </div>
            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="svcForm.enabled" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">{{ t('enableNow') }}</span>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="serviceModal=null">{{ t('cancel') }}</button>
            <div v-if="svcError" class="flex items-center gap-2 text-red-600 bg-red-50 px-3 py-2 rounded-xl border border-red-100 text-sm mr-auto">
              <span>⚠️ {{ svcError }}</span>
            </div>
            <button class="btn-primary" @click="saveService">{{ editingService ? t('save') : t('create') }}</button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- ── Route Modal ─────────────────────────────────────── -->
    <Teleport to="body">
      <div v-if="routeModal" class="modal-overlay" @click.self="routeModal=null">
        <div class="modal-box">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900">{{ editingRoute ? t('editSubRoute') : t('addSubRouteTitle') }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">{{ t('routeDesc') }}</p>
            </div>
            <button @click="routeModal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div class="p-4 bg-purple-50 rounded-xl border border-purple-100 text-xs text-purple-700 space-y-1">
              <p v-html="t('routeHelp1')"></p>
              <p v-html="t('routeHelp2')"></p>
            </div>
            <div>
              <label class="input-label">{{ t('frontDomain') }}</label>
              <input v-model="routeForm.domain" class="input font-mono" placeholder="a.com" />
              <p class="text-xs text-slate-400 mt-1">
                {{ currentSvc?.enable_https ? 'https' : 'http' }}://{{ routeForm.domain || 'a.com' }}{{ currentSvc && currentSvc.listen_port !== 443 ? ':'+currentSvc.listen_port : '' }}
              </p>
            </div>
            <div>
              <label class="input-label">{{ t('backendAddr') }}</label>
              <input v-model="routeForm.backend_url" class="input font-mono text-sm" placeholder="http://127.0.0.1:8080" />
            </div>
            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="routeForm.enabled" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">{{ t('enableRoute') }}</span>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="routeModal=null">{{ t('cancel') }}</button>
            <button class="btn-primary" @click="saveRoute">{{ editingRoute ? t('saveRouteBtn') : t('addRouteBtn') }}</button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- ── Access Logs Modal ───────────────────────────────── -->
    <Teleport to="body">
      <div v-if="logsModal" class="modal-overlay" @click.self="logsModal=false; logsServiceID=''">
        <div class="modal-box max-w-4xl w-full">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900">{{ t('logsTitle') }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">{{ t('logsCount', {n: logs.length}) }}</p>
            </div>
            <button @click="logsModal=false; logsServiceID=''" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>

          <!-- Log filter bar -->
          <div class="px-6 py-3 border-b border-slate-50 flex items-center gap-3">
            <input v-model="logSearch" class="input max-w-xs text-xs py-1.5" :placeholder="t('logsSearch')" />
            <button @click="loadLogs" class="btn-secondary btn-sm">
              <RefreshCw :size="12" /> {{ t('refresh') }}
            </button>
            <span class="text-xs text-slate-400 ml-auto">{{ t('logsTotal', {n: filteredLogs.length}) }}</span>
          </div>

          <div class="overflow-auto max-h-[60vh]">
            <table class="w-full text-xs">
              <thead class="bg-slate-50 sticky top-0">
                <tr>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">{{ t('logsTime') }}</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">{{ t('logsDomain') }}</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">{{ t('logsPath') }}</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">{{ t('logsStatus') }}</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">{{ t('logsDuration') }}</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">{{ t('logsSrcIp') }}</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500 max-w-[180px]">User-Agent</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="log in filteredLogs" :key="log.id"
                    class="border-t border-slate-50 hover:bg-slate-50 transition-colors">
                  <td class="px-4 py-2 font-mono text-slate-400 whitespace-nowrap">
                    {{ formatTime(log.time) }}
                  </td>
                  <td class="px-4 py-2 font-mono font-semibold text-slate-700">{{ log.domain }}</td>
                  <td class="px-4 py-2 font-mono text-slate-500 max-w-[120px] truncate" :title="log.path">
                    {{ log.method }} {{ log.path }}
                  </td>
                  <td class="px-4 py-2">
                    <span :class="statusClass(log.status_code)" class="badge">{{ log.status_code }}</span>
                  </td>
                  <td class="px-4 py-2 font-mono text-slate-400">{{ log.duration_ms }}ms</td>
                  <td class="px-4 py-2 font-mono text-slate-600">{{ log.client_ip }}</td>
                  <td class="px-4 py-2 text-slate-400 max-w-[180px] truncate" :title="log.user_agent">
                    {{ parseUA(log.user_agent) }}
                  </td>
                </tr>
                <tr v-if="filteredLogs.length === 0">
                  <td colspan="7" class="text-center py-12 text-slate-300">{{ t('noLogs') }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { Plus, Server, ArrowRight, Pencil, Trash2, X, ScrollText, RefreshCw } from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'

const { t } = useI18n()

const services = ref([])
const certs = ref([])
const logs = ref([])
const logSearch = ref('')
const logsModal = ref(false)
const logsServiceID = ref('')

// ── Service modal ──
const serviceModal = ref(false)
const editingService = ref(false)
const svcForm = ref({})

// ── Route modal ──
const routeModal = ref(false)
const editingRoute = ref(false)
const currentSvcID = ref('')
const routeForm = ref({})

const currentSvc = computed(() => services.value.find(s => s.id === currentSvcID.value))
const filteredLogs = computed(() => {
  if (!logSearch.value) return logs.value
  const q = logSearch.value.toLowerCase()
  return logs.value.filter(l =>
    l.client_ip?.includes(q) || l.domain?.includes(q) ||
    l.user_agent?.toLowerCase().includes(q) || l.path?.includes(q)
  )
})

async function load() {
  const [svcRes, certRes] = await Promise.all([api.get('/webservice'), api.get('/tls')])
  services.value = svcRes.data
  certs.value = certRes.data
}

async function loadLogs() {
  const url = logsServiceID.value ? `/webservice/${logsServiceID.value}/logs` : '/webservice/logs'
  const { data } = await api.get(url)
  logs.value = data
}

watch(logsModal, v => { if (v) loadLogs() })

function openLogsFor(id) {
  logsServiceID.value = id
  logsModal.value = true
}

// ── Service CRUD ──
function openServiceModal(svc = null) {
  editingService.value = !!svc
  svcError.value = ''
  svcForm.value = svc
    ? { ...svc }
    : { name: '', listen_port: 443, enable_https: true, tls_cert_id: '', enabled: true }
  serviceModal.value = true
}

const svcError = ref('')
async function saveService() {
  svcError.value = ''
  try {
    if (editingService.value) {
      await api.put(`/webservice/${svcForm.value.id}`, svcForm.value)
    } else {
      await api.post('/webservice', svcForm.value)
    }
    serviceModal.value = false
    await load()
  } catch (e) {
    const port = e.response?.data?.port || svcForm.value.listen_port
    if (e.response?.status === 409) {
      svcError.value = t('portOccupied', {port})
    } else {
      svcError.value = e.response?.data?.error || e.message
    }
  }
}

async function toggleService(id) { await api.post(`/webservice/${id}/toggle`); await load() }
async function delService(id) {
  if (!confirm(t('confirmDelService'))) return
  await api.delete(`/webservice/${id}`)
  await load()
}

// ── Route CRUD ──
function openRouteModal(svcID, route = null) {
  currentSvcID.value = svcID
  editingRoute.value = !!route
  routeForm.value = route
    ? { ...route }
    : { domain: '', backend_url: '', enabled: true }
  routeModal.value = true
}

async function saveRoute() {
  const id = currentSvcID.value
  if (editingRoute.value) {
    await api.put(`/webservice/${id}/routes/${routeForm.value.id}`, routeForm.value)
  } else {
    await api.post(`/webservice/${id}/routes`, routeForm.value)
  }
  routeModal.value = false
  await load()
}

async function toggleRoute(svcID, rid) {
  await api.post(`/webservice/${svcID}/routes/${rid}/toggle`)
  await load()
}

async function delRoute(svcID, rid) {
  if (!confirm(t('confirmDelRoute'))) return
  await api.delete(`/webservice/${svcID}/routes/${rid}`)
  await load()
}

// ── Helpers ──
function formatTime(t) {
  if (!t) return ''
  return new Date(t).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function statusClass(code) {
  if (code < 300) return 'badge-green'
  if (code < 400) return 'badge-blue'
  if (code < 500) return 'badge-amber'
  return 'badge-red'
}

function parseUA(ua) {
  if (!ua) return '—'
  if (ua.includes('iPhone') || ua.includes('iPad')) return '📱 iOS'
  if (ua.includes('Android')) return '📱 Android'
  if (ua.includes('Chrome')) return '🌐 Chrome'
  if (ua.includes('Firefox')) return '🦊 Firefox'
  if (ua.includes('Safari')) return '🧭 Safari'
  if (ua.includes('curl')) return '⌨️ curl'
  return ua.slice(0, 40)
}

onMounted(load)
</script>
