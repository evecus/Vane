<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">Web 服务</h1>
        <p class="page-subtitle">反向代理，HTTP 自动重定向 HTTPS，支持多域名子规则</p>
      </div>
      <div class="flex gap-2">
        <button class="btn-secondary" @click="logsModal=true">
          <ScrollText :size="15" /> 访问日志
        </button>
        <button class="btn-primary" @click="openServiceModal()">
          <Plus :size="16" /> 添加服务
        </button>
      </div>
    </div>

    <!-- Empty state -->
    <div v-if="services.length === 0" class="glass-card p-16 text-center">
      <div class="w-16 h-16 rounded-3xl bg-purple-50 flex items-center justify-center mx-auto mb-4">
        <Server :size="28" class="text-purple-400" />
      </div>
      <p class="text-slate-500 font-medium">暂无 Web 服务</p>
      <p class="text-slate-400 text-sm mt-1">点击「添加服务」绑定一个监听端口</p>
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
            <span class="font-semibold text-slate-900">{{ svc.name || '未命名服务' }}</span>
            <span class="status-dot" :class="svc.enabled ? 'active' : 'inactive'"></span>
            <span v-if="svc.enable_https" class="badge badge-green">HTTPS</span>
            <span v-else class="badge badge-slate">HTTP only</span>
            <span class="badge badge-purple">端口 {{ svc.listen_port }}</span>
          </div>
          <div class="text-xs text-slate-400 mt-0.5">
            {{ (svc.routes||[]).length }} 条子规则 ·
            {{ svc.enable_https ? 'HTTP 自动重定向至 HTTPS' : '仅 HTTP' }}
          </div>
        </div>
        <div class="flex items-center gap-2 flex-shrink-0">
          <button @click="openLogsFor(svc.id)" class="btn-ghost btn-sm text-slate-500" title="访问日志">
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
          <span class="text-xs font-bold text-slate-400 uppercase tracking-widest">子规则 (域名 → 后端)</span>
          <button @click="openRouteModal(svc.id)" class="btn-ghost btn-sm text-purple-600 hover:bg-purple-50">
            <Plus :size="12" /> 添加子规则
          </button>
        </div>

        <div v-if="!(svc.routes&&svc.routes.length)" class="text-center py-6 text-slate-300 text-sm border border-dashed border-slate-200 rounded-xl">
          暂无子规则，添加域名 → 后端映射
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
            <h3 class="font-semibold text-slate-900">{{ editingService ? '编辑 Web 服务' : '添加 Web 服务' }}</h3>
            <button @click="serviceModal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div>
              <label class="input-label">服务名称</label>
              <input v-model="svcForm.name" class="input" placeholder="My Web App" />
            </div>
            <div>
              <label class="input-label">监听端口</label>
              <input v-model.number="svcForm.listen_port" type="number" class="input max-w-xs" placeholder="443" />
              <p class="text-xs text-slate-400 mt-1">
                浏览器通过此端口访问，例如 443 则访问 https://a.com，6644 则访问 https://a.com:6644
              </p>
            </div>
            <div class="flex items-center gap-3 py-1">
              <label class="toggle">
                <input type="checkbox" v-model="svcForm.enable_https" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <div>
                <div class="text-sm font-medium text-slate-700">启用 HTTPS</div>
                <div class="text-xs text-slate-400">HTTP 访问自动 301 跳转至 HTTPS</div>
              </div>
            </div>
            <div v-if="svcForm.enable_https">
              <label class="input-label">TLS 证书</label>
              <select v-model="svcForm.tls_cert_id" class="select">
                <option value="">— 选择证书（可稍后配置）—</option>
                <option v-for="cert in certs" :key="cert.id" :value="cert.id">
                  {{ cert.domain }} · 剩余 {{ cert.days_left }} 天
                </option>
              </select>
            </div>
            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="svcForm.enabled" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">创建后立即启用</span>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="serviceModal=null">取消</button>
            <button class="btn-primary" @click="saveService">{{ editingService ? '保存' : '创建' }}</button>
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
              <h3 class="font-semibold text-slate-900">{{ editingRoute ? '编辑子规则' : '添加子规则' }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">域名 → 后端地址映射</p>
            </div>
            <button @click="routeModal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div class="p-4 bg-purple-50 rounded-xl border border-purple-100 text-xs text-purple-700 space-y-1">
              <p><strong>前端域名</strong>：浏览器输入的域名，Vane 根据 Host 头匹配</p>
              <p><strong>后端地址</strong>：内网实际服务地址，如 http://127.0.0.1:3000</p>
            </div>
            <div>
              <label class="input-label">前端域名</label>
              <input v-model="routeForm.domain" class="input font-mono" placeholder="a.com" />
              <p class="text-xs text-slate-400 mt-1">
                浏览器访问 {{ currentSvc?.enable_https ? 'https' : 'http' }}://{{ routeForm.domain || 'a.com' }}{{ currentSvc && currentSvc.listen_port !== 443 ? ':'+currentSvc.listen_port : '' }}
              </p>
            </div>
            <div>
              <label class="input-label">后端地址</label>
              <input v-model="routeForm.backend_url" class="input font-mono text-sm" placeholder="http://127.0.0.1:8080" />
            </div>
            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="routeForm.enabled" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">启用此子规则</span>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="routeModal=null">取消</button>
            <button class="btn-primary" @click="saveRoute">{{ editingRoute ? '保存' : '添加' }}</button>
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
              <h3 class="font-semibold text-slate-900">访问日志</h3>
              <p class="text-xs text-slate-400 mt-0.5">最近 {{ logs.length }} 条记录（内存保存 2000 条）</p>
            </div>
            <button @click="logsModal=false; logsServiceID=''" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>

          <!-- Log filter bar -->
          <div class="px-6 py-3 border-b border-slate-50 flex items-center gap-3">
            <input v-model="logSearch" class="input max-w-xs text-xs py-1.5" placeholder="搜索 IP / 域名 / UA..." />
            <button @click="loadLogs" class="btn-secondary btn-sm">
              <RefreshCw :size="12" /> 刷新
            </button>
            <span class="text-xs text-slate-400 ml-auto">{{ filteredLogs.length }} 条</span>
          </div>

          <div class="overflow-auto max-h-[60vh]">
            <table class="w-full text-xs">
              <thead class="bg-slate-50 sticky top-0">
                <tr>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">时间</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">域名</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">路径</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">状态</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">耗时</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">来源 IP</th>
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
                  <td colspan="7" class="text-center py-12 text-slate-300">暂无访问记录</td>
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
  svcForm.value = svc
    ? { ...svc }
    : { name: '', listen_port: 443, enable_https: true, tls_cert_id: '', enabled: true }
  serviceModal.value = true
}

async function saveService() {
  if (editingService.value) {
    await api.put(`/webservice/${svcForm.value.id}`, svcForm.value)
  } else {
    await api.post('/webservice', svcForm.value)
  }
  serviceModal.value = false
  await load()
}

async function toggleService(id) { await api.post(`/webservice/${id}/toggle`); await load() }
async function delService(id) {
  if (!confirm('确认删除此 Web 服务及其所有子规则？')) return
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
  if (!confirm('确认删除此子规则？')) return
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
