<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ t('ddnsTitle') }}</h1>
        <p class="page-subtitle">{{ t('ddnsSubtitle') }}</p>
      </div>
      <button class="btn-primary" @click="openModal()">
        <Plus :size="16" /> {{ t('addRule') }}
      </button>
    </div>

    <div v-if="rules.length === 0" class="glass-card p-16 text-center">
      <div class="w-16 h-16 rounded-3xl bg-emerald-50 flex items-center justify-center mx-auto mb-4">
        <Globe :size="28" class="text-emerald-400" />
      </div>
      <p class="text-slate-500 font-medium">{{ t('noDdns') }}</p>
    </div>

    <div v-else class="grid gap-4">
      <div v-for="rule in rules" :key="rule.id"
           class="glass-card p-5 group hover:shadow-colored-green transition-all duration-300">
        <div class="flex items-start gap-4">
          <div class="w-12 h-12 rounded-2xl flex items-center justify-center flex-shrink-0"
               :style="rule.enabled ? 'background:linear-gradient(135deg,#10b981,#059669)' : 'background:#f1f5f9'">
            <Globe :size="20" :class="rule.enabled ? 'text-white' : 'text-slate-400'" />
          </div>

          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-2 flex-wrap">
              <span class="font-semibold text-slate-900">{{ rule.name || t('unnamed') }}</span>
              <span class="status-dot" :class="rule.enabled ? 'active' : 'inactive'"></span>
              <ProviderBadge :provider="rule.provider" />
              <span class="badge badge-slate">{{ rule.ip_version === 'ipv6' ? 'IPv6' : 'IPv4' }}</span>
              <span v-if="rule.ip_detect_mode === 'iface'" class="badge text-xs" style="background:#f0f9ff;color:#0369a1;border:1px solid #bae6fd">
                {{ t('ifaceBadge', {iface: rule.ip_interface}) }}{{ rule.ip_version === 'ipv6' && rule.ip_index ? ` [${rule.ip_index}]` : '' }}
              </span>
              <span v-else class="badge text-xs" style="background:#f0fdf4;color:#166534;border:1px solid #bbf7d0">{{ t('apiMode') }}</span>
            </div>

            <div class="flex flex-wrap gap-1.5 mb-3">
              <span v-for="d in effectiveDomains(rule)" :key="d"
                    class="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-0.5 rounded-lg">{{ d }}</span>
            </div>

            <div class="flex items-end gap-0.5 h-6 mb-2">
              <div v-for="(rec, i) in (rule.ip_history||[]).slice(-30)" :key="i"
                   class="flex-1 rounded-sm"
                   :style="`height:${Math.max(3,(i+1)/30*24)}px;background:${rule.enabled?'#10b981':'#94a3b8'};opacity:${0.3+(i/30)*0.7}`"
                   :title="`${rec.ip} @ ${new Date(rec.timestamp).toLocaleString('zh-CN')}`"></div>
              <div v-if="!(rule.ip_history?.length)" class="text-xs text-slate-300 italic">{{ t('noHistory') }}</div>
            </div>

            <div class="flex items-center gap-4 text-xs text-slate-400">
              <!-- IP status with real-time feedback -->
              <span v-if="ipStatus[rule.id] === 'fetching'" class="flex items-center gap-1 text-amber-500 font-medium">
                <span class="inline-block w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full animate-spin"></span>
                {{ t('fetchingIp') }}
              </span>
              <span v-else-if="ipStatus[rule.id] === 'fail'" class="text-red-400 font-medium">{{ t('ipFetchFail') }}</span>
              <span v-else>
                {{ t('currentIp') }}
                <span class="font-mono" :class="rule.last_ip ? 'text-slate-700' : 'text-slate-400'">
                  {{ rule.last_ip || t('unknown') }}
                </span>
              </span>
              <span v-if="rule.last_updated">{{ t('lastUpdated') }} {{ new Date(rule.last_updated).toLocaleString() }}</span>
              <span>{{ t('interval') }} {{ rule.interval || 300 }}s</span>
            </div>
          </div>

          <div class="flex items-center gap-2 flex-shrink-0">
            <button @click="refresh(rule.id)" class="btn-ghost btn-sm text-emerald-500" :title="t('detectNow')">
              <RefreshCw :size="14" />
            </button>
            <label class="toggle">
              <input type="checkbox" :checked="rule.enabled" @change="toggle(rule.id)" />
              <div class="toggle-track"></div><div class="toggle-thumb"></div>
            </label>
            <button @click="openModal(rule)" class="btn-ghost btn-sm opacity-0 group-hover:opacity-100"><Pencil :size="14" /></button>
            <button @click="del(rule.id)" class="btn-ghost btn-sm text-red-400 hover:bg-red-50 opacity-0 group-hover:opacity-100"><Trash2 :size="14" /></button>
          </div>
        </div>
      </div>
    </div>

    <!-- Modal -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box max-w-lg">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <h3 class="font-semibold text-slate-900">{{ editing ? t('editDdns') : t('addDdns') }}</h3>
            <button @click="modal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4 max-h-[75vh] overflow-y-auto">

            <div>
              <label class="input-label">{{ t('ruleName') }}</label>
              <input v-model="form.name" class="input" placeholder="My DDNS" />
            </div>

            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="input-label">{{ t('dnsProvider') }}</label>
                <select v-model="form.provider" class="select">
                  <option value="cloudflare">Cloudflare</option>
                  <option value="alidns">AliDNS</option>
                  <option value="dnspod">DNSPod</option>
                  <option value="tencentcloud">{{ t('tencentCloud') }} DNS</option>
                </select>
              </div>
              <div>
                <label class="input-label">{{ t('ipVersion') }}</label>
                <select v-model="form.ip_version" class="select" @change="onIfaceChange">
                  <option value="ipv4">IPv4</option>
                  <option value="ipv6">IPv6</option>
                </select>
              </div>
            </div>

            <div>
              <label class="input-label">{{ t('ipDetectMode') }}</label>
              <select v-model="form.ip_detect_mode" class="select" @change="onDetectModeChange">
                <option value="api">{{ t('apiModeOpt') }}</option>
                <option value="iface">{{ t('ifaceModeOpt') }}</option>
              </select>
            </div>

            <template v-if="form.ip_detect_mode === 'iface'">
              <div>
                <label class="input-label">{{ t('ifaceList') }}</label>
                <div class="flex gap-2">
                  <select v-if="interfaces.length" v-model="form.ip_interface" class="select flex-1" @change="onIfaceChange">
                    <option v-for="i in interfaces" :key="i" :value="i">{{ i }}</option>
                  </select>
                  <input v-else v-model="form.ip_interface" class="input flex-1 font-mono" placeholder="eth0" @blur="onIfaceChange" />
                  <button type="button" class="btn-secondary btn-sm whitespace-nowrap" @click="loadInterfaces">
                    <RefreshCw :size="13" :class="ifaceLoading ? 'animate-spin' : ''" />
                  </button>
                </div>
              </div>

              <div v-if="form.ip_version === 'ipv6'">
                <label class="input-label">
                  {{ t('selectIpv6') }}
                  <span v-if="ifaceLoading" class="ml-2 text-xs text-amber-500 inline-flex items-center gap-1">
                    <span class="inline-block w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full animate-spin"></span>
                    {{ t('loadingIface') }}
                  </span>
                </label>

                    <div v-if="ifaceIPs.length" class="space-y-1.5">
                  <label v-for="(ip, i) in ifaceIPs" :key="i"
                         class="flex items-center gap-3 p-2.5 rounded-xl border-2 cursor-pointer transition-all"
                         :class="(form.ip_index ?? 0) === i
                           ? 'border-vane-500 bg-vane-50'
                           : 'border-slate-200 hover:border-vane-300'">
                    <input type="radio" :value="i" v-model.number="form.ip_index" class="accent-vane-500" />
                    <span class="font-mono text-sm text-slate-700 flex-1 break-all">{{ ip }}</span>
                    <span class="text-xs text-slate-400 flex-shrink-0">{{ t('ipIndex', {n: i+1}) }}</span>
                  </label>
                </div>

                    <div v-else-if="!ifaceLoading && ifaceLoadError"
                     class="p-3 bg-red-50 border border-red-100 rounded-xl text-xs text-red-600 font-mono">
                  ⚠ {{ ifaceLoadError }}
                </div>

                    <div v-else-if="!ifaceLoading && form.ip_interface"
                     class="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-500">
                  {{ t('noGlobalIpv6') }}
                </div>

                <p class="text-xs text-slate-400 mt-1.5">{{ t('ipv6Hint') }}</p>
              </div>
            </template>

            <div>
              <label class="input-label">{{ t('domainList') }}</label>
              <textarea v-model="form.domainsText" class="input font-mono text-sm resize-none" rows="4"
                        placeholder="home.example.com&#10;*.example.com&#10;example.com"></textarea>
              <p class="text-xs text-slate-400 mt-1">{{ t('domainListHint') }}</p>
            </div>

            <div>
              <label class="input-label">{{ t('checkInterval') }}</label>
              <input v-model.number="form.interval" type="number" min="60" class="input max-w-xs" placeholder="300" />
            </div>

            <!-- Cloudflare -->
            <template v-if="form.provider === 'cloudflare'">
              <div class="p-4 bg-amber-50 rounded-xl border border-amber-100 space-y-3">
                <h4 class="text-xs font-bold text-amber-700 uppercase tracking-wide">{{ t('cfConfig') }}</h4>
                <div>
                  <label class="input-label">{{ t('cfApiToken') }} <span class="text-red-400">*</span></label>
                  <input v-model="form.provider_conf.api_token" class="input font-mono text-xs" placeholder="API Token (DNS:Edit)" />
                </div>
                <div>
                  <label class="input-label">{{ t('cfZoneId') }} <span class="text-xs font-normal text-slate-400 ml-1">{{ t('cfZoneIdHint') }}</span></label>
                  <input v-model="form.provider_conf.zone_id" class="input font-mono text-xs" :placeholder="t('cfZonePlaceholder')" />
                </div>
              </div>
            </template>

            <template v-if="form.provider === 'alidns'">
              <div class="p-4 bg-blue-50 rounded-xl border border-blue-100 space-y-3">
                <h4 class="text-xs font-bold text-blue-700 uppercase tracking-wide">{{ t('alidnsConfig') }}</h4>
                <div><label class="input-label">Access Key ID</label><input v-model="form.provider_conf.access_key_id" class="input font-mono text-xs" /></div>
                <div><label class="input-label">Access Key Secret</label><input v-model="form.provider_conf.access_key_secret" class="input font-mono text-xs" type="password" /></div>
              </div>
            </template>

            <template v-if="form.provider === 'dnspod' || form.provider === 'tencentcloud'">
              <div class="p-4 bg-blue-50 rounded-xl border border-blue-100 space-y-3">
                <h4 class="text-xs font-bold text-blue-700 uppercase tracking-wide">{{ t('dnspodConfig', {name: form.provider === 'dnspod' ? 'DNSPod' : t('tencentCloud')}) }}</h4>
                <div><label class="input-label">SecretId</label><input v-model="form.provider_conf.secret_id" class="input font-mono text-xs" /></div>
                <div><label class="input-label">SecretKey</label><input v-model="form.provider_conf.secret_key" class="input font-mono text-xs" type="password" /></div>
              </div>
            </template>

            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="form.enabled" />
                <div class="toggle-track"></div><div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">{{ t('enableAfterCreate') }}</span>
            </div>

          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="modal=null">{{ t('cancel') }}</button>
            <button class="btn-primary" @click="save">{{ editing ? t('save') : t('create') }}</button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Plus, Globe, Pencil, Trash2, X, RefreshCw } from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'
import ProviderBadge from '@/components/ProviderBadge.vue'

const { t } = useI18n()

const rules = ref([])
const modal = ref(null)
const editing = ref(false)
const form = ref({})
const interfaces = ref([])
const ifaceIPs = ref([])
const ifaceTestResult = ref('')
const ifaceLoading = ref(false)
const ifaceLoadError = ref('')
// per-rule IP fetch status: { [id]: 'fetching' | 'ok' | 'fail' }
const ipStatus = ref({})

function effectiveDomains(rule) {
  if (rule.domains?.length) return rule.domains
  if (rule.domain) {
    const fqdn = rule.sub_domain && rule.sub_domain !== '@'
      ? rule.sub_domain + '.' + rule.domain : rule.domain
    return [fqdn]
  }
  return []
}

function defaultForm() {
  return {
    name: '', provider: 'cloudflare', domainsText: '',
    ip_version: 'ipv4', ip_detect_mode: 'api',
    ip_interface: '', ip_index: 0,
    interval: 300, enabled: true, provider_conf: {}
  }
}

async function load() {
  const { data } = await api.get('/ddns')
  rules.value = data
}

async function loadInterfaces() {
  try {
    const { data } = await api.get('/ddns/interfaces')
    interfaces.value = data || []
    if (interfaces.value.length && !form.value.ip_interface) {
      form.value.ip_interface = interfaces.value[0]
    }
    // Always trigger IP load after interface list is ready
    onIfaceChange()
  } catch {}
}

async function loadIfaceIPs(iface, version) {
  if (!iface || version !== 'ipv6') return
  ifaceLoading.value = true
  ifaceLoadError.value = ''
  try {
    const { data } = await api.get('/ddns/iface-ips', { params: { iface, version } })
    ifaceIPs.value = data || []
    // Auto-select first address if current index out of range
    if (ifaceIPs.value.length && (form.value.ip_index ?? 0) >= ifaceIPs.value.length) {
      form.value.ip_index = 0
    }
  } catch (e) {
    ifaceIPs.value = []
    ifaceLoadError.value = e.response?.data?.error || e.message || 'Load failed'
  } finally {
    ifaceLoading.value = false
  }
}

function onIfaceChange() {
  ifaceIPs.value = []
  ifaceLoadError.value = ''
  if (form.value.ip_detect_mode === 'iface' && form.value.ip_version === 'ipv6' && form.value.ip_interface) {
    loadIfaceIPs(form.value.ip_interface, 'ipv6')
  }
}

// Called when user switches to "通过网卡获取":
// load physical interfaces and immediately detect IPs on the first one
async function onDetectModeChange() {
  if (form.value.ip_detect_mode !== 'iface') return
  ifaceIPs.value = []
  ifaceLoadError.value = ''
  try {
    const { data } = await api.get('/ddns/interfaces')
    interfaces.value = data || []
    if (interfaces.value.length) {
      // Auto-select first physical interface
      form.value.ip_interface = interfaces.value[0]
      // Auto-load IPv6 addresses if in IPv6 mode
      if (form.value.ip_version === 'ipv6') {
        loadIfaceIPs(form.value.ip_interface, 'ipv6')
      }
    }
  } catch {}
}



function openModal(rule = null) {
  editing.value = !!rule
  ifaceIPs.value = []
  ifaceTestResult.value = ''
  if (rule) {
    const domains = rule.domains?.length ? rule.domains : effectiveDomains(rule)
    form.value = {
      ...rule,
      provider_conf: { ...rule.provider_conf },
      domainsText: domains.join('\n'),
      ip_detect_mode: rule.ip_detect_mode || 'api',
      ip_interface: rule.ip_interface || '',
      ip_index: rule.ip_index ?? 0,
    }
    if (rule.ip_detect_mode === 'iface' && rule.ip_version === 'ipv6') {
      loadIfaceIPs(rule.ip_interface, 'ipv6')
    }
  } else {
    form.value = defaultForm()
  }
  modal.value = true
  loadInterfaces()
}

async function save() {
  const domains = form.value.domainsText
    .split('\n').map(s => s.trim()).filter(Boolean)
  const payload = { ...form.value, domains, domainsText: undefined }
  let savedId = form.value.id
  if (editing.value) {
    await api.put(`/ddns/${savedId}`, payload)
  } else {
    const { data } = await api.post('/ddns', payload)
    savedId = data.id
  }
  modal.value = null
  await load()
  // Trigger immediate IP detection and show status
  triggerRefreshWithStatus(savedId)
}

// Trigger a refresh and track its status in ipStatus
async function triggerRefreshWithStatus(id) {
  ipStatus.value[id] = 'fetching'
  try {
    await api.post(`/ddns/${id}/refresh`)
    // Poll until last_ip appears or timeout (30s)
    const deadline = Date.now() + 30000
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 1200))
      await load()
      const rule = rules.value.find(r => r.id === id)
      if (rule?.last_ip) {
        ipStatus.value[id] = 'ok'
        // Clear 'ok' status after 5s so it looks normal
        setTimeout(() => { delete ipStatus.value[id] }, 5000)
        return
      }
    }
    // Timeout — still no IP
    ipStatus.value[id] = 'fail'
    setTimeout(() => { delete ipStatus.value[id] }, 8000)
  } catch {
    ipStatus.value[id] = 'fail'
    setTimeout(() => { delete ipStatus.value[id] }, 8000)
  }
}

async function toggle(id) { await api.post(`/ddns/${id}/toggle`); await load() }
async function refresh(id) { triggerRefreshWithStatus(id) }
async function del(id) {
  if (!confirm(t('confirmDelDdns'))) return
  await api.delete(`/ddns/${id}`); await load()
}

onMounted(load)
</script>
