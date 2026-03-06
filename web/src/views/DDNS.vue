<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">动态域名 DDNS</h1>
        <p class="page-subtitle">自动同步公网 IP 到 DNS 服务商，支持 Cloudflare、阿里云、DNSPod</p>
      </div>
      <button class="btn-primary" @click="openModal()">
        <Plus :size="16" /> 添加规则
      </button>
    </div>

    <div v-if="rules.length === 0" class="glass-card p-16 text-center">
      <div class="w-16 h-16 rounded-3xl bg-emerald-50 flex items-center justify-center mx-auto mb-4">
        <Globe :size="28" class="text-emerald-400" />
      </div>
      <p class="text-slate-500 font-medium">暂无 DDNS 规则</p>
    </div>

    <div v-else class="grid gap-4">
      <div v-for="rule in rules" :key="rule.id"
           class="glass-card p-5 group hover:shadow-colored-green transition-all duration-300">
        <div class="flex items-start gap-4">
          <!-- Icon -->
          <div class="w-12 h-12 rounded-2xl flex items-center justify-center flex-shrink-0"
               :style="rule.enabled ? 'background: linear-gradient(135deg, #10b981, #059669)' : 'background: #f1f5f9'">
            <Globe :size="20" :class="rule.enabled ? 'text-white' : 'text-slate-400'" />
          </div>

          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-2 flex-wrap">
              <span class="font-semibold text-slate-900">{{ rule.name || '未命名' }}</span>
              <span class="status-dot" :class="rule.enabled ? 'active' : 'inactive'"></span>
              <ProviderBadge :provider="rule.provider" />
              <span class="badge badge-slate">{{ rule.ip_version === 'ipv6' ? 'IPv6' : 'IPv4' }}</span>
            </div>

            <div class="font-mono text-sm text-slate-600 mb-3">
              {{ rule.sub_domain ? rule.sub_domain + '.' : '' }}{{ rule.domain }}
            </div>

            <!-- IP history bar chart -->
            <div class="flex items-end gap-0.5 h-8 mb-2">
              <div v-for="(rec, i) in (rule.ip_history || []).slice(-30)" :key="i"
                   class="flex-1 rounded-sm transition-all duration-300"
                   :style="`height: ${Math.max(4, (i+1)/30*32)}px; background: ${rule.enabled ? '#10b981' : '#94a3b8'}; opacity: ${0.3 + (i/30)*0.7}`"
                   :title="`${rec.ip} @ ${new Date(rec.timestamp).toLocaleString('zh-CN')}`">
              </div>
              <div v-if="!(rule.ip_history?.length)" class="flex-1 text-xs text-slate-300 italic">暂无记录</div>
            </div>

            <div class="flex items-center gap-4 text-xs text-slate-400">
              <span>当前 IP: <span class="font-mono text-slate-600">{{ rule.last_ip || '未知' }}</span></span>
              <span v-if="rule.last_updated">更新: {{ new Date(rule.last_updated).toLocaleString('zh-CN') }}</span>
              <span>间隔: {{ rule.interval || 300 }}s</span>
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center gap-2 flex-shrink-0">
            <button @click="refresh(rule.id)" class="btn-ghost btn-sm text-emerald-500" title="立即检测">
              <RefreshCw :size="14" />
            </button>
            <label class="toggle">
              <input type="checkbox" :checked="rule.enabled" @change="toggle(rule.id)" />
              <div class="toggle-track"></div>
              <div class="toggle-thumb"></div>
            </label>
            <button @click="openModal(rule)" class="btn-ghost btn-sm opacity-0 group-hover:opacity-100">
              <Pencil :size="14" />
            </button>
            <button @click="del(rule.id)" class="btn-ghost btn-sm text-red-400 hover:text-red-500 hover:bg-red-50 opacity-0 group-hover:opacity-100">
              <Trash2 :size="14" />
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Modal -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <h3 class="font-semibold text-slate-900">{{ editing ? '编辑 DDNS 规则' : '添加 DDNS 规则' }}</h3>
            <button @click="modal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div>
              <label class="input-label">规则名称</label>
              <input v-model="form.name" class="input" placeholder="My DDNS" />
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="input-label">DNS 服务商</label>
                <select v-model="form.provider" class="select">
                  <option value="cloudflare">Cloudflare</option>
                  <option value="alidns">阿里云 DNS</option>
                  <option value="dnspod">DNSPod</option>
                  <option value="tencentcloud">腾讯云 DNS</option>
                </select>
              </div>
              <div>
                <label class="input-label">IP 版本</label>
                <select v-model="form.ip_version" class="select">
                  <option value="ipv4">IPv4</option>
                  <option value="ipv6">IPv6</option>
                </select>
              </div>
            </div>
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="input-label">子域名</label>
                <input v-model="form.sub_domain" class="input" placeholder="home (留空为@)" />
              </div>
              <div>
                <label class="input-label">主域名</label>
                <input v-model="form.domain" class="input" placeholder="example.com" />
              </div>
            </div>
            <div>
              <label class="input-label">检测间隔 (秒)</label>
              <input v-model.number="form.interval" type="number" class="input" placeholder="300" />
            </div>

            <!-- Cloudflare fields -->
            <template v-if="form.provider === 'cloudflare'">
              <div class="p-4 bg-amber-50 rounded-xl border border-amber-100">
                <h4 class="text-xs font-bold text-amber-700 uppercase tracking-wide mb-3">Cloudflare 配置</h4>
                <div class="space-y-3">
                  <div>
                    <label class="input-label">API Token</label>
                    <input v-model="form.provider_conf.api_token" class="input font-mono text-xs" placeholder="Bearer token with DNS edit permission" />
                  </div>
                  <div>
                    <label class="input-label">Zone ID</label>
                    <input v-model="form.provider_conf.zone_id" class="input font-mono text-xs" placeholder="Zone ID from Cloudflare dashboard" />
                  </div>
                </div>
              </div>
            </template>

            <!-- AliDNS fields -->
            <template v-if="form.provider === 'alidns'">
              <div class="p-4 bg-blue-50 rounded-xl border border-blue-100">
                <h4 class="text-xs font-bold text-blue-700 uppercase tracking-wide mb-3">阿里云 DNS 配置</h4>
                <div class="space-y-3">
                  <div>
                    <label class="input-label">Access Key ID</label>
                    <input v-model="form.provider_conf.access_key_id" class="input font-mono text-xs" />
                  </div>
                  <div>
                    <label class="input-label">Access Key Secret</label>
                    <input v-model="form.provider_conf.access_key_secret" class="input font-mono text-xs" type="password" />
                  </div>
                </div>
              </div>
            </template>

            <!-- DNSPod / Tencent fields -->
            <template v-if="form.provider === 'dnspod' || form.provider === 'tencentcloud'">
              <div class="p-4 bg-blue-50 rounded-xl border border-blue-100">
                <h4 class="text-xs font-bold text-blue-700 uppercase tracking-wide mb-3">{{ form.provider === 'dnspod' ? 'DNSPod' : '腾讯云' }} 配置</h4>
                <div class="space-y-3">
                  <div>
                    <label class="input-label">SecretId</label>
                    <input v-model="form.provider_conf.secret_id" class="input font-mono text-xs" />
                  </div>
                  <div>
                    <label class="input-label">SecretKey</label>
                    <input v-model="form.provider_conf.secret_key" class="input font-mono text-xs" type="password" />
                  </div>
                </div>
              </div>
            </template>

            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="form.enabled" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">创建后立即启用</span>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="modal=null">取消</button>
            <button class="btn-primary" @click="save">{{ editing ? '保存' : '创建' }}</button>
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
import ProviderBadge from '@/components/ProviderBadge.vue'

const rules = ref([])
const modal = ref(null)
const editing = ref(false)
const form = ref({})

function defaultForm() {
  return { name: '', provider: 'cloudflare', domain: '', sub_domain: '', ip_version: 'ipv4', interval: 300, enabled: true, provider_conf: {} }
}

async function load() {
  const { data } = await api.get('/ddns')
  rules.value = data
}

function openModal(rule = null) {
  editing.value = !!rule
  form.value = rule ? { ...rule, provider_conf: { ...rule.provider_conf } } : defaultForm()
  modal.value = true
}

async function save() {
  if (editing.value) {
    await api.put(`/ddns/${form.value.id}`, form.value)
  } else {
    await api.post('/ddns', form.value)
  }
  modal.value = null
  await load()
}

async function toggle(id) {
  await api.post(`/ddns/${id}/toggle`)
  await load()
}

async function refresh(id) {
  await api.post(`/ddns/${id}/refresh`)
  setTimeout(load, 500)
}

async function del(id) {
  if (!confirm('确认删除此规则？')) return
  await api.delete(`/ddns/${id}`)
  await load()
}

onMounted(load)
</script>
