<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">TLS 证书</h1>
        <p class="page-subtitle">DNS-01 自动申请 Let's Encrypt 证书，支持手动上传，自动续期</p>
      </div>
      <div class="flex gap-2">
        <button class="btn-secondary" @click="openUpload()">
          <Upload :size="16" /> 上传证书
        </button>
        <button class="btn-primary" @click="openModal()">
          <Plus :size="16" /> 申请证书
        </button>
      </div>
    </div>

    <div v-if="certs.length === 0" class="glass-card p-16 text-center">
      <div class="w-16 h-16 rounded-3xl bg-amber-50 flex items-center justify-center mx-auto mb-4">
        <Shield :size="28" class="text-amber-400" />
      </div>
      <p class="text-slate-500 font-medium">暂无 TLS 证书</p>
    </div>

    <div v-else class="grid gap-4">
      <div v-for="cert in certs" :key="cert.id"
           class="glass-card p-5 group hover:shadow-colored-amber transition-all duration-300">
        <div class="flex items-center gap-4">
          <!-- Cert icon with expiry color -->
          <div class="w-14 h-14 rounded-2xl flex flex-col items-center justify-center flex-shrink-0 text-white relative"
               :style="`background: ${certGradient(cert.days_left)}`">
            <Lock :size="16" class="mb-0.5" />
            <span class="text-xs font-bold leading-none">{{ cert.days_left >= 0 ? cert.days_left : '?' }}</span>
            <span class="text-[9px] opacity-80">DAYS</span>
          </div>

          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1.5 flex-wrap">
              <span class="font-semibold text-slate-900 font-mono">{{ cert.domain }}</span>
              <StatusBadge :status="cert.status" />
              <span class="badge badge-slate text-xs">{{ cert.source === 'acme' ? 'ACME' : '手动' }}</span>
              <ProviderBadge v-if="cert.provider" :provider="cert.provider" />
              <span v-if="cert.auto_renew" class="badge badge-green text-xs">自动续期</span>
            </div>

            <!-- Expiry bar -->
            <div class="h-1.5 bg-slate-100 rounded-full overflow-hidden mb-2 max-w-xs">
              <div class="h-full rounded-full transition-all duration-700"
                   :style="`width: ${Math.min(100, Math.max(0, cert.days_left/90*100))}%; background: ${certBarColor(cert.days_left)}`"></div>
            </div>

            <div class="flex items-center gap-4 text-xs text-slate-400">
              <span v-if="cert.issued_at">签发: {{ new Date(cert.issued_at).toLocaleDateString('zh-CN') }}</span>
              <span v-if="cert.expires_at">到期: {{ new Date(cert.expires_at).toLocaleDateString('zh-CN') }}</span>
            </div>
          </div>

          <div class="flex items-center gap-2 flex-shrink-0">
            <button v-if="cert.source === 'acme'" @click="issue(cert.id)"
                    class="btn-secondary btn-sm" :disabled="cert.status === 'pending'">
              <RefreshCw :size="13" :class="cert.status === 'pending' ? 'animate-spin' : ''" />
              {{ cert.status === 'pending' ? '申请中...' : '重新申请' }}
            </button>
            <button @click="del(cert.id)" class="btn-ghost btn-sm text-red-400 hover:text-red-500 hover:bg-red-50 opacity-0 group-hover:opacity-100">
              <Trash2 :size="14" />
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Apply cert modal -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900">申请 Let's Encrypt 证书</h3>
              <p class="text-xs text-slate-400 mt-0.5">使用 DNS-01 验证，无需开放 80/443 端口</p>
            </div>
            <button @click="modal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div class="p-4 bg-blue-50 rounded-xl border border-blue-100 text-xs text-blue-700">
              <strong>DNS-01 验证</strong>：通过 DNS 服务商 API 自动添加 TXT 记录完成验证，支持泛域名证书（*.example.com）
            </div>
            <div>
              <label class="input-label">域名</label>
              <input v-model="form.domain" class="input font-mono" placeholder="example.com 或 *.example.com" />
            </div>
            <div>
              <label class="input-label">邮箱（Let's Encrypt 通知）</label>
              <input v-model="form.email" class="input" type="email" placeholder="admin@example.com" />
            </div>
            <div>
              <label class="input-label">DNS 服务商</label>
              <select v-model="form.provider" class="select">
                <option value="cloudflare">Cloudflare</option>
              </select>
            </div>
            <template v-if="form.provider === 'cloudflare'">
              <div class="p-4 bg-amber-50 rounded-xl border border-amber-100 space-y-3">
                <h4 class="text-xs font-bold text-amber-700 uppercase tracking-wide">Cloudflare API</h4>
                <div>
                  <label class="input-label">API Token</label>
                  <input v-model="form.provider_conf.api_token" class="input font-mono text-xs" placeholder="需要 DNS:Edit 权限" />
                </div>
                <div>
                  <label class="input-label">Zone ID</label>
                  <input v-model="form.provider_conf.zone_id" class="input font-mono text-xs" />
                </div>
              </div>
            </template>
            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="form.auto_renew" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">到期前 30 天自动续期</span>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="modal=null">取消</button>
            <button class="btn-primary" @click="createAndIssue">
              <Shield :size="14" /> 申请证书
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Upload modal -->
    <Teleport to="body">
      <div v-if="uploadModal" class="modal-overlay" @click.self="uploadModal=null">
        <div class="modal-box">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <h3 class="font-semibold text-slate-900">上传证书</h3>
            <button @click="uploadModal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div>
              <label class="input-label">域名</label>
              <input v-model="uploadForm.domain" class="input font-mono" placeholder="example.com" />
            </div>
            <div>
              <label class="input-label">证书内容 (PEM)</label>
              <textarea v-model="uploadForm.cert_pem" class="input font-mono text-xs h-28 resize-none"
                        placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
            </div>
            <div>
              <label class="input-label">私钥内容 (PEM)</label>
              <textarea v-model="uploadForm.key_pem" class="input font-mono text-xs h-28 resize-none"
                        placeholder="-----BEGIN EC PRIVATE KEY-----&#10;...&#10;-----END EC PRIVATE KEY-----"></textarea>
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="uploadModal=null">取消</button>
            <button class="btn-primary" @click="upload">
              <Upload :size="14" /> 上传
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Plus, Shield, Lock, RefreshCw, Upload, Trash2, X } from 'lucide-vue-next'
import { api } from '@/stores/auth'
import ProviderBadge from '@/components/ProviderBadge.vue'
import StatusBadge from '@/components/StatusBadge.vue'

const certs = ref([])
const modal = ref(null)
const uploadModal = ref(null)
const form = ref({})
const uploadForm = ref({})

function certGradient(days) {
  if (days < 0)  return 'linear-gradient(135deg, #94a3b8, #64748b)'
  if (days < 14) return 'linear-gradient(135deg, #ef4444, #dc2626)'
  if (days < 30) return 'linear-gradient(135deg, #f59e0b, #d97706)'
  return 'linear-gradient(135deg, #10b981, #059669)'
}
function certBarColor(days) {
  if (days < 14) return '#ef4444'
  if (days < 30) return '#f59e0b'
  return '#10b981'
}

async function load() {
  const { data } = await api.get('/tls')
  certs.value = data
}

function openModal() {
  form.value = { domain: '', email: '', provider: 'cloudflare', provider_conf: {}, auto_renew: true, source: 'acme' }
  modal.value = true
}
function openUpload() {
  uploadForm.value = { domain: '', cert_pem: '', key_pem: '' }
  uploadModal.value = true
}

async function createAndIssue() {
  const { data } = await api.post('/tls', { ...form.value })
  modal.value = null
  await api.post(`/tls/${data.id}/issue`)
  await load()
}

async function issue(id) {
  await api.post(`/tls/${id}/issue`)
  await load()
}

async function upload() {
  await api.post('/tls/upload', uploadForm.value)
  uploadModal.value = null
  await load()
}

async function del(id) {
  if (!confirm('确认删除此证书？')) return
  await api.delete(`/tls/${id}`)
  await load()
}

onMounted(load)
</script>
