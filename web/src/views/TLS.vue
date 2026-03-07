<template>
  <div class="space-y-6 animate-fade-in">
    <div class="page-header">
      <div>
        <h1 class="page-title">{{ t('tlsTitle') }}</h1>
        <p class="page-subtitle">{{ t('tlsSubtitle') }}</p>
      </div>
      <div class="flex gap-2">
        <button class="btn-secondary" @click="openUpload()">
          <Upload :size="16" /> {{ t('uploadCert') }}
        </button>
        <button class="btn-primary" @click="openModal()">
          <Plus :size="16" /> {{ t('applyCert') }}
        </button>
      </div>
    </div>

    <div v-if="certs.length === 0" class="glass-card p-16 text-center">
      <div class="w-16 h-16 rounded-3xl bg-amber-50 flex items-center justify-center mx-auto mb-4">
        <Shield :size="28" class="text-amber-400" />
      </div>
      <p class="text-slate-500 font-medium">{{ t('noTlsCerts') }}</p>
      <p class="text-slate-400 text-sm mt-1">{{ t('noTlsCertsHint') }}</p>
    </div>

    <div v-else class="grid gap-4">
      <div v-for="cert in certs" :key="cert.id"
           class="glass-card p-5 group hover:shadow-colored-amber transition-all duration-300">
        <div class="flex items-center gap-4">
          <!-- Days badge -->
          <div class="w-14 h-14 rounded-2xl flex flex-col items-center justify-center flex-shrink-0 text-white"
               :style="`background: ${certGradient(cert.days_left)}`">
            <Lock :size="16" class="mb-0.5" />
            <span class="text-xs font-bold leading-none">{{ cert.days_left >= 0 ? cert.days_left : '?' }}</span>
            <span class="text-[9px] opacity-80">DAYS</span>
          </div>

          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1.5 flex-wrap">
              <span class="font-semibold text-slate-900">{{ cert.name || cert.domain }}</span>
              <StatusBadge :status="cert.status" />
              <!-- domain tags -->
              <span v-for="d in (cert.domains||[cert.domain]).slice(0,3)" :key="d"
                    class="font-mono text-xs text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded">{{ d }}</span>
              <span v-if="(cert.domains||[]).length > 3" class="text-xs text-slate-400">+{{ cert.domains.length-3 }}</span>
              <span class="badge badge-slate text-xs">{{ cert.source === 'acme' ? 'ACME' : t('manual') }}</span>
              <!-- CA badge -->
              <span v-if="cert.ca_provider === 'zerossl'" class="badge text-xs" style="background:#f0f9ff;color:#0369a1;border:1px solid #bae6fd">ZeroSSL</span>
              <span v-else-if="cert.source === 'acme'" class="badge text-xs" style="background:#f0fdf4;color:#166534;border:1px solid #bbf7d0">Let's Encrypt</span>
              <!-- fallback: ca_provider explicitly set but not matched above -->
              <span v-else-if="cert.ca_provider && cert.ca_provider !== 'letsencrypt'" class="badge text-xs badge-slate">{{ cert.ca_provider }}</span>
              <ProviderBadge v-if="cert.provider" :provider="cert.provider" />
              <span v-if="cert.auto_renew" class="badge badge-green text-xs">{{ t('autoRenew') }}</span>
            </div>

            <div class="h-1.5 bg-slate-100 rounded-full overflow-hidden mb-2 max-w-xs">
              <div class="h-full rounded-full transition-all duration-700"
                   :style="`width: ${Math.min(100, Math.max(0, cert.days_left/90*100))}%; background: ${certBarColor(cert.days_left)}`"></div>
            </div>

            <div class="flex items-center gap-4 text-xs text-slate-400">
              <span v-if="cert.issued_at">{{ t('issuedAt') }} {{ fmtDate(cert.issued_at) }}</span>
              <span v-if="cert.expires_at">{{ t('expiresAt') }} {{ fmtDate(cert.expires_at) }}</span>
            </div>
          </div>

          <div class="flex items-center gap-1.5 flex-shrink-0">
            <!-- Download (only if cert exists) -->
            <button v-if="cert.status === 'active'" @click="downloadCert(cert)"
                    class="btn-ghost btn-sm text-slate-500" :title="t('downloadCert')">
              <Download :size="13" />
            </button>
            <!-- View PEM -->
            <button v-if="cert.status === 'active'" @click="viewPEM(cert)"
                    class="btn-ghost btn-sm text-slate-500" :title="t('viewCert')">
              <Eye :size="13" />
            </button>
            <!-- Edit -->
            <button @click="openEdit(cert)" class="btn-ghost btn-sm text-slate-500" :title="t('editCert')">
              <Pencil :size="13" />
            </button>
            <!-- Re-issue (ACME only) -->
            <button v-if="cert.source === 'acme'" @click="issue(cert.id)"
                    class="btn-secondary btn-sm" :disabled="cert.status === 'pending'">
              <RefreshCw :size="13" :class="cert.status === 'pending' ? 'animate-spin' : ''" />
              {{ cert.status === 'pending' ? t('applying') : t('reApply') }}
            </button>
            <button @click="del(cert.id)" class="btn-ghost btn-sm text-red-400 hover:text-red-500 hover:bg-red-50">
              <Trash2 :size="13" />
            </button>
          </div>
        </div>

        <!-- Error message -->
        <div v-if="cert.status === 'error'" class="mt-3 px-3 py-2 bg-red-50 rounded-lg border border-red-100 text-xs text-red-600 flex items-center gap-2">
          <AlertCircle :size="13" />
          {{ cert.error_msg || t('applyFailed') }}
        </div>
      </div>
    </div>

    <!-- ─── Apply / Edit cert modal ─────────────────────────────────────── -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box max-w-lg">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900">{{ editId ? t('editTlsCert') : t('applyAcme') }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">{{ t('acmeDesc') }}</p>
            </div>
            <button @click="modal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>

          <div class="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
            <!-- CA Provider -->
            <div>
              <label class="input-label">{{ t('caProvider') }}</label>
              <div class="grid grid-cols-2 gap-3">
                <button type="button"
                  @click="form.ca_provider='letsencrypt'"
                  :class="['ca-btn', form.ca_provider !== 'zerossl' ? 'ca-btn-active' : '']">
                  <div class="font-semibold text-sm">Let's Encrypt</div>
                  <div class="text-xs text-slate-400 mt-0.5">{{ t('leFree') }}</div>
                </button>
                <button type="button"
                  @click="form.ca_provider='zerossl'"
                  :class="['ca-btn', form.ca_provider === 'zerossl' ? 'ca-btn-active' : '']">
                  <div class="font-semibold text-sm">ZeroSSL</div>
                  <div class="text-xs text-slate-400 mt-0.5">{{ t('zsFree') }}</div>
                </button>
              </div>
            </div>

            <div>
              <label class="input-label">{{ t('certTaskName') }}</label>
              <input v-model="form.name" class="input" :placeholder="t('certTaskPlaceholder')" />
            </div>

            <div>
              <label class="input-label">{{ t('certDomains') }}</label>
              <textarea v-model="form.domainsText" class="input font-mono text-sm resize-none" rows="4"
                        placeholder="example.com&#10;*.example.com&#10;www.example.com"></textarea>
              <p class="text-xs text-slate-400 mt-1">{{ t('certDomainsHint') }}</p>
            </div>

            <div>
              <label class="input-label">{{ t('acmeEmail') }}</label>
              <input v-model="form.email" class="input" type="email" placeholder="admin@example.com" />
            </div>

            <!-- ZeroSSL EAB -->
            <div v-if="form.ca_provider === 'zerossl'"
                 class="p-4 bg-sky-50 rounded-xl border border-sky-100 space-y-3">
              <div class="flex items-start gap-2">
                <Info :size="14" class="text-sky-500 mt-0.5 flex-shrink-0" />
                <p class="text-xs text-sky-700">
                  {{ t('zsEabHint') }}
                  <a href="https://app.zerossl.com/developer" target="_blank" class="underline font-medium">{{ t('zsEabLink') }}</a>
                </p>
              </div>
              <div>
                <label class="input-label">EAB Key ID</label>
                <input v-model="form.provider_conf.zerossl_key_id" class="input font-mono text-xs" placeholder="ZeroSSL EAB Key ID" />
              </div>
              <div>
                <label class="input-label">EAB HMAC Key</label>
                <input v-model="form.provider_conf.zerossl_api_key" class="input font-mono text-xs" placeholder="ZeroSSL EAB HMAC Key" />
              </div>
            </div>

            <!-- DNS Provider -->
            <div>
              <label class="input-label">{{ t('dnsProviderLabel') }}</label>
              <select v-model="form.provider" class="select">
                <option value="cloudflare">Cloudflare</option>
              </select>
            </div>

            <template v-if="form.provider === 'cloudflare'">
              <div class="p-4 bg-amber-50 rounded-xl border border-amber-100 space-y-3">
                <h4 class="text-xs font-bold text-amber-700 uppercase tracking-wide">Cloudflare DNS API</h4>
                <div class="p-3 bg-amber-100/60 rounded-lg text-xs text-amber-700">
                  <span v-html="t('cfTokenHint')"></span>
                </div>
                <div>
                  <label class="input-label">API Token</label>
                  <input v-model="form.provider_conf.api_token" class="input font-mono text-xs" placeholder="CF API Token (DNS:Edit)" />
                </div>
                <div>
                  <label class="input-label">Zone ID</label>
                  <input v-model="form.provider_conf.zone_id" class="input font-mono text-xs" :placeholder="t('cfZoneIdPlaceholder')" />
                </div>
              </div>
            </template>

            <div class="flex items-center gap-3">
              <label class="toggle">
                <input type="checkbox" v-model="form.auto_renew" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <span class="text-sm text-slate-600">{{ t('autoRenewHint') }}</span>
            </div>

            <div v-if="modalError" class="flex items-center gap-2 text-red-600 bg-red-50 px-3 py-2.5 rounded-xl border border-red-100 text-xs">
              <AlertCircle :size="13" /> {{ modalError }}
            </div>
          </div>

          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="modal=null">{{ t('cancel') }}</button>
            <button class="btn-primary" @click="editId ? updateCert() : createAndIssue()" :disabled="saving">
              <Shield :size="14" />
              {{ editId ? t('saveReApply') : t('createApply') }}
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- ─── Upload modal ─────────────────────────────────────────────────── -->
    <Teleport to="body">
      <div v-if="uploadModal" class="modal-overlay" @click.self="uploadModal=null">
        <div class="modal-box">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900">{{ t('uploadCertTitle') }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">{{ t('uploadCertDesc') }}</p>
            </div>
            <button @click="uploadModal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
          </div>
          <div class="p-6 space-y-4">
            <div>
              <label class="input-label">{{ t('domain') }}</label>
              <input v-model="uploadForm.domain" class="input font-mono" :placeholder="t('domainPlaceholder')" />
            </div>

            <!-- Upload mode tabs -->
            <div class="flex gap-2 p-1 bg-slate-100 rounded-xl">
              <button type="button" @click="uploadMode='files'"
                      :class="['flex-1 py-1.5 text-xs font-medium rounded-lg transition-all', uploadMode==='files' ? 'bg-white shadow text-slate-800' : 'text-slate-500 hover:text-slate-700']">
                {{ t('separatePem') }}
              </button>
              <button type="button" @click="uploadMode='zip'"
                      :class="['flex-1 py-1.5 text-xs font-medium rounded-lg transition-all', uploadMode==='zip' ? 'bg-white shadow text-slate-800' : 'text-slate-500 hover:text-slate-700']">
                {{ t('zipUpload') }}
              </button>
              <button type="button" @click="uploadMode='paste'"
                      :class="['flex-1 py-1.5 text-xs font-medium rounded-lg transition-all', uploadMode==='paste' ? 'bg-white shadow text-slate-800' : 'text-slate-500 hover:text-slate-700']">
                {{ t('pasteText') }}
              </button>
            </div>

            <!-- Files mode -->
            <template v-if="uploadMode==='files'">
              <div>
                <label class="input-label">{{ t('certFilePem') }}</label>
                <label class="flex items-center gap-3 p-3 border-2 border-dashed border-slate-200 rounded-xl cursor-pointer hover:border-vane-300 hover:bg-vane-50/30 transition-all">
                  <Upload :size="16" class="text-slate-400 flex-shrink-0" />
                  <span class="text-sm text-slate-500">{{ uploadForm.certFile ? uploadForm.certFile.name : t('selectFile') }}</span>
                  <input type="file" accept=".pem,.crt,.cer" class="hidden" @change="e => uploadForm.certFile = e.target.files[0]" />
                </label>
              </div>
              <div>
                <label class="input-label">{{ t('keyFilePem') }}</label>
                <label class="flex items-center gap-3 p-3 border-2 border-dashed border-slate-200 rounded-xl cursor-pointer hover:border-vane-300 hover:bg-vane-50/30 transition-all">
                  <Upload :size="16" class="text-slate-400 flex-shrink-0" />
                  <span class="text-sm text-slate-500">{{ uploadForm.keyFile ? uploadForm.keyFile.name : t('selectKeyFile') }}</span>
                  <input type="file" accept=".pem,.key" class="hidden" @change="e => uploadForm.keyFile = e.target.files[0]" />
                </label>
              </div>
            </template>

            <!-- Zip mode -->
            <template v-else-if="uploadMode==='zip'">
              <div>
                <label class="input-label">{{ t('zipHint') }}</label>
                <label class="flex items-center gap-3 p-3 border-2 border-dashed border-slate-200 rounded-xl cursor-pointer hover:border-vane-300 hover:bg-vane-50/30 transition-all">
                  <Upload :size="16" class="text-slate-400 flex-shrink-0" />
                  <span class="text-sm text-slate-500">{{ uploadForm.zipFile ? uploadForm.zipFile.name : t('selectZip') }}</span>
                  <input type="file" accept=".zip" class="hidden" @change="e => uploadForm.zipFile = e.target.files[0]" />
                </label>
              </div>
            </template>

            <!-- Paste mode -->
            <template v-else>
              <div>
                <label class="input-label">{{ t('certPem') }}</label>
                <textarea v-model="uploadForm.cert_pem" class="input font-mono text-xs h-24 resize-none"
                          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
              </div>
              <div>
                <label class="input-label">{{ t('keyPem') }}</label>
                <textarea v-model="uploadForm.key_pem" class="input font-mono text-xs h-24 resize-none"
                          placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"></textarea>
              </div>
            </template>

            <div v-if="uploadError" class="flex items-center gap-2 text-red-600 bg-red-50 px-3 py-2 rounded-xl border border-red-100 text-xs">
              <AlertCircle :size="13" /> {{ uploadError }}
            </div>
          </div>
          <div class="flex justify-end gap-3 px-6 pb-6">
            <button class="btn-secondary" @click="uploadModal=null">{{ t('cancel') }}</button>
            <button class="btn-primary" @click="upload"><Upload :size="14" /> {{ t('upload') }}</button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- ─── View PEM modal ───────────────────────────────────────────────── -->
    <Teleport to="body">
      <div v-if="pemModal" class="modal-overlay" @click.self="pemModal=null">
        <div class="modal-box max-w-2xl">
          <div class="flex items-center justify-between p-6 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900 font-mono">{{ pemData.domain }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">{{ t('certContent') }}</p>
            </div>
            <div class="flex gap-2">
              <button class="btn-secondary btn-sm" @click="downloadFromPEM()"><Download :size="13" /> {{ t('downloadCertBtn') }}</button>
              <button class="btn-secondary btn-sm" @click="downloadKeyFromPEM()"><Download :size="13" /> {{ t('downloadKey') }}</button>
              <button @click="pemModal=null" class="btn-ghost btn-sm"><X :size="16" /></button>
            </div>
          </div>
          <div class="p-6 space-y-4">
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="input-label mb-0">{{ t('certPemLabel') }}</label>
                <button class="text-xs text-vane-500 hover:text-vane-700" @click="copy(pemData.cert_pem)">
                  <Copy :size="12" class="inline mr-1" />{{ t('copy') }}
                </button>
              </div>
              <textarea readonly class="input font-mono text-xs h-40 resize-none bg-slate-50" :value="pemData.cert_pem"></textarea>
            </div>
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="input-label mb-0">{{ t('keyPemLabel') }}</label>
                <button class="text-xs text-vane-500 hover:text-vane-700" @click="copy(pemData.key_pem)">
                  <Copy :size="12" class="inline mr-1" />{{ t('copy') }}
                </button>
              </div>
              <textarea readonly class="input font-mono text-xs h-40 resize-none bg-slate-50" :value="pemData.key_pem"></textarea>
            </div>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import {
  Plus, Shield, Lock, RefreshCw, Upload, Trash2, X,
  Download, Eye, Pencil, AlertCircle, Info, Copy
} from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'
import ProviderBadge from '@/components/ProviderBadge.vue'
import StatusBadge from '@/components/StatusBadge.vue'

const { t } = useI18n()

const certs = ref([])
const modal = ref(null)
const uploadModal = ref(null)
const pemModal = ref(false)
const pemData = ref({})
const form = ref({})
const uploadForm = ref({})
const editId = ref(null)
const saving = ref(false)
const modalError = ref('')
const uploadMode = ref('files')
const uploadError = ref('')

function fmtDate(s) {
  if (!s) return ''
  return new Date(s).toLocaleDateString('zh-CN')
}
function certGradient(days) {
  if (days < 0)  return 'linear-gradient(135deg,#94a3b8,#64748b)'
  if (days < 14) return 'linear-gradient(135deg,#ef4444,#dc2626)'
  if (days < 30) return 'linear-gradient(135deg,#f59e0b,#d97706)'
  return 'linear-gradient(135deg,#10b981,#059669)'
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

function blankForm() {
  return {
    name: '', domainsText: '', domain: '', email: '', ca_provider: 'letsencrypt',
    provider: 'cloudflare', provider_conf: {}, auto_renew: true, source: 'acme'
  }
}

function openModal() {
  editId.value = null
  modalError.value = ''
  form.value = blankForm()
  modal.value = true
}

function openEdit(cert) {
  editId.value = cert.id
  modalError.value = ''
  const domains = cert.domains?.length ? cert.domains : (cert.domain ? [cert.domain] : [])
  form.value = {
    name:          cert.name || '',
    domainsText:   domains.join('\n'),
    domain:        cert.domain,
    email:         cert.email || '',
    ca_provider:   cert.ca_provider || 'letsencrypt',
    provider:      cert.provider || 'cloudflare',
    provider_conf: cert.provider_conf || {},
    auto_renew:    cert.auto_renew,
    source:        cert.source,
  }
  modal.value = true
}

function openUpload() {
  uploadForm.value = { domain: '', cert_pem: '', key_pem: '', certFile: null, keyFile: null, zipFile: null }
  uploadError.value = ''
  uploadMode.value = 'files'
  uploadModal.value = true
}

function validateForm() {
  const domains = (form.value.domainsText || '').split('\n').map(s=>s.trim()).filter(Boolean)
  if (!domains.length) return t('errNoDomain')
  if (!form.value.email)  return t('errNoEmail')
  if (form.value.ca_provider === 'zerossl') {
    if (!form.value.provider_conf.zerossl_key_id) return t('errNoEabKeyId')
    if (!form.value.provider_conf.zerossl_api_key) return t('errNoZsHmac')
  }
  if (form.value.provider === 'cloudflare' && !form.value.provider_conf.api_token) {
    return t('errNoCfToken')
  }
  return null
}

function formPayload() {
  const domains = (form.value.domainsText || '').split('\n').map(s=>s.trim()).filter(Boolean)
  return { ...form.value, domains, domain: domains[0] || '', domainsText: undefined }
}

async function createAndIssue() {
  modalError.value = validateForm() || ''
  if (modalError.value) return
  saving.value = true
  try {
    const { data } = await api.post('/tls', formPayload())
    modal.value = null
    await load()
    // Fire issue and poll in background
    api.post(`/tls/${data.id}/issue`).catch(() => {})
    const id = data.id
    const start = Date.now()
    const poll = setInterval(async () => {
      await load()
      const c = certs.value.find(x => x.id === id)
      if (!c || c.status !== 'pending' || Date.now() - start > 900000) clearInterval(poll)
    }, 5000)
  } catch(e) {
    modalError.value = e.response?.data?.error || e.message
  } finally {
    saving.value = false
  }
}

async function updateCert() {
  modalError.value = validateForm() || ''
  if (modalError.value) return
  saving.value = true
  try {
    const id = editId.value
    await api.put(`/tls/${id}`, formPayload())
    modal.value = null
    await load()
    // Re-issue: always fire after save for ACME certs so the new CA/domains take effect.
    // Do NOT await — issue is a long async operation on the server; we just fire and poll.
    api.post(`/tls/${id}/issue`).catch(() => {})
    const start = Date.now()
    const poll = setInterval(async () => {
      await load()
      const c = certs.value.find(x => x.id === id)
      if (!c || c.status !== 'pending' || Date.now() - start > 900000) clearInterval(poll)
    }, 5000)
  } catch(e) {
    modalError.value = e.response?.data?.error || e.message
  } finally {
    saving.value = false
  }
}

async function issue(id) {
  // Optimistically set pending in UI
  const cert = certs.value.find(c => c.id === id)
  if (cert) cert.status = 'pending'
  api.post(`/tls/${id}/issue`).catch(() => {})
  // Poll until status is no longer pending (max 15 min)
  const start = Date.now()
  const poll = setInterval(async () => {
    await load()
    const c = certs.value.find(x => x.id === id)
    if (!c || c.status !== 'pending' || Date.now() - start > 900000) {
      clearInterval(poll)
    }
  }, 5000)
}

async function upload() {
  uploadError.value = ''
  if (!uploadForm.value.domain) { uploadError.value = t('errNoDomainUpload'); return }
  try {
    if (uploadMode.value === 'files') {
      if (!uploadForm.value.certFile || !uploadForm.value.keyFile) {
        uploadError.value = t('errNoCertKey'); return
      }
      const cert_pem = await uploadForm.value.certFile.text()
      const key_pem  = await uploadForm.value.keyFile.text()
      await api.post('/tls/upload', { domain: uploadForm.value.domain, cert_pem, key_pem })
    } else if (uploadMode.value === 'zip') {
      if (!uploadForm.value.zipFile) { uploadError.value = t('errNoZip'); return }
      const JSZip = (await import('https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js')).default
      const zip = await JSZip.loadAsync(uploadForm.value.zipFile)
      // Try common names
      const certEntry = zip.file('cert.pem') || zip.file('fullchain.pem') || zip.file('certificate.pem')
      const keyEntry  = zip.file('key.pem')  || zip.file('privkey.pem')   || zip.file('private.pem')
      if (!certEntry || !keyEntry) { uploadError.value = t('errZipContent'); return }
      const cert_pem = await certEntry.async('string')
      const key_pem  = await keyEntry.async('string')
      await api.post('/tls/upload', { domain: uploadForm.value.domain, cert_pem, key_pem })
    } else {
      if (!uploadForm.value.cert_pem || !uploadForm.value.key_pem) {
        uploadError.value = t('errNoPasteContent'); return
      }
      await api.post('/tls/upload', { domain: uploadForm.value.domain, cert_pem: uploadForm.value.cert_pem, key_pem: uploadForm.value.key_pem })
    }
    uploadModal.value = null
    await load()
  } catch (e) {
    uploadError.value = e.response?.data?.error || e.message
  }
}

async function del(id) {
  if (!confirm(t('confirmDelCert'))) return
  await api.delete(`/tls/${id}`)
  await load()
}

// Download cert + key as zip
async function downloadCert(cert) {
  const { data } = await api.get(`/tls/${cert.id}/pem`)
  const domain = cert.domain.replace('*.', 'wildcard.')
  // Use JSZip if available, otherwise download separately
  try {
    const JSZip = (await import('https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js')).default
    const zip = new JSZip()
    zip.file('cert.pem', data.cert_pem)
    zip.file('key.pem', data.key_pem)
    const blob = await zip.generateAsync({ type: 'blob' })
    triggerDownload(`${domain}-certs.zip`, blob, true)
  } catch {
    // Fallback: download both separately
    triggerDownload(domain + '-cert.pem', data.cert_pem)
    setTimeout(() => triggerDownload(domain + '-key.pem', data.key_pem), 500)
  }
}

async function viewPEM(cert) {
  const { data } = await api.get(`/tls/${cert.id}/pem`)
  pemData.value = data
  pemModal.value = true
}

function downloadFromPEM() {
  triggerDownload(pemData.value.domain + '-cert.pem', pemData.value.cert_pem)
}
function downloadKeyFromPEM() {
  triggerDownload(pemData.value.domain + '-key.pem', pemData.value.key_pem)
}

function triggerDownload(filename, content, isBlob = false) {
  const blob = isBlob ? content : new Blob([content], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

function copy(text) {
  navigator.clipboard.writeText(text).catch(() => {})
}

onMounted(load)
</script>

<style scoped>
.ca-btn {
  @apply p-3 rounded-xl border-2 border-slate-200 bg-white text-left cursor-pointer transition-all duration-200 hover:border-vane-300;
}
.ca-btn-active {
  @apply border-vane-500 bg-vane-50;
}
</style>
