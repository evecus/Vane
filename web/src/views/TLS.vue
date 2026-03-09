<template>
  <div class="space-y-4 sm:space-y-6 animate-fade-in">

    <!-- 页面标题 + 按钮 -->
    <div class="page-header">
      <h1 class="page-title">{{ t('tlsTitle') }}</h1>
      <div class="flex gap-2">
        <button class="btn-secondary btn-sm sm:btn-normal" @click="openUpload()">
          <Upload :size="15" />
          <span class="hidden xs:inline">{{ t('uploadCert') }}</span>
        </button>
        <button class="btn-primary btn-sm sm:btn-normal" @click="openModal()">
          <Plus :size="15" />
          <span class="hidden xs:inline">{{ t('applyCert') }}</span>
        </button>
      </div>
    </div>

    <!-- 空状态 -->
    <div v-if="certs.length === 0" class="glass-card p-10 sm:p-16 text-center">
      <div class="w-14 h-14 sm:w-16 sm:h-16 rounded-3xl bg-amber-50 flex items-center justify-center mx-auto mb-4">
        <Shield :size="26" class="text-amber-400" />
      </div>
      <p class="text-slate-500 font-medium">{{ t('noTlsCerts') }}</p>
      <p class="text-slate-400 text-sm mt-1">{{ t('noTlsCertsHint') }}</p>
    </div>

    <!-- 证书列表 -->
    <div v-else class="grid gap-3 sm:gap-4">
      <div v-for="cert in certs" :key="cert.id"
           class="glass-card p-4 sm:p-5 group transition-all duration-300">

        <div class="flex items-start gap-3 sm:gap-4">
          <!-- Days badge -->
          <div class="w-12 h-12 sm:w-14 sm:h-14 rounded-xl sm:rounded-2xl flex flex-col items-center justify-center flex-shrink-0 text-white"
               :style="`background: ${certGradient(cert.days_left)}`">
            <Lock :size="14" class="mb-0.5" />
            <span class="text-xs font-bold leading-none">{{ cert.days_left >= 0 ? cert.days_left : '?' }}</span>
            <span class="text-[9px] opacity-80 leading-none mt-0.5">DAYS</span>
          </div>

          <!-- 内容区 -->
          <div class="flex-1 min-w-0">
            <!-- 名称 + 状态标签 -->
            <div class="flex items-center gap-1.5 mb-1.5 flex-wrap">
              <span class="font-semibold text-slate-900 text-sm sm:text-base leading-tight">{{ cert.name || cert.domain }}</span>
              <StatusBadge :status="cert.status" />
              <span v-for="d in (cert.domains||[cert.domain]).slice(0,2)" :key="d"
                    class="font-mono text-xs text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded break-all hidden sm:inline">{{ d }}</span>
              <span v-if="(cert.domains||[cert.domain]).length > 2" class="text-xs text-slate-400 hidden sm:inline">+{{ (cert.domains||[cert.domain]).length - 2 }}</span>
            </div>

            <!-- 移动端域名（单独一行，最多显示1个） -->
            <div class="flex flex-wrap gap-1 mb-1.5 sm:hidden">
              <span v-if="cert.domain" class="font-mono text-xs text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded break-all max-w-full truncate">{{ cert.domain }}</span>
              <span v-if="(cert.domains||[]).length > 1" class="text-xs text-slate-400">+{{ cert.domains.length - 1 }}</span>
            </div>

            <!-- 徽章行 -->
            <div class="flex flex-wrap items-center gap-1 mb-2">
              <span class="badge badge-slate text-xs">{{ cert.source === 'acme' ? 'ACME' : t('manual') }}</span>
              <span v-if="cert.ca_provider === 'zerossl'" class="badge text-xs" style="background:#f0f9ff;color:#0369a1;border:1px solid #bae6fd">ZeroSSL</span>
              <span v-else-if="cert.source === 'acme'" class="badge text-xs" style="background:#f0fdf4;color:#166534;border:1px solid #bbf7d0">Let's Encrypt</span>
              <span v-else-if="cert.ca_provider && cert.ca_provider !== 'letsencrypt'" class="badge text-xs badge-slate">{{ cert.ca_provider }}</span>
              <ProviderBadge v-if="cert.provider" :provider="cert.provider" />
              <span v-if="cert.auto_renew" class="badge badge-green text-xs">{{ t('autoRenew') }}</span>
            </div>

            <!-- 进度条 -->
            <div class="h-1.5 bg-slate-100 rounded-full overflow-hidden mb-2 max-w-[200px] sm:max-w-xs">
              <div class="h-full rounded-full transition-all duration-700"
                   :style="`width: ${Math.min(100, Math.max(0, cert.days_left/90*100))}%; background: ${certBarColor(cert.days_left)}`"></div>
            </div>

            <!-- 日期信息 -->
            <div class="flex flex-wrap items-center gap-2 sm:gap-4 text-xs text-slate-400">
              <span v-if="cert.issued_at">{{ t('issuedAt') }} {{ fmtDate(cert.issued_at) }}</span>
              <span v-if="cert.expires_at">{{ t('expiresAt') }} {{ fmtDate(cert.expires_at) }}</span>
            </div>
          </div>

          <!-- 操作按钮区（桌面端） -->
          <div class="hidden sm:flex items-center gap-1.5 flex-shrink-0">
            <button v-if="cert.status === 'active'" @click="downloadCert(cert)"
                    class="btn-ghost btn-sm text-slate-500" :title="t('downloadCert')">
              <Download :size="13" />
            </button>
            <button v-if="cert.status === 'active'" @click="viewPEM(cert)"
                    class="btn-ghost btn-sm text-slate-500" :title="t('viewCert')">
              <Eye :size="13" />
            </button>
            <button @click="openEdit(cert)" class="btn-ghost btn-sm text-slate-500" :title="t('editCert')">
              <Pencil :size="13" />
            </button>
            <button v-if="cert.source === 'acme'" @click="issue(cert.id)"
                    class="btn-secondary btn-sm" :disabled="cert.status === 'pending'">
              <RefreshCw :size="13" :class="cert.status === 'pending' ? 'animate-spin' : ''" />
              {{ cert.status === 'pending' ? t('applying') : t('reApply') }}
            </button>
            <button @click="del(cert.id)" class="btn-ghost btn-sm text-red-400 hover:text-red-500 hover:bg-red-50">
              <Trash2 :size="13" />
            </button>
          </div>

          <!-- 移动端：右上角仅编辑按钮 -->
          <div class="flex sm:hidden items-center flex-shrink-0 -mt-0.5">
            <button @click="openEdit(cert)" class="btn-ghost p-1.5 text-slate-400">
              <Pencil :size="14" />
            </button>
          </div>
        </div>

        <!-- 移动端操作栏（在卡片底部） -->
        <div class="flex sm:hidden items-center gap-2 mt-3 pt-3 border-t border-slate-100">
          <button v-if="cert.status === 'active'" @click="downloadCert(cert)"
                  class="btn-ghost btn-sm flex-1 justify-center text-slate-500 gap-1.5">
            <Download :size="13" /> <span class="text-xs">{{ t('downloadCert') }}</span>
          </button>
          <button v-if="cert.status === 'active'" @click="viewPEM(cert)"
                  class="btn-ghost btn-sm flex-1 justify-center text-slate-500 gap-1.5">
            <Eye :size="13" /> <span class="text-xs">{{ t('viewCert') }}</span>
          </button>
          <button v-if="cert.source === 'acme'" @click="issue(cert.id)"
                  class="btn-secondary btn-sm flex-1 justify-center" :disabled="cert.status === 'pending'">
            <RefreshCw :size="13" :class="cert.status === 'pending' ? 'animate-spin' : ''" />
            <span class="text-xs">{{ cert.status === 'pending' ? t('applying') : t('reApply') }}</span>
          </button>
          <button @click="del(cert.id)" class="btn-ghost btn-sm flex-1 justify-center text-red-400 hover:bg-red-50 gap-1.5">
            <Trash2 :size="13" /> <span class="text-xs">删除</span>
          </button>
        </div>

        <!-- 错误信息 -->
        <div v-if="cert.status === 'error'" class="mt-3 px-3 py-2 bg-red-50 rounded-lg border border-red-100 text-xs text-red-600 flex items-start gap-2">
          <AlertCircle :size="13" class="flex-shrink-0 mt-0.5" />
          <span class="break-all">{{ cert.error_msg || t('applyFailed') }}</span>
        </div>
      </div>
    </div>

    <!-- ══ 申请 / 编辑证书弹窗 ══════════════════════════════════════════ -->
    <Teleport to="body">
      <div v-if="modal" class="modal-overlay" @click.self="modal=null">
        <div class="modal-box max-w-lg">

          <!-- 移动端拖动条 -->
          <div class="sm:hidden flex justify-center pt-3 pb-1 flex-shrink-0">
            <div class="w-10 h-1 bg-slate-200 rounded-full"></div>
          </div>

          <!-- 标题栏 -->
          <div class="flex-shrink-0 flex items-center justify-between px-5 sm:px-6 py-3 sm:py-4 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900 text-base">{{ editId ? t('editTlsCert') : t('applyAcme') }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">{{ t('acmeDesc') }}</p>
            </div>
            <button @click="modal=null" class="btn-ghost btn-sm p-1.5 ml-2"><X :size="16" /></button>
          </div>

          <!-- 可滚动内容区 -->
          <div class="flex-1 overflow-y-auto overscroll-contain px-5 sm:px-6 py-4 space-y-4">

            <!-- CA Provider -->
            <div>
              <label class="input-label">{{ t('caProvider') }}</label>
              <div class="grid grid-cols-2 gap-2 sm:gap-3">
                <button type="button"
                  @click="form.ca_provider='letsencrypt'"
                  :class="['ca-btn', form.ca_provider !== 'zerossl' ? 'ca-btn-active' : '']">
                  <div class="font-semibold text-sm">Let's Encrypt</div>
                  <div class="text-xs text-slate-400 mt-0.5 leading-snug">{{ t('leFree') }}</div>
                </button>
                <button type="button"
                  @click="form.ca_provider='zerossl'"
                  :class="['ca-btn', form.ca_provider === 'zerossl' ? 'ca-btn-active' : '']">
                  <div class="font-semibold text-sm">ZeroSSL</div>
                  <div class="text-xs text-slate-400 mt-0.5 leading-snug">{{ t('zsFree') }}</div>
                </button>
              </div>
            </div>

            <!-- 任务名称 -->
            <div>
              <label class="input-label">{{ t('certTaskName') }}</label>
              <input v-model="form.name" class="input" :placeholder="t('certTaskPlaceholder')" />
            </div>

            <!-- 域名列表 -->
            <div>
              <label class="input-label">{{ t('certDomains') }}</label>
              <textarea v-model="form.domainsText" class="input font-mono text-sm resize-none" rows="3"
                        placeholder="example.com&#10;*.example.com"></textarea>
              <p class="text-xs text-slate-400 mt-1">{{ t('certDomainsHint') }}</p>
            </div>

            <!-- ZeroSSL 区域 -->
            <template v-if="form.ca_provider === 'zerossl'">
              <!-- 是否使用私有账号 -->
              <div class="flex items-center justify-between p-3 bg-slate-50 rounded-xl border border-slate-200 gap-3">
                <div class="min-w-0">
                  <div class="text-sm font-medium text-slate-700">{{ t('usePrivateAccount') }}</div>
                  <div class="text-xs text-slate-400 mt-0.5 leading-snug">{{ t('usePrivateAccountHint') }}</div>
                </div>
                <label class="toggle flex-shrink-0">
                  <input type="checkbox" v-model="form.usePrivateAccount" />
                  <div class="toggle-track"></div>
                  <div class="toggle-thumb"></div>
                </label>
              </div>

              <!-- 私有账号填写区 -->
              <div v-if="form.usePrivateAccount"
                   class="p-4 bg-sky-50 rounded-xl border border-sky-100 space-y-3">
                <div>
                  <label class="input-label">{{ t('acmeEmail') }}</label>
                  <input v-model="form.email" class="input" type="email" placeholder="admin@example.com"
                         autocomplete="off" inputmode="email" />
                </div>
                <div>
                  <label class="input-label">EAB Key ID</label>
                  <input v-model="form.provider_conf.zerossl_key_id" class="input font-mono text-xs"
                         placeholder="ZeroSSL EAB Key ID" autocomplete="off" />
                </div>
                <div>
                  <label class="input-label">EAB HMAC Key</label>
                  <input v-model="form.provider_conf.zerossl_api_key" class="input font-mono text-xs"
                         placeholder="ZeroSSL EAB HMAC Key" autocomplete="off" />
                </div>
              </div>
            </template>

            <!-- Let's Encrypt：邮箱 -->
            <template v-else>
              <div>
                <label class="input-label">{{ t('acmeEmail') }}</label>
                <input v-model="form.email" class="input" type="email" placeholder="admin@example.com"
                       autocomplete="off" inputmode="email" />
              </div>
            </template>

            <!-- DNS Provider -->
            <div>
              <label class="input-label">{{ t('dnsProviderLabel') }}</label>
              <select v-model="form.provider" class="select">
                <option value="cloudflare">Cloudflare</option>
              </select>
            </div>

            <!-- Cloudflare 配置 -->
            <template v-if="form.provider === 'cloudflare'">
              <div class="p-4 bg-amber-50 rounded-xl border border-amber-100 space-y-3">
                <h4 class="text-xs font-bold text-amber-700 uppercase tracking-wide">Cloudflare DNS API</h4>
                <div class="p-2.5 bg-amber-100/60 rounded-lg text-xs text-amber-700 leading-relaxed">
                  <span v-html="t('cfTokenHint')"></span>
                </div>
                <div>
                  <label class="input-label">API Token</label>
                  <input v-model="form.provider_conf.api_token" class="input font-mono text-xs"
                         placeholder="CF API Token (DNS:Edit)" autocomplete="off" />
                </div>
              </div>
            </template>

            <!-- 错误提示 -->
            <div v-if="modalError" class="flex items-start gap-2 text-red-600 bg-red-50 px-3 py-2.5 rounded-xl border border-red-100 text-xs">
              <AlertCircle :size="13" class="flex-shrink-0 mt-0.5" /> <span>{{ modalError }}</span>
            </div>
          </div>

          <!-- 底部操作栏 -->
          <div class="flex-shrink-0 border-t border-slate-100 px-5 sm:px-6 py-3 sm:py-4">
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div class="flex items-center gap-2">
                <span class="text-sm text-slate-600">{{ t('autoRenewHint') }}</span>
                <label class="toggle">
                  <input type="checkbox" v-model="form.auto_renew" />
                  <div class="toggle-track"></div>
                  <div class="toggle-thumb"></div>
                </label>
              </div>
              <div class="flex gap-2 sm:gap-3">
                <button class="btn-primary flex-1 sm:flex-none sm:min-w-[120px] justify-center"
                        @click="editId ? updateCert() : createAndIssue()" :disabled="saving">
                  <Shield :size="14" />
                  <span>{{ editId ? t('saveReApply') : t('createApply') }}</span>
                </button>
                <button class="btn-secondary flex-1 sm:flex-none sm:min-w-[80px] justify-center" @click="modal=null">
                  {{ t('cancel') }}
                </button>
              </div>
            </div>
          </div>

        </div>
      </div>
    </Teleport>

    <!-- ══ 上传证书弹窗 ════════════════════════════════════════════════ -->
    <Teleport to="body">
      <div v-if="uploadModal" class="modal-overlay" @click.self="uploadModal=null">
        <div class="modal-box max-w-lg">

          <div class="sm:hidden flex justify-center pt-3 pb-1 flex-shrink-0">
            <div class="w-10 h-1 bg-slate-200 rounded-full"></div>
          </div>

          <div class="flex-shrink-0 flex items-center justify-between px-5 sm:px-6 py-3 sm:py-4 border-b border-slate-100">
            <div>
              <h3 class="font-semibold text-slate-900 text-base">{{ t('uploadCertTitle') }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">上传包含 cert.pem 和 key.pem 的 ZIP 压缩包</p>
            </div>
            <button @click="uploadModal=null" class="btn-ghost btn-sm p-1.5 ml-2"><X :size="16" /></button>
          </div>

          <div class="flex-1 overflow-y-auto overscroll-contain px-5 sm:px-6 py-4 space-y-4">

            <div>
              <label class="input-label">证书 ZIP 文件</label>
              <label class="flex items-center gap-3 p-4 border-2 border-dashed border-slate-200 rounded-xl cursor-pointer hover:border-vane-300 hover:bg-vane-50/30 transition-all active:bg-vane-50/50">
                <Upload :size="18" class="text-slate-400 flex-shrink-0" />
                <div class="min-w-0">
                  <div class="text-sm text-slate-600 truncate">{{ uploadForm.zipFile ? uploadForm.zipFile.name : '点击选择 ZIP 文件' }}</div>
                  <div class="text-xs text-slate-400 mt-0.5">需包含 cert.pem（或 fullchain.pem）和 key.pem（或 privkey.pem）</div>
                </div>
                <input type="file" accept=".zip" class="hidden" @change="e => uploadForm.zipFile = e.target.files[0]" />
              </label>
            </div>

            <div class="flex items-start gap-2 text-xs text-slate-500 bg-slate-50 rounded-xl px-3 py-2.5">
              <Info :size="13" class="flex-shrink-0 mt-0.5 text-slate-400" />
              <span>程序将自动从证书中读取域名信息（SAN），无需手动填写。可直接上传从本程序下载的证书 ZIP。</span>
            </div>

            <div v-if="uploadError" class="flex items-start gap-2 text-red-600 bg-red-50 px-3 py-2 rounded-xl border border-red-100 text-xs">
              <AlertCircle :size="13" class="flex-shrink-0 mt-0.5" /> <span>{{ uploadError }}</span>
            </div>
          </div>

          <div class="flex-shrink-0 border-t border-slate-100 px-5 sm:px-6 py-3 sm:py-4">
            <div class="flex gap-2 sm:gap-3 justify-end">
              <button class="btn-primary flex-1 sm:flex-none sm:min-w-[100px] justify-center" @click="upload">
                <Upload :size="14" /> {{ t('upload') }}
              </button>
              <button class="btn-secondary flex-1 sm:flex-none sm:min-w-[80px] justify-center" @click="uploadModal=null">
                {{ t('cancel') }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- ══ 查看 PEM 弹窗 ══════════════════════════════════════════════ -->
    <Teleport to="body">
      <div v-if="pemModal" class="modal-overlay" @click.self="pemModal=null">
        <div class="modal-box sm:max-w-2xl">

          <!-- 移动端拖动条 -->
          <div class="sm:hidden flex justify-center pt-3 pb-1 flex-shrink-0">
            <div class="w-10 h-1 bg-slate-200 rounded-full"></div>
          </div>

          <!-- 标题栏 -->
          <div class="flex-shrink-0 flex items-center justify-between px-5 sm:px-6 py-3 sm:py-4 border-b border-slate-100">
            <div class="min-w-0">
              <h3 class="font-semibold text-slate-900 font-mono text-sm sm:text-base truncate">{{ pemData.domain }}</h3>
              <p class="text-xs text-slate-400 mt-0.5">{{ t('certContent') }}</p>
            </div>
            <button @click="pemModal=null" class="btn-ghost btn-sm p-1.5 ml-2 flex-shrink-0"><X :size="16" /></button>
          </div>

          <!-- 可滚动内容 -->
          <div class="flex-1 overflow-y-auto overscroll-contain px-5 sm:px-6 py-4 space-y-4">
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="input-label mb-0">{{ t('certPemLabel') }}</label>
                <button class="text-xs text-vane-500 hover:text-vane-700 flex items-center gap-1" @click="copy(pemData.cert_pem)">
                  <Copy :size="12" />{{ t('copy') }}
                </button>
              </div>
              <textarea readonly class="input font-mono text-xs h-32 sm:h-40 resize-none bg-slate-50" :value="pemData.cert_pem"></textarea>
            </div>
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="input-label mb-0">{{ t('keyPemLabel') }}</label>
                <button class="text-xs text-vane-500 hover:text-vane-700 flex items-center gap-1" @click="copy(pemData.key_pem)">
                  <Copy :size="12" />{{ t('copy') }}
                </button>
              </div>
              <textarea readonly class="input font-mono text-xs h-32 sm:h-40 resize-none bg-slate-50" :value="pemData.key_pem"></textarea>
            </div>
          </div>

          <!-- 底部下载按钮 -->
          <div class="flex-shrink-0 border-t border-slate-100 px-5 sm:px-6 py-3 sm:py-4">
            <div class="flex gap-2">
              <button class="btn-secondary flex-1 justify-center gap-1.5" @click="downloadFromPEM()">
                <Download :size="13" /> <span class="text-xs sm:text-sm">{{ t('downloadCertBtn') }}</span>
              </button>
              <button class="btn-secondary flex-1 justify-center gap-1.5" @click="downloadKeyFromPEM()">
                <Download :size="13" /> <span class="text-xs sm:text-sm">{{ t('downloadKey') }}</span>
              </button>
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
  Download, Eye, Pencil, AlertCircle, Copy, Info
} from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'
import ProviderBadge from '@/components/ProviderBadge.vue'
import StatusBadge from '@/components/StatusBadge.vue'

const { t } = useI18n()

// ─── 内置 ZeroSSL 账号（Base64 编码存储，轮询使用）────────────────────────
const BUILTIN_ZS_ACCOUNTS = [
  {
    email: '76q7n@dollicons.com',
    _kid:  'SmhMNWdrVmUwLXpQS29INUc2X1o1QQ==',
    _hmac: 'TDI0T3VQSG1lVVMzUnlOOXdwMjhlYUpxVEJyWVQ3QlZCWHZIVTNCdm1OT2g4NU1weDNuejY1c0tzaVkxQ2lrNGpyQVZLTnZGVmRSRms2OXRmVDB0QVE=',
  },
  {
    email: 'jamie@gmail.com',
    _kid:  'UnVtUExSRFMxSWFHNVlySEtVcUctZw==',
    _hmac: 'T3ByN1psVDl0MWcyTXAzbndNam4xZGw5c1VDMi15cDZwR2pmLUUyUHpHWEJKVFhvTHNwX2dQenYzNWVTMHpLNG13Tm5RUENJRFVQSmNGNTYzMmphbHc=',
  },
  {
    email: 'gings@gmail.com',
    _kid:  'MTZubU82eUNiaGttX055NnNwaEp1UQ==',
    _hmac: 'aFBPdjFiZFNEQ05USm1BU1F2elhxSklDY091UHh1QlVFT25wN3pGVm5BektpbUpNZlNiTDlSSEdreVkyUGlnX2J3Z2NzZVNXVTBYVWNzWV9PUW5FYlE=',
  },
]

function decodeAccount(acc) {
  return {
    email: acc.email,
    zerossl_key_id: atob(acc._kid),
    zerossl_api_key: atob(acc._hmac),
  }
}

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
    name: '', domainsText: '', domain: '', email: '',
    ca_provider: 'letsencrypt', provider: 'cloudflare',
    provider_conf: {}, auto_renew: true, source: 'acme',
    usePrivateAccount: false,
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
  const pc = cert.provider_conf || {}
  const builtinEmails = BUILTIN_ZS_ACCOUNTS.map(a => a.email)
  const hasPrivateEab = cert.ca_provider === 'zerossl' &&
    !!(pc.zerossl_key_id || pc.zerossl_api_key) &&
    !builtinEmails.includes(cert.email)
  form.value = {
    name:              cert.name || '',
    domainsText:       domains.join('\n'),
    domain:            cert.domain || '',
    email:             cert.email || '',
    ca_provider:       cert.ca_provider || 'letsencrypt',
    provider:          cert.provider || 'cloudflare',
    provider_conf:     { ...pc },
    auto_renew:        cert.auto_renew,
    source:            cert.source,
    usePrivateAccount: hasPrivateEab,
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
  const domains = (form.value.domainsText || '').split('\n').map(s => s.trim()).filter(Boolean)
  if (!domains.length) return t('errNoDomain')
  if (form.value.ca_provider === 'zerossl') {
    if (form.value.usePrivateAccount) {
      if (!form.value.email) return t('errNoEmail')
      if (!form.value.provider_conf.zerossl_key_id) return t('errNoEabKeyId')
      if (!form.value.provider_conf.zerossl_api_key) return t('errNoZsHmac')
    }
  } else {
    if (!form.value.email) return t('errNoEmail')
  }
  if (form.value.provider === 'cloudflare' && !form.value.provider_conf.api_token) {
    return t('errNoCfToken')
  }
  return null
}

function buildPayload(builtinIdx = 0) {
  const domains = (form.value.domainsText || '').split('\n').map(s => s.trim()).filter(Boolean)
  const base = { ...form.value, domains, domain: domains[0] || '', domainsText: undefined, usePrivateAccount: undefined }
  if (form.value.ca_provider === 'zerossl' && !form.value.usePrivateAccount) {
    const acc = decodeAccount(BUILTIN_ZS_ACCOUNTS[builtinIdx % BUILTIN_ZS_ACCOUNTS.length])
    base.email = acc.email
    base.provider_conf = { ...base.provider_conf, zerossl_key_id: acc.zerossl_key_id, zerossl_api_key: acc.zerossl_api_key }
  }
  return base
}

async function tryWithBuiltin(action) {
  let lastErr = null
  for (let i = 0; i < BUILTIN_ZS_ACCOUNTS.length; i++) {
    try { return await action(i) } catch (e) { lastErr = e }
  }
  throw lastErr
}

async function createAndIssue() {
  modalError.value = validateForm() || ''
  if (modalError.value) return
  saving.value = true
  try {
    let certId
    if (form.value.ca_provider === 'zerossl' && !form.value.usePrivateAccount) {
      await tryWithBuiltin(async (idx) => { const { data } = await api.post('/tls', buildPayload(idx)); certId = data.id })
    } else {
      const { data } = await api.post('/tls', buildPayload()); certId = data.id
    }
    modal.value = null
    await load()
    api.post(`/tls/${certId}/issue`).catch(() => {})
    pollUntilDone(certId)
  } catch (e) {
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
    if (form.value.ca_provider === 'zerossl' && !form.value.usePrivateAccount) {
      await tryWithBuiltin(async (idx) => { await api.put(`/tls/${id}`, buildPayload(idx)) })
    } else {
      await api.put(`/tls/${id}`, buildPayload())
    }
    modal.value = null
    await load()
    api.post(`/tls/${id}/issue`).catch(() => {})
    pollUntilDone(id)
  } catch (e) {
    modalError.value = e.response?.data?.error || e.message
  } finally {
    saving.value = false
  }
}

function pollUntilDone(id) {
  const start = Date.now()
  const poll = setInterval(async () => {
    await load()
    const c = certs.value.find(x => x.id === id)
    if (!c || c.status !== 'pending' || Date.now() - start > 900000) clearInterval(poll)
  }, 5000)
}

async function issue(id) {
  const cert = certs.value.find(c => c.id === id)
  if (cert) cert.status = 'pending'
  // If this is a ZeroSSL cert using a builtin account, refresh EAB before issuing
  if (cert && cert.ca_provider === 'zerossl' && isBuiltinAccount(cert)) {
    try {
      await tryWithBuiltin(async (idx) => {
        const acc = decodeAccount(BUILTIN_ZS_ACCOUNTS[idx % BUILTIN_ZS_ACCOUNTS.length])
        await api.put(`/tls/${id}`, {
          ...cert,
          email: acc.email,
          provider_conf: { ...cert.provider_conf, zerossl_key_id: acc.zerossl_key_id, zerossl_api_key: acc.zerossl_api_key }
        })
      })
    } catch (e) { /* proceed anyway */ }
  }
  api.post(`/tls/${id}/issue`).catch(() => {})
  pollUntilDone(id)
}

async function upload() {
  uploadError.value = ''
  if (!uploadForm.value.zipFile) { uploadError.value = '请选择 ZIP 文件'; return }
  try {
    const fd = new FormData()
    fd.append('file', uploadForm.value.zipFile)
    await api.post('/tls/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
    uploadModal.value = null
    uploadForm.value = {}
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

// ─── 下载证书 ZIP ──────────────────────────────────────────────────────────
async function downloadCert(cert) {
  const res = await api.get(`/tls/${cert.id}/download`, { responseType: 'blob' })
  const safeName = (cert.domain || 'cert').replace(/\*/g, 'wildcard').replace(/[^a-zA-Z0-9._-]/g, '_')
  triggerDownload(`${safeName}-certs.zip`, res.data, true)
}

async function viewPEM(cert) {
  const { data } = await api.get(`/tls/${cert.id}/pem`)
  pemData.value = data
  pemModal.value = true
}

function downloadFromPEM() { triggerDownload(pemData.value.domain + '-cert.pem', pemData.value.cert_pem) }
function downloadKeyFromPEM() { triggerDownload(pemData.value.domain + '-key.pem', pemData.value.key_pem) }

function triggerDownload(filename, content, isBlob = false) {
  const blob = isBlob ? content : new Blob([content], { type: 'application/x-pem-file' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

function copy(text) { navigator.clipboard.writeText(text).catch(() => {}) }

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
