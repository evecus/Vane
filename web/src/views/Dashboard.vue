<template>
  <div class="space-y-4 sm:space-y-5 animate-fade-in">

    <!-- ══ First-login welcome modal ════════════════════════════════════ -->
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

    <!-- ══ 第一行：端口转发 + 动态域名 ══════════════════════════════ -->
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">

      <!-- 端口转发 -->
      <div class="glass-card p-3 sm:p-5 flex flex-col min-h-[160px] sm:min-h-[220px]">
        <!-- 移动端头部 -->
        <div class="flex flex-col gap-0.5 mb-2 sm:hidden">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5">
              <div class="w-7 h-7 rounded-lg flex items-center justify-center text-white shadow flex-shrink-0"
                   style="background: linear-gradient(135deg,#3b82f6,#06b6d4)">
                <ArrowLeftRight :size="13" />
              </div>
              <span class="font-semibold text-slate-800 text-xs">端口转发</span>
            </div>
            <div class="text-2xl font-bold text-slate-900 tabular-nums leading-none">{{ pfRules.length }}</div>
          </div>
          <div class="text-xs text-slate-400 pl-9">{{ pfRules.filter(r=>r.enabled).length }}/{{ pfRules.length }} 条启用</div>
        </div>
        <!-- 桌面端头部 -->
        <div class="hidden sm:flex items-start justify-between mb-3">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-9 h-9 rounded-xl flex items-center justify-center text-white shadow flex-shrink-0"
                 style="background: linear-gradient(135deg,#3b82f6,#06b6d4)">
              <ArrowLeftRight :size="16" />
            </div>
            <div class="min-w-0">
              <div class="font-semibold text-slate-800 text-sm leading-tight">端口转发</div>
              <div class="text-xs text-slate-400 mt-0.5 truncate">{{ pfRules.filter(r=>r.enabled).length }}/{{ pfRules.length }} 条启用</div>
            </div>
          </div>
          <div class="text-3xl font-bold text-slate-900 tabular-nums leading-none flex-shrink-0 ml-1">{{ pfRules.length }}</div>
        </div>
        <div v-if="pfRules.length === 0" class="flex-1 flex items-center justify-center text-slate-300 text-xs">暂无规则</div>
        <div v-else class="flex-1 space-y-0.5 sm:space-y-1 overflow-hidden">
          <div v-for="r in pfRules.slice(0,4)" :key="r.id"
               class="flex items-center gap-1.5 py-1 sm:py-1.5 border-b border-slate-50 last:border-0">
            <span class="status-dot flex-shrink-0" :class="r.enabled ? 'active' : 'inactive'"></span>
            <span class="text-slate-700 font-medium text-xs truncate flex-1">{{ r.name }}</span>
            <span class="text-slate-400 font-mono text-xs flex-shrink-0 hidden sm:inline">:{{ r.listen_port }}</span>
          </div>
          <div v-if="pfRules.length > 4" class="text-xs text-slate-400 text-center pt-0.5">+{{ pfRules.length - 4 }} 条</div>
        </div>
      </div>

      <!-- 动态域名 -->
      <div class="glass-card p-3 sm:p-5 flex flex-col min-h-[160px] sm:min-h-[220px]">
        <div class="flex flex-col gap-0.5 mb-2 sm:hidden">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5">
              <div class="w-7 h-7 rounded-lg flex items-center justify-center text-white shadow flex-shrink-0"
                   style="background: linear-gradient(135deg,#10b981,#059669)">
                <Globe :size="13" />
              </div>
              <span class="font-semibold text-slate-800 text-xs">动态域名</span>
            </div>
            <div class="text-2xl font-bold text-slate-900 tabular-nums leading-none">{{ ddnsRules.length }}</div>
          </div>
          <div class="text-xs text-slate-400 pl-9">{{ ddnsRules.filter(r=>r.enabled).length }}/{{ ddnsRules.length }} 条启用</div>
        </div>
        <div class="hidden sm:flex items-start justify-between mb-3">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-9 h-9 rounded-xl flex items-center justify-center text-white shadow flex-shrink-0"
                 style="background: linear-gradient(135deg,#10b981,#059669)">
              <Globe :size="16" />
            </div>
            <div class="min-w-0">
              <div class="font-semibold text-slate-800 text-sm leading-tight">动态域名</div>
              <div class="text-xs text-slate-400 mt-0.5 truncate">{{ ddnsRules.filter(r=>r.enabled).length }}/{{ ddnsRules.length }} 条启用</div>
            </div>
          </div>
          <div class="text-3xl font-bold text-slate-900 tabular-nums leading-none flex-shrink-0 ml-1">{{ ddnsRules.length }}</div>
        </div>
        <div v-if="ddnsRules.length === 0" class="flex-1 flex items-center justify-center text-slate-300 text-xs">暂无规则</div>
        <div v-else class="flex-1 space-y-0.5 sm:space-y-1 overflow-hidden">
          <div v-for="r in ddnsRules.slice(0,4)" :key="r.id"
               class="flex items-center gap-1.5 py-1 sm:py-1.5 border-b border-slate-50 last:border-0">
            <span class="status-dot flex-shrink-0" :class="r.enabled ? 'active' : 'inactive'"></span>
            <span class="text-slate-700 font-medium text-xs truncate flex-1 font-mono">{{ domainLabel(r) }}</span>
          </div>
          <div v-if="ddnsRules.length > 4" class="text-xs text-slate-400 text-center pt-0.5">+{{ ddnsRules.length - 4 }} 条</div>
        </div>
      </div>

    </div>

    <!-- ══ 第二行：网页服务 + 证书 ══════════════════════════════════ -->
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">

      <!-- 网页服务 -->
      <div class="glass-card p-3 sm:p-5 flex flex-col min-h-[160px] sm:min-h-[220px]">
        <div class="flex flex-col gap-0.5 mb-2 sm:hidden">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5">
              <div class="w-7 h-7 rounded-lg flex items-center justify-center text-white shadow flex-shrink-0"
                   style="background: linear-gradient(135deg,#8b5cf6,#ec4899)">
                <Server :size="13" />
              </div>
              <span class="font-semibold text-slate-800 text-xs">网页服务</span>
            </div>
            <div class="text-2xl font-bold text-slate-900 tabular-nums leading-none">{{ wsRules.length }}</div>
          </div>
          <div class="text-xs text-slate-400 pl-9">{{ wsRules.filter(r=>r.enabled).length }}/{{ wsRules.length }} 个运行中</div>
        </div>
        <div class="hidden sm:flex items-start justify-between mb-3">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-9 h-9 rounded-xl flex items-center justify-center text-white shadow flex-shrink-0"
                 style="background: linear-gradient(135deg,#8b5cf6,#ec4899)">
              <Server :size="16" />
            </div>
            <div class="min-w-0">
              <div class="font-semibold text-slate-800 text-sm leading-tight">网页服务</div>
              <div class="text-xs text-slate-400 mt-0.5 truncate">{{ wsRules.filter(r=>r.enabled).length }}/{{ wsRules.length }} 个运行中</div>
            </div>
          </div>
          <div class="text-3xl font-bold text-slate-900 tabular-nums leading-none flex-shrink-0 ml-1">{{ wsRules.length }}</div>
        </div>
        <div v-if="wsRules.length === 0" class="flex-1 flex items-center justify-center text-slate-300">
          <div class="text-center">
            <Server :size="24" class="mx-auto mb-1 opacity-40" />
            <span class="text-xs">暂无网页服务</span>
          </div>
        </div>
        <div v-else class="flex-1 space-y-0.5 sm:space-y-1 overflow-hidden">
          <div v-for="svc in wsRules.slice(0,4)" :key="svc.id"
               class="flex items-center gap-1.5 py-1 sm:py-1.5 border-b border-slate-50 last:border-0">
            <span class="status-dot flex-shrink-0" :class="svc.enabled ? 'active' : 'inactive'"></span>
            <span class="font-medium text-slate-700 text-xs flex-1 truncate">{{ svc.name }}</span>
            <span class="font-mono text-xs text-slate-400 flex-shrink-0 hidden sm:inline">:{{ svc.listen_port }}</span>
          </div>
          <div v-if="wsRules.length > 4" class="text-xs text-slate-400 text-center pt-0.5">+{{ wsRules.length - 4 }} 条</div>
        </div>
      </div>

      <!-- 证书 -->
      <div class="glass-card p-3 sm:p-5 flex flex-col min-h-[160px] sm:min-h-[220px]">
        <div class="flex flex-col gap-0.5 mb-2 sm:hidden">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5">
              <div class="w-7 h-7 rounded-lg flex items-center justify-center text-white shadow flex-shrink-0"
                   :style="dashboard.certs_expiring_soon > 0 ? 'background:linear-gradient(135deg,#ef4444,#f97316)' : 'background:linear-gradient(135deg,#f59e0b,#eab308)'">
                <Shield :size="13" />
              </div>
              <span class="font-semibold text-slate-800 text-xs">证书</span>
            </div>
            <div class="text-2xl font-bold text-slate-900 tabular-nums leading-none">{{ certs.length }}</div>
          </div>
          <div class="text-xs pl-9" :class="dashboard.certs_expiring_soon > 0 ? 'text-red-400' : 'text-slate-400'">
            {{ dashboard.certs_expiring_soon > 0 ? `${dashboard.certs_expiring_soon} 张即将到期` : '全部正常' }}
          </div>
        </div>
        <div class="hidden sm:flex items-start justify-between mb-3">
          <div class="flex items-center gap-2 min-w-0">
            <div class="w-9 h-9 rounded-xl flex items-center justify-center text-white shadow flex-shrink-0"
                 :style="dashboard.certs_expiring_soon > 0 ? 'background:linear-gradient(135deg,#ef4444,#f97316)' : 'background:linear-gradient(135deg,#f59e0b,#eab308)'">
              <Shield :size="16" />
            </div>
            <div class="min-w-0">
              <div class="font-semibold text-slate-800 text-sm leading-tight">证书</div>
              <div class="text-xs mt-0.5 truncate" :class="dashboard.certs_expiring_soon > 0 ? 'text-red-400' : 'text-slate-400'">
                {{ dashboard.certs_expiring_soon > 0 ? `${dashboard.certs_expiring_soon} 张即将到期` : '全部正常' }}
              </div>
            </div>
          </div>
          <div class="text-3xl font-bold text-slate-900 tabular-nums leading-none flex-shrink-0 ml-1">{{ certs.length }}</div>
        </div>
        <div v-if="certs.length === 0" class="flex-1 flex items-center justify-center text-slate-300">
          <div class="text-center">
            <Shield :size="24" class="mx-auto mb-1 opacity-40" />
            <span class="text-xs">暂无证书</span>
          </div>
        </div>
        <div v-else class="flex-1 space-y-1.5 sm:space-y-2 overflow-hidden">
          <div v-for="cert in certs.slice(0,3)" :key="cert.id">
            <div class="flex items-center justify-between mb-0.5 sm:mb-1">
              <span class="font-mono text-xs text-slate-600 truncate flex-1 mr-1">{{ cert.domain }}</span>
              <span :class="cert.days_left < 14 ? 'text-red-500' : cert.days_left < 30 ? 'text-amber-500' : 'text-emerald-600'"
                    class="font-bold text-xs flex-shrink-0">
                {{ cert.days_left >= 0 ? cert.days_left + '天' : '?' }}
              </span>
            </div>
            <div class="h-1.5 bg-slate-100 rounded-full overflow-hidden">
              <div class="h-full rounded-full transition-all duration-700" :style="certBarStyle(cert.days_left)"></div>
            </div>
          </div>
          <div v-if="certs.length > 3" class="text-xs text-slate-400 text-center pt-0.5">+{{ certs.length - 3 }} 张</div>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Shield, Server, ShieldAlert, ArrowLeftRight, Globe } from 'lucide-vue-next'
import { useRouter } from 'vue-router'
import { api } from '@/stores/auth'

const router = useRouter()
const dashboard = ref({})
const certs = ref([])
const ddnsRules = ref([])
const pfRules = ref([])
const wsRules = ref([])

// ── First-login modal ──────────────────────────────────────────────────────
const showWelcomeModal = ref(false)
async function dismissModal() {
  showWelcomeModal.value = false
  try { await api.post('/settings/welcome-shown') } catch {}
}
async function goToSettings() {
  showWelcomeModal.value = false
  try { await api.post('/settings/welcome-shown') } catch {}
  router.push('/settings')
}

function certBarStyle(days) {
  const pct = Math.min(100, Math.max(0, (days / 90) * 100))
  const color = days < 14 ? '#ef4444' : days < 30 ? '#f59e0b' : '#10b981'
  return `width: ${pct}%; background: ${color}`
}
function domainLabel(r) {
  return (r.sub_domain ? r.sub_domain + '.' : '') + (r.domain || '')
}

async function load() {
  try {
    const [db, certsRes, ddnsRes, pfRes, wsRes, settingsRes] = await Promise.all([
      api.get('/dashboard'), api.get('/tls'), api.get('/ddns'),
      api.get('/portforward'), api.get('/webservice'), api.get('/settings'),
    ])
    dashboard.value = db.data
    certs.value = certsRes.data
    ddnsRules.value = ddnsRes.data
    pfRules.value = pfRes.data
    wsRules.value = wsRes.data
    if (!settingsRes.data.welcome_shown) {
      showWelcomeModal.value = true
    }
  } catch {}
}

onMounted(load)
</script>

<style scoped>
.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
</style>
