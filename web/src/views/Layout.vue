<template>
  <div class="flex h-screen overflow-hidden">

    <!-- ══ 移动端遮罩层（点击关闭抽屉）══════════════════════════════ -->
    <Transition name="fade-overlay">
      <div v-if="drawerOpen"
           class="fixed inset-0 z-40 bg-black/50 sm:hidden"
           @click="drawerOpen = false" />
    </Transition>

    <!-- ══ Sidebar（桌面端固定 / 移动端抽屉）═══════════════════════ -->
    <aside
      class="fixed sm:static inset-y-0 left-0 z-50 w-72 sm:w-64 flex-shrink-0 flex flex-col h-full
             transform transition-transform duration-300 ease-in-out bg-white border-r border-slate-100
             sm:translate-x-0"
      :class="drawerOpen ? 'translate-x-0' : '-translate-x-full'">

      <!-- Logo + 移动端关闭按钮 -->
      <div class="px-5 pt-6 pb-4 flex items-center gap-3 border-b border-slate-100">
        <div class="w-10 h-10 rounded-2xl bg-vane-600 flex items-center justify-center shadow flex-shrink-0">
          <svg class="w-5 h-5 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z"/>
            <path d="M9.879 16.121A3 3 0 1012.015 11L11 14H9c0 .768.293 1.536.879 2.121z"/>
          </svg>
        </div>
        <div class="flex-1">
          <div class="text-slate-900 font-bold text-lg leading-none">Vane</div>
          <div class="text-slate-400 text-xs mt-0.5">Network Manager</div>
        </div>
        <!-- 移动端关闭按钮 -->
        <button @click="drawerOpen = false"
                class="sm:hidden text-slate-400 hover:text-slate-700 p-1.5 rounded-lg hover:bg-slate-100 transition-colors">
          <X :size="18" />
        </button>
      </div>

      <!-- Nav -->
      <nav class="flex-1 px-3 py-3 space-y-0.5 overflow-y-auto">
        <div class="px-3 pb-1 pt-2">
          <span class="text-slate-400 text-xs font-bold uppercase tracking-widest">{{ i18n.t('main') }}</span>
        </div>
        <router-link
          v-for="item in navItems" :key="item.to" :to="item.to"
          class="nav-item group"
          :class="isActive(item.to) ? 'active text-white' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'"
          :style="isActive(item.to) ? `background: ${item.gradient}; box-shadow: ${item.shadow}` : ''"
          @click="drawerOpen = false">
          <div class="w-8 h-8 rounded-xl flex items-center justify-center transition-all"
               :class="isActive(item.to) ? 'bg-white/20' : 'bg-slate-100 group-hover:bg-slate-200'">
            <component :is="item.icon" :size="16" />
          </div>
          <span class="flex-1 font-semibold">{{ item.label }}</span>
        </router-link>

        <div class="px-3 pb-1 pt-4">
          <span class="text-slate-400 text-xs font-bold uppercase tracking-widest">{{ i18n.t('system') }}</span>
        </div>
        <router-link to="/settings"
          class="nav-item"
          :class="isActive('/settings') ? 'active text-white' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'"
          :style="isActive('/settings') ? 'background:linear-gradient(135deg,#475569,#1e293b);box-shadow:0 4px 15px rgba(71,85,105,0.4)' : ''"
          @click="drawerOpen = false">
          <div class="w-8 h-8 rounded-xl flex items-center justify-center"
               :class="isActive('/settings') ? 'bg-white/20' : 'bg-slate-100'">
            <Settings :size="16" />
          </div>
          
          <span class="font-semibold">{{ i18n.t('settings') }}</span>
        </router-link>
      </nav>

      <!-- User footer -->
      <div class="p-4 border-t border-slate-100">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-gradient-to-br from-vane-500 to-pink-400 flex items-center justify-center text-white font-bold text-sm shadow flex-shrink-0">
            {{ username.charAt(0).toUpperCase() }}
          </div>
          <div class="flex-1 min-w-0">
            <div class="text-slate-800 text-sm font-medium truncate">{{ username }}</div>
            <div class="text-slate-400 text-xs">{{ i18n.t('administrator') }}</div>
          </div>
          <button @click="auth.logout()" class="text-slate-400 hover:text-slate-700 transition-colors p-1.5 rounded-lg hover:bg-slate-100" title="退出登录">
            <LogOut :size="15" />
          </button>
        </div>
      </div>
    </aside>

    <!-- ══ Main content ══════════════════════════════════════════════ -->
    <main class="flex-1 overflow-y-auto min-w-0">
      <!-- Topbar -->
      <header class="sticky top-0 z-30 bg-white/80 backdrop-blur-sm border-b border-slate-100
                     px-4 sm:px-8 py-3 sm:py-4 flex items-center justify-between sm:justify-end gap-3">

        <!-- 移动端汉堡菜单按钮 -->
        <button @click="drawerOpen = true"
                class="sm:hidden flex items-center justify-center w-9 h-9 rounded-xl
                       text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors">
          <Menu :size="20" />
        </button>

        <!-- 右侧状态栏 -->
        <div class="flex items-center gap-2 sm:gap-3">
          <!-- 访问日志按钮：仅仪表盘页显示 -->
          <button v-if="route.path === '/dashboard'"
                  @click="openLogs"
                  class="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-700 bg-slate-50 hover:bg-slate-100
                         px-2.5 py-1.5 rounded-full border border-slate-200 transition-all"
                  title="访问日志">
            <ScrollText :size="13" />
            <span class="hidden sm:inline">访问日志</span>
          </button>
          <button @click="i18n.toggle()"
                  class="text-xs text-slate-500 hover:text-slate-700 bg-slate-50 hover:bg-slate-100
                         px-2.5 sm:px-3 py-1.5 rounded-full border border-slate-200 transition-all">
            {{ i18n.t('switchLang') }}
          </button>
          <div class="flex items-center gap-1.5 text-xs text-emerald-600 bg-emerald-50 px-2.5 sm:px-3 py-1.5 rounded-full border border-emerald-200">
            <span class="status-dot active"></span>
            <span class="hidden xs:inline">{{ i18n.t('running') }}</span>
          </div>
          <div class="hidden sm:block text-xs text-slate-400 font-mono bg-slate-50 px-3 py-1.5 rounded-full border border-slate-100">
            {{ new Date().toLocaleTimeString(i18n.locale === 'zh' ? 'zh-CN' : 'en-US') }}
          </div>
        </div>
      </header>

      <div class="p-4 sm:p-8">
        <router-view />
      </div>
    </main>
  </div>

  <!-- ══ 访问日志面板 ══════════════════════════════════════════════ -->
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="logsOpen"
           class="fixed inset-0 z-50 flex items-center justify-center p-4"
           style="background:rgba(0,0,0,0.35);backdrop-filter:blur(4px)"
           @click.self="logsOpen=false">
        <div class="bg-white rounded-2xl shadow-2xl w-full max-w-4xl flex flex-col"
             style="max-height:80vh">
          <!-- 标题栏 -->
          <div class="flex items-center justify-between px-5 py-4 border-b border-slate-100 flex-shrink-0">
            <div class="flex items-center gap-2">
              <ScrollText :size="16" class="text-vane-500" />
              <span class="font-semibold text-slate-800">访问日志</span>
              <span class="text-xs text-slate-400 ml-1">{{ filteredLogs.length }} 条</span>
            </div>
            <div class="flex items-center gap-2">
              <button @click="loadLogs" class="btn-ghost btn-sm p-1.5 text-slate-400 hover:text-slate-600" title="刷新">
                <RefreshCw :size="14" />
              </button>
              <button @click="logsOpen=false" class="btn-ghost btn-sm p-1.5 text-slate-400 hover:text-slate-600">
                <X :size="16" />
              </button>
            </div>
          </div>
          <!-- 搜索 -->
          <div class="px-5 py-2.5 border-b border-slate-50 flex-shrink-0">
            <input v-model="logSearch" class="input text-xs py-1.5 max-w-xs" placeholder="搜索 IP / 域名 / UA…" />
          </div>
          <!-- 表格 -->
          <div class="flex-1 overflow-auto">
            <table class="w-full text-xs min-w-[500px]">
              <thead class="bg-slate-50 sticky top-0">
                <tr>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500 whitespace-nowrap">时间</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">路由</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">域名</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">来源 IP</th>
                  <th class="text-left px-4 py-2.5 font-semibold text-slate-500">UA</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="log in filteredLogs" :key="log.id"
                    class="border-t border-slate-50 hover:bg-slate-50 transition-colors">
                  <td class="px-4 py-2 font-mono text-slate-400 whitespace-nowrap">{{ formatTime(log.time) }}</td>
                  <td class="px-4 py-2 text-slate-600">{{ log.route_name || '—' }}</td>
                  <td class="px-4 py-2 font-mono font-semibold text-slate-700">{{ log.domain }}</td>
                  <td class="px-4 py-2 font-mono text-slate-600">{{ log.client_ip }}</td>
                  <td class="px-4 py-2 text-slate-400 max-w-[160px] truncate" :title="log.user_agent">{{ parseUA(log.user_agent) }}</td>
                </tr>
                <tr v-if="filteredLogs.length === 0">
                  <td colspan="5" class="text-center py-12 text-slate-300 text-sm">暂无访问记录</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'
import { api } from '@/stores/auth'
import {
  LayoutDashboard, ArrowLeftRight, Globe, Server, Shield, Settings, LogOut, Menu, X, ScrollText, RefreshCw
} from 'lucide-vue-next'

const auth = useAuthStore()
const i18n = useI18n()
const route = useRoute()
const username = computed(() => 'admin')

// 移动端抽屉开关
const drawerOpen = ref(false)

// 路由切换时自动关闭抽屉
watch(() => route.path, () => { drawerOpen.value = false })

// ── 访问日志面板 ──────────────────────────────────────────────────
const logsOpen = ref(false)
const logs = ref([])
const logSearch = ref('')

const filteredLogs = computed(() => {
  if (!logSearch.value) return logs.value
  const q = logSearch.value.toLowerCase()
  return logs.value.filter(l =>
    l.client_ip?.includes(q) || l.domain?.includes(q) ||
    l.user_agent?.toLowerCase().includes(q)
  )
})

async function loadLogs() {
  try {
    const { data } = await api.get('/webservice/logs')
    logs.value = data
  } catch {}
}

function openLogs() {
  logsOpen.value = true
  loadLogs()
}

function formatTime(ts) {
  if (!ts) return ''
  return new Date(ts).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function parseUA(ua) {
  if (!ua) return '—'
  if (ua.includes('iPhone') || ua.includes('iPad')) return '📱 iOS'
  if (ua.includes('Android')) return '📱 Android'
  if (ua.includes('Chrome')) return '🌐 Chrome'
  if (ua.includes('Firefox')) return '🦊 Firefox'
  if (ua.includes('Safari')) return '🧭 Safari'
  if (ua.includes('curl')) return '⌨️ curl'
  return ua.slice(0, 30)
}

const navItems = computed(() => [
  { to: '/dashboard',   label: i18n.t('dashboard'),   icon: LayoutDashboard,
    gradient: 'linear-gradient(135deg,#6366f1,#8b5cf6)', shadow: '0 4px 15px rgba(99,102,241,0.4)' },
  { to: '/portforward', label: i18n.t('portforward'),  icon: ArrowLeftRight,
    gradient: 'linear-gradient(135deg,#3b82f6,#06b6d4)', shadow: '0 4px 15px rgba(59,130,246,0.4)' },
  { to: '/ddns',        label: i18n.t('ddns'),          icon: Globe,
    gradient: 'linear-gradient(135deg,#10b981,#059669)', shadow: '0 4px 15px rgba(16,185,129,0.4)' },
  { to: '/webservice',  label: i18n.t('webservice'),   icon: Server,
    gradient: 'linear-gradient(135deg,#8b5cf6,#ec4899)', shadow: '0 4px 15px rgba(139,92,246,0.4)' },
  { to: '/tls',         label: i18n.t('tls'),           icon: Shield,
    gradient: 'linear-gradient(135deg,#f59e0b,#ef4444)', shadow: '0 4px 15px rgba(245,158,11,0.4)' },
])

function isActive(to) {
  return route.path === to || route.path.startsWith(to + '/')
}
</script>

<style scoped>
.fade-overlay-enter-active,
.fade-overlay-leave-active {
  transition: opacity 0.25s ease;
}
.fade-overlay-enter-from,
.fade-overlay-leave-to {
  opacity: 0;
}
.modal-enter-active, .modal-leave-active { transition: opacity 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
</style>
