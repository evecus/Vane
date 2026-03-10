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
             transform transition-transform duration-300 ease-in-out
             sm:translate-x-0"
      :class="drawerOpen ? 'translate-x-0' : '-translate-x-full'"
      style="background: linear-gradient(180deg, #1e1b4b 0%, #312e81 40%, #4c1d95 100%)">

      <!-- 装饰光晕 -->
      <div class="absolute inset-0 overflow-hidden pointer-events-none">
        <div class="absolute w-32 h-32 rounded-full opacity-10 blur-2xl bg-purple-400 -top-8 -right-8"></div>
        <div class="absolute w-24 h-24 rounded-full opacity-10 blur-2xl bg-blue-400 bottom-20 -left-4"></div>
      </div>

      <!-- Logo + 移动端关闭按钮 -->
      <div class="relative z-10 px-5 pt-6 pb-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-2xl bg-white/15 border border-white/20 flex items-center justify-center shadow-lg flex-shrink-0">
          <svg class="w-5 h-5 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z"/>
            <path d="M9.879 16.121A3 3 0 1012.015 11L11 14H9c0 .768.293 1.536.879 2.121z"/>
          </svg>
        </div>
        <div class="flex-1">
          <div class="text-white font-bold text-lg leading-none">Vane</div>
          <div class="text-white/50 text-xs mt-0.5">Network Manager</div>
        </div>
        <!-- 移动端关闭按钮 -->
        <button @click="drawerOpen = false"
                class="sm:hidden text-white/50 hover:text-white p-1.5 rounded-lg hover:bg-white/10 transition-colors">
          <X :size="18" />
        </button>
      </div>

      <!-- Nav -->
      <nav class="relative z-10 flex-1 px-3 py-2 space-y-1 overflow-y-auto">
        <div class="px-3 py-2">
          <span class="text-white/30 text-xs font-bold uppercase tracking-widest">{{ i18n.t('main') }}</span>
        </div>
        <router-link
          v-for="item in navItems" :key="item.to" :to="item.to"
          class="nav-item group"
          :class="isActive(item.to) ? 'active text-white' : 'text-white/60 hover:text-white'"
          :style="isActive(item.to) ? `background: ${item.gradient}; box-shadow: ${item.shadow}` : ''"
          @click="drawerOpen = false">
          <div class="w-8 h-8 rounded-xl flex items-center justify-center transition-all"
               :class="isActive(item.to) ? 'bg-white/20' : 'bg-white/5 group-hover:bg-white/10'">
            <component :is="item.icon" :size="16" />
          </div>
          <span class="flex-1">{{ item.label }}</span>
        </router-link>

        <div class="px-3 py-2 mt-4">
          <span class="text-white/30 text-xs font-bold uppercase tracking-widest">{{ i18n.t('system') }}</span>
        </div>
        <router-link to="/settings"
          class="nav-item text-white/60 hover:text-white"
          :class="isActive('/settings') ? 'active text-white bg-white/10' : ''"
          @click="drawerOpen = false">
          <div class="w-8 h-8 rounded-xl flex items-center justify-center bg-white/5">
            <Settings :size="16" />
          </div>
          {{ i18n.t('settings') }}
        </router-link>
      </nav>

      <!-- User footer -->
      <div class="relative z-10 p-4 border-t border-white/10">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-gradient-to-br from-purple-400 to-pink-400 flex items-center justify-center text-white font-bold text-sm shadow flex-shrink-0">
            {{ username.charAt(0).toUpperCase() }}
          </div>
          <div class="flex-1 min-w-0">
            <div class="text-white text-sm font-medium truncate">{{ username }}</div>
            <div class="text-white/40 text-xs">{{ i18n.t('administrator') }}</div>
          </div>
          <button @click="auth.logout()" class="text-white/40 hover:text-white/70 transition-colors p-1.5 rounded-lg hover:bg-white/10" title="退出登录">
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
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'
import {
  LayoutDashboard, ArrowLeftRight, Globe, Server, Shield, Settings, LogOut, Menu, X
} from 'lucide-vue-next'

const auth = useAuthStore()
const i18n = useI18n()
const route = useRoute()
const username = computed(() => 'admin')

// 移动端抽屉开关
const drawerOpen = ref(false)

// 路由切换时自动关闭抽屉
watch(() => route.path, () => { drawerOpen.value = false })

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
</style>
