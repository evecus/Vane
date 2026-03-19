<template>
  <div class="space-y-4 sm:space-y-6 animate-fade-in">

    <!-- 页面标题 -->
    <div class="page-header">
      <h1 class="page-title">{{ t('wsTitle') }}</h1>
      <div class="flex gap-2">
        <button class="btn-secondary btn-sm sm:btn-normal" @click="logsModal=true">
          <ScrollText :size="14" /> <span class="hidden sm:inline">{{ t('accessLogs') }}</span>
        </button>
        <button class="btn-primary btn-sm sm:btn-normal" @click="openServiceModal()">
          <Plus :size="15" /> {{ t('addService') }}
        </button>
      </div>
    </div>

    <!-- 空状态 -->
    <div v-if="services.length === 0" class="glass-card p-10 sm:p-16 text-center">
      <div class="w-14 h-14 sm:w-16 sm:h-16 rounded-3xl bg-purple-50 flex items-center justify-center mx-auto mb-4">
        <Server :size="26" class="text-purple-400" />
      </div>
      <p class="text-slate-500 font-medium">{{ t('noServices') }}</p>
      <p class="text-slate-400 text-sm mt-1">{{ t('noServicesHint') }}</p>
    </div>

    <!-- 服务卡片列表 -->
    <div v-for="svc in services" :key="svc.id" class="glass-card overflow-hidden group">

      <!-- 服务头部 -->
      <div class="flex items-center gap-3 sm:gap-4 p-4 sm:p-5 border-b border-slate-100">
        <div class="w-10 h-10 sm:w-12 sm:h-12 rounded-xl sm:rounded-2xl flex items-center justify-center flex-shrink-0 text-white font-bold text-xs sm:text-sm"
             :style="svc.enabled ? 'background:linear-gradient(135deg,#8b5cf6,#ec4899)' : 'background:#e2e8f0;color:#94a3b8'">
          :{{ svc.listen_port }}
        </div>
        <div class="flex-1 min-w-0">
          <!-- 第一行：名称 + 状态点 -->
          <div class="flex items-center gap-1.5">
            <span class="font-semibold text-slate-900 text-sm sm:text-base truncate">{{ svc.name || t('unnamedService') }}</span>
            <span class="status-dot flex-shrink-0" :class="svc.enabled ? 'active' : 'inactive'"></span>
          </div>
          <!-- 第二行：badges -->
          <div class="flex items-center gap-1 mt-1 flex-wrap">
            <span v-if="svc.enable_https" class="badge badge-green text-xs">HTTPS</span>
            <span v-else class="badge badge-slate text-xs">HTTP</span>
            <span class="badge badge-purple text-xs">{{ t('port', {port: svc.listen_port}) }}</span>
            <span v-if="svc.enable_https" class="badge badge-slate text-xs">HTTP→HTTPS</span>
          </div>
          <!-- 第三行：子规则数量 -->
          <div class="text-xs text-slate-400 mt-0.5">
            {{ t('routeCount', {n: (svc.routes||[]).length}) }}
          </div>
        </div>
        <div class="flex items-center gap-1 sm:gap-2 flex-shrink-0">
          <button @click="openLogsFor(svc.id)" class="btn-ghost btn-sm p-1.5 text-slate-500" :title="t('accessLogs')">
            <ScrollText :size="14" />
          </button>
          <label class="toggle scale-90 sm:scale-100">
            <input type="checkbox" :checked="svc.enabled" @change="toggleService(svc.id)" />
            <div class="toggle-track"></div>
            <div class="toggle-thumb"></div>
          </label>
          <!-- 编辑/删除：移动端始终显示 -->
          <button @click="openServiceModal(svc)" class="btn-ghost btn-sm p-1.5 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
            <Pencil :size="14" />
          </button>
          <button @click="delService(svc.id)" class="btn-ghost btn-sm p-1.5 text-red-400 hover:bg-red-50 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
            <Trash2 :size="14" />
          </button>
        </div>
      </div>

      <!-- 子规则区域 -->
      <div class="p-3 sm:p-4">
        <div class="flex items-center justify-between mb-3">
          <button @click="toggleCollapse(svc.id)"
                  class="flex items-center gap-1.5 text-xs font-bold text-slate-400 uppercase tracking-widest hover:text-slate-600 transition-colors select-none">
            <svg class="w-3.5 h-3.5 transition-transform duration-200 flex-shrink-0"
                 :class="collapsed[svc.id] ? '-rotate-90' : 'rotate-0'"
                 fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19 9l-7 7-7-7"/>
            </svg>
            {{ t('subRoutes') }}
            <span class="font-normal normal-case tracking-normal text-slate-300 ml-0.5">({{ (svc.routes||[]).length }})</span>
          </button>
          <button @click="openRouteModal(svc.id)" class="btn-ghost btn-sm text-purple-600 hover:bg-purple-50 text-xs">
            <Plus :size="12" /> {{ t('addSubRoute') }}
          </button>
        </div>

        <div v-show="!collapsed[svc.id]">
          <div v-if="!(svc.routes&&svc.routes.length)"
               class="text-center py-5 sm:py-6 text-slate-300 text-sm border border-dashed border-slate-200 rounded-xl">
            {{ t('noSubRoutes') }}
          </div>
        <div v-else class="space-y-2">
          <div v-for="route in svc.routes" :key="route.id"
               class="flex items-start sm:items-center gap-2 sm:gap-3 px-3 sm:px-4 py-2.5 sm:py-3 bg-slate-50 rounded-xl hover:bg-purple-50/50 transition-colors group/route">
            <span class="status-dot flex-shrink-0 mt-1 sm:mt-0" :class="route.enabled ? 'active' : 'inactive'"></span>

            <!-- 路由信息：移动端竖排 -->
            <div class="flex-1 flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2 min-w-0">
              <span v-if="route.name" class="text-xs font-medium text-slate-700 break-all">{{ route.name }}</span>
              <span class="font-mono text-xs sm:text-sm font-semibold text-purple-700 bg-purple-100 px-2 py-0.5 rounded-lg break-all cursor-pointer hover:bg-purple-200 transition-colors select-all"
                    :title="t('clickToCopy')"
                    @click="copyUrl(svc, route)">
                {{ svc.enable_https ? 'https' : 'http' }}://{{ route.domain }}{{ (svc.enable_https && svc.listen_port === 443) || (!svc.enable_https && svc.listen_port === 80) ? '' : ':'+svc.listen_port }}
              </span>
              <ArrowRight :size="12" class="text-slate-300 flex-shrink-0 hidden sm:block" />
              <span class="font-mono text-xs text-slate-600 bg-white border border-slate-100 px-2 py-0.5 rounded-lg break-all">
                {{ route.backend_url }}
              </span>
              <!-- 证书状态（仅 TLS 服务显示） -->
              <template v-if="svc.enable_https">
                <span v-if="route.cert_status === 'ok'"
                      class="inline-flex items-center gap-1 text-xs text-emerald-600 bg-emerald-50 border border-emerald-100 px-2 py-0.5 rounded-lg flex-shrink-0">
                  <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                  证书已匹配
                </span>
                <span v-else-if="route.cert_status === 'cert_inactive'"
                      class="inline-flex items-center gap-1 text-xs text-amber-600 bg-amber-50 border border-amber-100 px-2 py-0.5 rounded-lg flex-shrink-0">
                  <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                  证书未激活
                </span>
                <span v-else
                      class="inline-flex items-center gap-1 text-xs text-red-500 bg-red-50 border border-red-100 px-2 py-0.5 rounded-lg flex-shrink-0">
                  <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                  无匹配证书
                </span>
              </template>
              <!-- 访问验证角标 -->
              <span v-if="route.auth_enabled"
                    class="inline-flex items-center gap-1 text-xs text-slate-600 bg-slate-100 border border-slate-200 px-2 py-0.5 rounded-lg flex-shrink-0">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
                需验证
              </span>
            </div>

            <!-- 路由操作：移动端始终可见 -->
            <div class="flex items-center gap-1 flex-shrink-0 sm:opacity-0 sm:group-hover/route:opacity-100 transition-opacity">
              <label class="toggle scale-75">
                <input type="checkbox" :checked="route.enabled" @change="toggleRoute(svc.id, route.id)" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
              <button @click="openRouteModal(svc.id, route)" class="btn-ghost btn-sm p-1">
                <Pencil :size="12" />
              </button>
              <button @click="delRoute(svc.id, route.id)" class="btn-ghost btn-sm p-1 text-red-400 hover:bg-red-50">
                <Trash2 :size="12" />
              </button>
            </div>
          </div>
        </div>
        </div>
      </div>
    </div>

    <!-- ══ 服务弹窗 ════════════════════════════════════════════ -->
    <Teleport to="body">
      <div v-if="serviceModal" class="modal-overlay" @click.self="serviceModal=null">
        <div class="modal-box">

          <!-- 标题栏 -->
          <div class="flex-shrink-0">
            <div class="sm:hidden flex justify-center pt-3 pb-1">
              <div class="w-10 h-1 bg-slate-200 rounded-full"></div>
            </div>
            <div class="flex items-center justify-between px-5 sm:px-6 py-3 sm:py-4 border-b border-slate-100">
              <h3 class="font-semibold text-slate-900">{{ editingService ? t('editService') : t('addWebService') }}</h3>
              <button @click="serviceModal=null" class="btn-ghost btn-sm p-1.5"><X :size="16" /></button>
            </div>
          </div>

          <!-- 内容 -->
          <div class="flex-1 overflow-y-auto overscroll-contain px-5 sm:px-6 py-4 space-y-4">

            <div>
              <label class="input-label">{{ t('serviceName') }}</label>
              <input v-model="svcForm.name" class="input" placeholder="My Web App" />
            </div>

            <div>
              <label class="input-label">{{ t('listenPortLabel') }}</label>
              <input v-model.number="svcForm.listen_port" type="number" class="input" style="max-width:200px" placeholder="443" />
              <p class="text-xs text-slate-400 mt-1">{{ t('listenPortHint') }}</p>
            </div>

            <!-- TLS 开关：行内右对齐布局 -->
            <div class="flex items-center justify-between py-1">
              <div>
                <p class="text-sm font-medium text-slate-700">{{ t('enableTls') }}</p>
                <p class="text-xs text-slate-400 mt-0.5">{{ svcForm.enable_https ? t('httpsHint') : t('httpOnlyHint') }}</p>
              </div>
              <label class="toggle flex-shrink-0 ml-4">
                <input type="checkbox" v-model="svcForm.enable_https" />
                <div class="toggle-track"></div>
                <div class="toggle-thumb"></div>
              </label>
            </div>

            <!-- TLS 开启时：提示信息 -->
            <div v-if="svcForm.enable_https" class="p-3 bg-blue-50 rounded-xl border border-blue-100 flex items-start gap-2 text-xs text-blue-700">
              <svg class="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
              </svg>
              {{ t('httpsHint') }}证书将根据子规则域名自动匹配。
            </div>

            <!-- 错误提示已移至底部 -->

          </div>

          <!-- 底部操作栏 -->
          <div class="flex-shrink-0 border-t border-slate-100 px-5 sm:px-6 py-3 sm:py-4 space-y-3">
            <div v-if="svcError" class="flex items-center gap-2 text-red-600 bg-red-50 px-3 py-2.5 rounded-xl border border-red-100 text-xs">
              <AlertCircle :size="13" class="flex-shrink-0" /> {{ svcError }}
            </div>
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div class="flex items-center gap-2">
                <span class="text-sm text-slate-600">{{ t('enableService') }}</span>
                <label class="toggle">
                  <input type="checkbox" v-model="svcForm.enabled" />
                  <div class="toggle-track"></div>
                  <div class="toggle-thumb"></div>
                </label>
              </div>
              <div class="flex gap-2 sm:gap-3">
                <button class="btn-primary flex-1 sm:flex-none sm:min-w-[80px] justify-center" @click="saveService">{{ t('save') }}</button>
                <button class="btn-secondary flex-1 sm:flex-none sm:min-w-[80px] justify-center" @click="serviceModal=null">{{ t('cancel') }}</button>
              </div>
            </div>
          </div>

        </div>
      </div>
    </Teleport>

    <!-- ══ 子规则弹窗 ══════════════════════════════════════════ -->
    <Teleport to="body">
      <div v-if="routeModal" class="modal-overlay" @click.self="routeModal=null">
        <div class="modal-box">

          <!-- 标题栏 -->
          <div class="flex-shrink-0">
            <div class="sm:hidden flex justify-center pt-3 pb-1">
              <div class="w-10 h-1 bg-slate-200 rounded-full"></div>
            </div>
            <div class="flex items-center justify-between px-5 sm:px-6 py-3 sm:py-4 border-b border-slate-100">
              <div>
                <h3 class="font-semibold text-slate-900">{{ editingRoute ? t('editSubRoute') : t('addSubRouteTitle') }}</h3>
                <p class="text-xs text-slate-400 mt-0.5">{{ t('routeDesc') }}</p>
              </div>
              <button @click="routeModal=null" class="btn-ghost btn-sm p-1.5"><X :size="16" /></button>
            </div>
          </div>

          <!-- 内容 -->
          <div class="flex-1 overflow-y-auto overscroll-contain px-5 sm:px-6 py-4 space-y-4">

            <div class="p-3 bg-purple-50 rounded-xl border border-purple-100 text-xs text-purple-700 space-y-1">
              <p v-html="t('routeHelp1')"></p>
              <p v-html="t('routeHelp2')"></p>
            </div>

            <div>
              <label class="input-label">规则名称</label>
              <input v-model="routeForm.name" class="input" placeholder="可选，便于识别" />
            </div>

            <div>
              <label class="input-label">{{ t('frontDomain') }}</label>
              <div class="flex gap-0">
                <span class="inline-flex items-center px-3 bg-slate-100 border border-r-0 border-slate-200 rounded-l-xl text-sm font-mono text-slate-500 flex-shrink-0">
                  {{ currentSvc?.enable_https ? 'https://' : 'http://' }}
                </span>
                <input v-model="routeForm.domain" class="input rounded-l-none font-mono flex-1" placeholder="a.com" />
              </div>
              <p class="text-xs text-slate-400 mt-1 font-mono">
                {{ currentSvc?.enable_https ? 'https' : 'http' }}://{{ routeForm.domain || 'a.com' }}{{ currentSvc && currentSvc.listen_port !== 443 ? ':'+currentSvc.listen_port : '' }}
              </p>
            </div>

            <div>
              <label class="input-label">{{ t('backendAddr') }}</label>
              <div class="flex gap-0">
                <select v-model="routeScheme" class="select rounded-r-none border-r-0 w-28 flex-shrink-0 bg-slate-100 text-slate-700 font-mono text-sm">
                  <option value="http://">http://</option>
                  <option value="https://">https://</option>
                </select>
                <input v-model="routeHostPort"
                       class="input rounded-l-none font-mono text-sm flex-1"
                       placeholder="127.0.0.1:8080"
                       @blur="normalizeBackendUrl" />
              </div>
              <p class="text-xs text-slate-400 mt-1">{{ t('backendAddrHint') }}</p>
            </div>

            <!-- 访问验证 -->
            <div class="border border-slate-200 rounded-xl overflow-hidden">
              <!-- 开关行 -->
              <div class="flex items-center justify-between px-4 py-3 bg-slate-50">
                <div>
                  <p class="text-sm font-medium text-slate-700">访问验证</p>
                  <p class="text-xs text-slate-400 mt-0.5">开启后访问此域名需输入账号密码</p>
                </div>
                <label class="toggle flex-shrink-0 ml-4">
                  <input type="checkbox" v-model="routeForm.auth_enabled" />
                  <div class="toggle-track"></div>
                  <div class="toggle-thumb"></div>
                </label>
              </div>
              <!-- 账号密码字段 -->
              <div v-if="routeForm.auth_enabled" class="px-4 py-3 space-y-3 border-t border-slate-200">
                <div>
                  <label class="input-label">账号</label>
                  <input v-model="routeForm.auth_user" class="input font-mono" placeholder="admin" autocomplete="off" />
                </div>
                <div>
                  <label class="input-label">
                    密码
                    <span v-if="routeForm.auth_pass_hash === 'set'" class="text-xs font-normal text-emerald-500 ml-1 normal-case tracking-normal">已设置，留空保持不变</span>
                    <span v-else-if="routeForm.id" class="text-xs font-normal text-slate-400 ml-1 normal-case tracking-normal">留空则保持原密码不变</span>
                  </label>
                  <input v-model="routeAuthPass" type="password" class="input font-mono"
                         :placeholder="routeForm.auth_pass_hash === 'set' ? '不修改请留空' : '••••••••'"
                         autocomplete="new-password" />
                </div>
              </div>
            </div>

            <!-- 错误提示已移至底部 -->

          </div>

          <!-- 底部操作栏 -->
          <div class="flex-shrink-0 border-t border-slate-100 px-5 sm:px-6 py-3 sm:py-4 space-y-3">
            <div v-if="routeError" class="flex items-center gap-2 text-red-600 bg-red-50 px-3 py-2.5 rounded-xl border border-red-100 text-xs">
              <AlertCircle :size="13" class="flex-shrink-0" /> {{ routeError }}
            </div>
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div class="flex items-center gap-2">
                <span class="text-sm text-slate-600">{{ t('enableRouteLabel') }}</span>
                <label class="toggle">
                  <input type="checkbox" v-model="routeForm.enabled" />
                  <div class="toggle-track"></div>
                  <div class="toggle-thumb"></div>
                </label>
              </div>
              <div class="flex gap-2 sm:gap-3">
                <button class="btn-primary flex-1 sm:flex-none sm:min-w-[80px] justify-center" @click="saveRoute">{{ t('save') }}</button>
                <button class="btn-secondary flex-1 sm:flex-none sm:min-w-[80px] justify-center" @click="routeModal=null">{{ t('cancel') }}</button>
              </div>
            </div>
          </div>

        </div>
      </div>
    </Teleport>

    <!-- ══ 访问日志弹窗 ════════════════════════════════════════ -->
    <Teleport to="body">
      <div v-if="logsModal" class="modal-overlay" @click.self="logsModal=false; logsServiceID=''">
        <div class="modal-box sm:max-w-4xl">

          <!-- 标题栏 -->
          <div class="flex-shrink-0">
            <div class="sm:hidden flex justify-center pt-3 pb-1">
              <div class="w-10 h-1 bg-slate-200 rounded-full"></div>
            </div>
            <div class="flex items-center justify-between px-5 sm:px-6 py-3 sm:py-4 border-b border-slate-100">
              <div>
                <h3 class="font-semibold text-slate-900">{{ t('logsTitle') }}</h3>
                <p class="text-xs text-slate-400 mt-0.5">{{ t('logsCount', {n: logs.length}) }}</p>
              </div>
              <button @click="logsModal=false; logsServiceID=''" class="btn-ghost btn-sm p-1.5"><X :size="16" /></button>
            </div>
          </div>

          <!-- 搜索栏 -->
          <div class="flex-shrink-0 px-5 sm:px-6 py-3 border-b border-slate-50 flex items-center gap-2 sm:gap-3">
            <input v-model="logSearch" class="input flex-1 sm:max-w-xs text-xs py-1.5" :placeholder="t('logsSearch')" />
            <button @click="loadLogs" class="btn-secondary btn-sm flex-shrink-0">
              <RefreshCw :size="12" /> <span class="hidden sm:inline">{{ t('refresh') }}</span>
            </button>
            <span class="text-xs text-slate-400 ml-auto flex-shrink-0">{{ t('logsTotal', {n: filteredLogs.length}) }}</span>
          </div>

          <!-- 日志表：移动端横向滚动 -->
          <div class="flex-1 overflow-auto">
            <table class="w-full text-xs min-w-[400px]">
              <thead class="bg-slate-50 sticky top-0">
                <tr>
                  <th class="text-left px-3 sm:px-4 py-2.5 font-semibold text-slate-500">{{ t('logsTime') }}</th>
                  <th class="text-left px-3 sm:px-4 py-2.5 font-semibold text-slate-500">{{ t('logsRouteName') }}</th>
                  <th class="text-left px-3 sm:px-4 py-2.5 font-semibold text-slate-500">{{ t('logsDomain') }}</th>
                  <th class="text-left px-3 sm:px-4 py-2.5 font-semibold text-slate-500">{{ t('logsSrcIp') }}</th>
                  <th class="text-left px-3 sm:px-4 py-2.5 font-semibold text-slate-500 max-w-[140px]">UA</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="log in filteredLogs" :key="log.id"
                    class="border-t border-slate-50 hover:bg-slate-50 transition-colors">
                  <td class="px-3 sm:px-4 py-2 font-mono text-slate-400 whitespace-nowrap">{{ formatTime(log.time) }}</td>
                  <td class="px-3 sm:px-4 py-2 text-slate-600">{{ log.route_name || '—' }}</td>
                  <td class="px-3 sm:px-4 py-2 font-mono font-semibold text-slate-700">{{ log.domain }}</td>
                  <td class="px-3 sm:px-4 py-2 font-mono text-slate-600">{{ log.client_ip }}</td>
                  <td class="px-3 sm:px-4 py-2 text-slate-400 max-w-[140px] truncate" :title="log.user_agent">{{ parseUA(log.user_agent) }}</td>
                </tr>
                <tr v-if="filteredLogs.length === 0">
                  <td colspan="5" class="text-center py-10 text-slate-300">{{ t('noLogs') }}</td>
                </tr>
              </tbody>
            </table>
          </div>

        </div>
      </div>
    </Teleport>

    <!-- 复制成功提示 -->
    <Teleport to="body">
      <div v-if="copyToast"
           class="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 bg-slate-800 text-white text-sm px-4 py-2 rounded-xl shadow-lg transition-all">
        {{ t('copied') }}
      </div>
    </Teleport>
    <ConfirmModal v-model="showConfirm" :title="confirmTitle" :message="confirmMessage" @confirm="runConfirm" />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { Plus, Server, ArrowRight, Pencil, Trash2, X, ScrollText, RefreshCw, AlertCircle } from 'lucide-vue-next'
import { api } from '@/stores/auth'
import { useI18n } from '@/stores/i18n'
import ConfirmModal from '@/components/ConfirmModal.vue'

const { t } = useI18n()

const services = ref([])
const copyToast = ref(false)
let copyToastTimer = null
const certs = ref([])
// Confirm modal
const showConfirm = ref(false)
const confirmTitle = ref('')
const confirmMessage = ref('')
const confirmAction = ref(null)
async function runConfirm() { if (confirmAction.value) await confirmAction.value() }
// Collapse state per service id
const collapsed = ref({})
function toggleCollapse(id) { collapsed.value[id] = !collapsed.value[id] }
const logs = ref([])
const logSearch = ref('')
const logsModal = ref(false)
const logsServiceID = ref('')

// ── Service modal ──
const serviceModal = ref(false)
const editingService = ref(false)
const svcForm = ref({})
const svcError = ref('')

// ── Route modal ──
const routeModal = ref(false)
const editingRoute = ref(false)
const currentSvcID = ref('')
const routeForm = ref({})
const routeError = ref('')

// 后端地址拆分为 scheme + host:port
const routeScheme = ref('http://')
const routeHostPort = ref('')
const routeAuthPass = ref('')

// 同步 routeScheme + routeHostPort → routeForm.backend_url
watch([routeScheme, routeHostPort], () => {
  routeForm.value.backend_url = routeScheme.value + routeHostPort.value
})

function normalizeBackendUrl() {
  // 如果用户粘贴了完整 URL（含 scheme），自动拆分
  const val = routeHostPort.value
  if (val.startsWith('http://')) {
    routeScheme.value = 'http://'
    routeHostPort.value = val.slice(7)
  } else if (val.startsWith('https://')) {
    routeScheme.value = 'https://'
    routeHostPort.value = val.slice(8)
  }
}

function parseBackendUrl(url) {
  if (!url) return { scheme: 'http://', host: '' }
  if (url.startsWith('https://')) return { scheme: 'https://', host: url.slice(8) }
  if (url.startsWith('http://')) return { scheme: 'http://', host: url.slice(7) }
  return { scheme: 'http://', host: url }
}

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
  const res = await api.get('/webservice')
  services.value = res.data
  // 默认折叠所有子规则，已手动展开的保持不变
  res.data.forEach(svc => {
    if (collapsed.value[svc.id] === undefined) {
      collapsed.value[svc.id] = true
    }
  })
}

async function loadLogs() {
  const url = logsServiceID.value ? `/webservice/${logsServiceID.value}/logs` : '/webservice/logs'
  const { data } = await api.get(url)
  logs.value = data
}

watch(logsModal, v => {
  if (v) {
    loadLogs()
    // Schedule reload at next midnight to clear previous day's logs
    scheduleDailyLogRefresh()
  } else {
    clearDailyLogRefresh()
  }
})

let dailyRefreshTimer = null
function scheduleDailyLogRefresh() {
  clearDailyLogRefresh()
  const now = new Date()
  const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1)
  const msUntilMidnight = midnight - now
  dailyRefreshTimer = setTimeout(() => {
    if (logsModal.value) loadLogs()
    scheduleDailyLogRefresh()
  }, msUntilMidnight)
}
function clearDailyLogRefresh() {
  if (dailyRefreshTimer) { clearTimeout(dailyRefreshTimer); dailyRefreshTimer = null }
}

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
    : { name: '', listen_port: 443, enable_https: true, enabled: true }
  serviceModal.value = true
}

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

async function toggleService(id) {
  try {
    await api.post(`/webservice/${id}/toggle`)
    await load()
  } catch (e) {
    alert(e.response?.data?.error || e.message)
  }
}
async function delService(id) {
  confirmTitle.value = '删除 Web 服务'
  confirmMessage.value = '将同时删除该服务下的所有路由规则，此操作不可撤销。'
  confirmAction.value = async () => {
    await api.delete(`/webservice/${id}`)
    await load()
  }
  showConfirm.value = true
}

// ── Route CRUD ──
function openRouteModal(svcID, route = null) {
  currentSvcID.value = svcID
  editingRoute.value = !!route
  routeError.value = ''
  routeAuthPass.value = ''
  if (route) {
    routeForm.value = { ...route }
    const parsed = parseBackendUrl(route.backend_url)
    routeScheme.value = parsed.scheme
    routeHostPort.value = parsed.host
  } else {
    routeForm.value = { name: '', domain: '', backend_url: '', enabled: true, auth_enabled: false, auth_user: '' }
    routeScheme.value = 'http://'
    routeHostPort.value = ''
  }
  routeModal.value = true
}

async function saveRoute() {
  routeError.value = ''
  routeForm.value.backend_url = routeScheme.value + routeHostPort.value
  // Validate auth fields
  if (routeForm.value.auth_enabled) {
    if (!routeForm.value.auth_user) {
      routeError.value = '开启访问验证时，账号不能为空'
      return
    }
    // New route: password required; edit: only required if no existing hash
    const isNew = !editingRoute.value
    if (isNew && !routeAuthPass.value) {
      routeError.value = '开启访问验证时，密码不能为空'
      return
    }
  }
  const id = currentSvcID.value
  const payload = {
    ...routeForm.value,
    auth_pass_hash: undefined, // never send hash back to backend
    auth_pass: routeAuthPass.value || undefined,
  }
  try {
    if (editingRoute.value) {
      await api.put(`/webservice/${id}/routes/${routeForm.value.id}`, payload)
    } else {
      await api.post(`/webservice/${id}/routes`, payload)
    }
    routeModal.value = false
    await load()
  } catch (e) {
    routeError.value = e.response?.data?.error || e.message
  }
}

async function toggleRoute(svcID, rid) {
  await api.post(`/webservice/${svcID}/routes/${rid}/toggle`)
  await load()
}

async function delRoute(svcID, rid) {
  confirmTitle.value = '删除路由规则'
  confirmMessage.value = '确认删除此路由规则？此操作不可撤销。'
  confirmAction.value = async () => {
    await api.delete(`/webservice/${svcID}/routes/${rid}`)
    // Immediately remove from local state for instant UI feedback
    const svc = services.value.find(s => s.id === svcID)
    if (svc) svc.routes = (svc.routes || []).filter(r => r.id !== rid)
    await load()
  }
  showConfirm.value = true
}

// ── Helpers ──
function copyUrl(svc, route) {
  const isDefaultPort = (svc.enable_https && svc.listen_port === 443) || (!svc.enable_https && svc.listen_port === 80)
  const port = isDefaultPort ? '' : ':' + svc.listen_port
  const url = `${svc.enable_https ? 'https' : 'http'}://${route.domain}${port}`
  navigator.clipboard.writeText(url).then(() => {
    clearTimeout(copyToastTimer)
    copyToast.value = true
    copyToastTimer = setTimeout(() => { copyToast.value = false }, 2000)
  })
}

function formatTime(ts) {
  if (!ts) return ''
  return new Date(ts).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
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
